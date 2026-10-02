// Package rekorapi does read-only lookups against the public Rekor REST
// API. It exists for one reason: Rekor's public search index supports
// lookup by artifact hash, by signer email, or by log index — but not by
// arbitrary custom attestation fields like Anchor's "toolId". So Anchor
// can't ask Rekor "give me the latest attestation for toolId X" directly.
//
// Instead, Anchor's local log-index (internal/state) remembers which log
// index belongs to which toolId as it signs things. This package is used
// to go back to the public log and fetch that entry live — proving it's
// really there, not just trusting the local cache — by the one key Rekor
// does support looking up by: log index.
package rekorapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
)

// DefaultURL is the public Sigstore Rekor instance.
const DefaultURL = "https://rekor.sigstore.dev"

// Entry is the subset of a Rekor log entry Anchor cares about.
type Entry struct {
	UUID           string
	Body           string `json:"body"` // base64-encoded, algorithm-specific entry body (e.g. an "intoto" entry)
	IntegratedTime int64  `json:"integratedTime"`
	LogIndex       int64  `json:"logIndex"`
	LogID          string `json:"logID"`

	// Attestation carries the DSSE payload (base64) when the Rekor instance
	// stores attestations, as the public one does for in-toto entries.
	// Nil if absent.
	Attestation *struct {
		Data string `json:"data"`
	} `json:"attestation"`
	Verification *struct {
		SignedEntryTimestamp string          `json:"signedEntryTimestamp"`
		InclusionProof       *InclusionProof `json:"inclusionProof"`
	} `json:"verification"`
}

// InclusionProof is the Merkle inclusion proof Rekor returns with an entry.
// Hashes are hex-encoded here, as in Rekor's REST API.
type InclusionProof struct {
	LogIndex   int64    `json:"logIndex"`
	RootHash   string   `json:"rootHash"`
	TreeSize   int64    `json:"treeSize"`
	Hashes     []string `json:"hashes"`
	Checkpoint string   `json:"checkpoint"`
}

// GetByLogIndex fetches the log entry at the given index from the public
// Rekor instance, confirming it is genuinely present in the transparency
// log (not merely in Anchor's local cache).
func GetByLogIndex(ctx context.Context, logIndex int64) (*Entry, error) {
	url := fmt.Sprintf("%s/api/v1/log/entries?logIndex=%s", DefaultURL, strconv.FormatInt(logIndex, 10))
	return getOne(ctx, url)
}

// GetByUUID fetches a log entry by its Rekor UUID.
func GetByUUID(ctx context.Context, uuid string) (*Entry, error) {
	url := fmt.Sprintf("%s/api/v1/log/entries/%s", DefaultURL, uuid)
	return getOne(ctx, url)
}

// getOne handles both Rekor response shapes Anchor uses: a map of
// {uuid: entry} (the ?logIndex= query form) collapses to a single entry
// since a log index identifies exactly one entry.
func getOne(ctx context.Context, url string) (*Entry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("contacting Rekor: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Rekor returned %s: %s", resp.Status, string(body))
	}

	var byUUID map[string]Entry
	if err := json.Unmarshal(body, &byUUID); err != nil {
		return nil, fmt.Errorf("parse Rekor response: %w", err)
	}
	for uuid, entry := range byUUID {
		entry.UUID = uuid
		return &entry, nil
	}
	return nil, fmt.Errorf("Rekor returned no entries")
}

// SearchByEmail asks Rekor's public search index for every entry whose
// signing certificate (or key) carries the given email identity, returning
// entry UUIDs. This is one of the few lookups the index supports (see the
// package comment) — it cannot filter by anything inside an attestation, so
// callers must fetch and filter the results themselves.
func SearchByEmail(ctx context.Context, email string) ([]string, error) {
	reqBody, _ := json.Marshal(map[string]string{"email": email})
	body, err := post(ctx, DefaultURL+"/api/v1/index/retrieve", reqBody)
	if err != nil {
		return nil, err
	}
	var uuids []string
	if err := json.Unmarshal(body, &uuids); err != nil {
		return nil, fmt.Errorf("parse Rekor index response: %w", err)
	}
	return uuids, nil
}

// maxRetrieveBatch is Rekor's cap on entryUUIDs per retrieve request.
const maxRetrieveBatch = 10

// GetEntries fetches full log entries for the given UUIDs, batching to
// stay within Rekor's per-request limit.
func GetEntries(ctx context.Context, uuids []string) ([]Entry, error) {
	var out []Entry
	for start := 0; start < len(uuids); start += maxRetrieveBatch {
		end := start + maxRetrieveBatch
		if end > len(uuids) {
			end = len(uuids)
		}
		reqBody, _ := json.Marshal(map[string][]string{"entryUUIDs": uuids[start:end]})
		body, err := post(ctx, DefaultURL+"/api/v1/log/entries/retrieve", reqBody)
		if err != nil {
			return nil, err
		}
		var batch []map[string]Entry
		if err := json.Unmarshal(body, &batch); err != nil {
			return nil, fmt.Errorf("parse Rekor entries response: %w", err)
		}
		for _, m := range batch {
			for uuid, e := range m {
				e.UUID = uuid
				out = append(out, e)
			}
		}
	}
	return out, nil
}

func post(ctx context.Context, url string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("contacting Rekor: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Rekor returned %s: %s", resp.Status, string(respBody))
	}
	return respBody, nil
}
