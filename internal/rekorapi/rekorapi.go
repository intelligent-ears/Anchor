// Package rekorapi does read-only lookups against the public Rekor REST
// API. It exists for one reason: Rekor's public search index supports
// lookup by artifact hash, by signer email, or by log index — but not by
// arbitrary custom attestation fields like Anchor's "toolId". So Anchor
// can't ask Rekor "give me the latest attestation for toolId X" directly.
//
// There are two ways Anchor works around that, and this package serves
// both:
//
//   - Anchor's local log-index (internal/state) remembers which log index
//     belongs to which toolId as it signs things. GetByLogIndex/GetByUUID
//     go back to the public log and fetch that entry live — proving it's
//     really there, not just trusting the local cache.
//   - With no local state at all, SearchByEmail asks the index for every
//     entry signed by a claimed publisher identity, and GetEntries fetches
//     them so the caller can filter for Anchor predicates itself
//     (internal/bootstrap).
//
// All of it is behind the Client interface, so history reconstruction can
// be unit-tested against fixture entries. That is deliberate: signing
// writes a permanent, public, undeletable record, so Anchor's own
// verification logic must never need new live Rekor entries to be tested.
package rekorapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// DefaultURL is the public Sigstore Rekor instance.
const DefaultURL = "https://rekor.sigstore.dev"

// Entry is the subset of a Rekor log entry Anchor cares about.
type Entry struct {
	UUID           string `json:"uuid,omitempty"` // set from the response's map key, or from a fixture
	Body           string `json:"body"`           // base64-encoded, algorithm-specific entry body (e.g. a "dsse" entry)
	IntegratedTime int64  `json:"integratedTime"`
	LogIndex       int64  `json:"logIndex"`
	LogID          string `json:"logID"`

	// Attestation carries the DSSE payload (base64) for entry kinds where
	// Rekor stores the attestation itself. Nil if absent — and absent is
	// the common case on the public instance for "dsse" entries, which
	// record only a payload hash. See internal/bootstrap.
	Attestation *Attestation `json:"attestation"`
	// Verification carries Rekor's own proof that the entry is in the log.
	Verification *Verification `json:"verification"`
}

// Attestation is the stored DSSE payload Rekor returns for entry kinds
// that keep one.
type Attestation struct {
	Data string `json:"data"` // base64-encoded in-toto Statement
}

// Verification is Rekor's evidence that an entry is in the log: the signed
// entry timestamp (its promise of inclusion) and the Merkle proof itself.
type Verification struct {
	SignedEntryTimestamp string          `json:"signedEntryTimestamp"`
	InclusionProof       *InclusionProof `json:"inclusionProof"`
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

// Client is the read-only slice of Rekor that Anchor depends on. Every
// method is a lookup; nothing here can write to the log.
type Client interface {
	// GetByLogIndex fetches the entry at a log index.
	GetByLogIndex(ctx context.Context, logIndex int64) (*Entry, error)
	// GetByUUID fetches the entry with a Rekor UUID.
	GetByUUID(ctx context.Context, uuid string) (*Entry, error)
	// SearchByEmail returns the UUIDs of every entry whose signing
	// certificate carries the given email identity.
	SearchByEmail(ctx context.Context, email string) ([]string, error)
	// GetEntries fetches full entries for the given UUIDs.
	GetEntries(ctx context.Context, uuids []string) ([]Entry, error)
}

// Doer is the HTTP surface HTTPClient needs, so tests can substitute a
// transport without a network.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// HTTPClient talks to a real Rekor REST endpoint.
type HTTPClient struct {
	BaseURL string
	HTTP    Doer

	// MaxAttempts bounds how many times one request is tried before giving
	// up. Rekor's public instance rate-limits, and a bootstrap scan of a
	// busy identity makes many requests in a row, so a 429 has to be waited
	// out rather than treated as a missing entry.
	MaxAttempts int
	// BaseBackoff is the first retry delay; it doubles each attempt, capped
	// at MaxBackoff. A Retry-After header, when Rekor sends one, wins.
	BaseBackoff time.Duration
	MaxBackoff  time.Duration

	// sleep is time.Sleep unless a test replaces it.
	sleep func(time.Duration)
}

var _ Client = (*HTTPClient)(nil)

// New returns a client for the public Rekor instance.
func New() *HTTPClient {
	return &HTTPClient{
		BaseURL:     DefaultURL,
		HTTP:        &http.Client{Timeout: 30 * time.Second},
		MaxAttempts: 5,
		BaseBackoff: 500 * time.Millisecond,
		MaxBackoff:  8 * time.Second,
	}
}

// defaultClient backs the package-level helpers, which exist so the common
// "look this one entry up on the real public log" call sites stay short.
var defaultClient = New()

// GetByLogIndex looks up a log index on the public Rekor instance.
func GetByLogIndex(ctx context.Context, logIndex int64) (*Entry, error) {
	return defaultClient.GetByLogIndex(ctx, logIndex)
}

// GetByUUID looks up a Rekor UUID on the public Rekor instance.
func GetByUUID(ctx context.Context, uuid string) (*Entry, error) {
	return defaultClient.GetByUUID(ctx, uuid)
}

// GetByLogIndex fetches the log entry at the given index, confirming it is
// genuinely present in the transparency log (not merely in Anchor's local
// cache).
func (c *HTTPClient) GetByLogIndex(ctx context.Context, logIndex int64) (*Entry, error) {
	url := fmt.Sprintf("%s/api/v1/log/entries?logIndex=%s", c.BaseURL, strconv.FormatInt(logIndex, 10))
	return c.getOne(ctx, url)
}

// GetByUUID fetches a log entry by its Rekor UUID.
func (c *HTTPClient) GetByUUID(ctx context.Context, uuid string) (*Entry, error) {
	url := fmt.Sprintf("%s/api/v1/log/entries/%s", c.BaseURL, uuid)
	return c.getOne(ctx, url)
}

// getOne handles both Rekor response shapes Anchor uses: a map of
// {uuid: entry} (the ?logIndex= query form) collapses to a single entry
// since a log index identifies exactly one entry.
func (c *HTTPClient) getOne(ctx context.Context, url string) (*Entry, error) {
	body, err := c.send(ctx, func() (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	})
	if err != nil {
		return nil, err
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
//
// The index endpoint is not paginated: it answers with the identity's
// complete UUID list in one response. Paging happens on the way back out,
// in GetEntries, which Rekor does cap per request. A caller that needs to
// bound total work has to bound it on the returned slice — see
// internal/bootstrap, which refuses rather than truncate.
func (c *HTTPClient) SearchByEmail(ctx context.Context, email string) ([]string, error) {
	reqBody, err := json.Marshal(map[string]string{"email": email})
	if err != nil {
		return nil, err
	}
	body, err := c.post(ctx, c.BaseURL+"/api/v1/index/retrieve", reqBody)
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
func (c *HTTPClient) GetEntries(ctx context.Context, uuids []string) ([]Entry, error) {
	var out []Entry
	for start := 0; start < len(uuids); start += maxRetrieveBatch {
		end := start + maxRetrieveBatch
		if end > len(uuids) {
			end = len(uuids)
		}
		reqBody, err := json.Marshal(map[string][]string{"entryUUIDs": uuids[start:end]})
		if err != nil {
			return nil, err
		}
		body, err := c.post(ctx, c.BaseURL+"/api/v1/log/entries/retrieve", reqBody)
		if err != nil {
			return nil, fmt.Errorf("fetching entries %d-%d of %d: %w", start, end, len(uuids), err)
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

func (c *HTTPClient) post(ctx context.Context, url string, body []byte) ([]byte, error) {
	return c.send(ctx, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		return req, nil
	})
}

// send issues a request, retrying the responses that mean "ask again
// later" (429, and the 5xx a load balancer returns when Rekor is briefly
// unavailable) rather than "this entry isn't there". newReq rebuilds the
// request each attempt, since a request body can only be read once.
func (c *HTTPClient) send(ctx context.Context, newReq func() (*http.Request, error)) ([]byte, error) {
	attempts := c.MaxAttempts
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		// delay is how long to wait before the next attempt, if there is
		// one. Rekor's own Retry-After wins over Anchor's guess.
		delay := c.backoff(attempt)

		req, err := newReq()
		if err != nil {
			return nil, err
		}
		resp, err := c.HTTP.Do(req)
		switch {
		case err != nil:
			lastErr = fmt.Errorf("contacting Rekor: %w", err)
		default:
			respBody, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr != nil {
				lastErr = fmt.Errorf("reading Rekor response: %w", readErr)
				break
			}
			if resp.StatusCode == http.StatusOK {
				return respBody, nil
			}
			lastErr = fmt.Errorf("Rekor returned %s: %s", resp.Status, truncate(string(respBody), 400))
			if !retryable(resp.StatusCode) {
				return nil, lastErr
			}
			if d, ok := retryAfter(resp.Header); ok {
				delay = c.cap(d)
			}
		}
		if attempt == attempts {
			break
		}
		if err := c.wait(ctx, delay); err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("gave up after %d attempt(s): %w", attempts, lastErr)
}

// backoff is the delay after a failed attempt: BaseBackoff, doubling,
// capped at MaxBackoff.
func (c *HTTPClient) backoff(attempt int) time.Duration {
	if c.BaseBackoff <= 0 {
		return 0
	}
	return c.cap(time.Duration(float64(c.BaseBackoff) * math.Pow(2, float64(attempt-1))))
}

func (c *HTTPClient) cap(d time.Duration) time.Duration {
	if c.MaxBackoff > 0 && d > c.MaxBackoff {
		return c.MaxBackoff
	}
	return d
}

func (c *HTTPClient) wait(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	if c.sleep != nil {
		c.sleep(d)
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

// retryable reports whether a status code means "try again", as opposed to
// a definitive answer about the entry.
func retryable(code int) bool {
	switch code {
	case http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	}
	return false
}

// retryAfter reads a Retry-After header in either of its two forms
// (delay-seconds, or an HTTP date).
func retryAfter(h http.Header) (time.Duration, bool) {
	v := strings.TrimSpace(h.Get("Retry-After"))
	if v == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			return 0, false
		}
		return time.Duration(secs) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d, true
		}
		return 0, true
	}
	return 0, false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
