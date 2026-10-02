package signer

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"anchor/internal/rekorapi"
)

// realBundle is a bundle from this project's own live Rekor entries (kept
// in the untracked local .anchor/ cache). The test inverts it into the
// shape Rekor's REST API returns and checks BundleFromRekorEntry rebuilds
// something cosign accepts. Skipped when no such bundle is available.
func realBundle(t *testing.T) string {
	t.Helper()
	matches, _ := filepath.Glob("../../.anchor/bundles/*/*.bundle.json")
	if len(matches) == 0 {
		t.Skip("no local live bundle available")
	}
	return matches[0]
}

func entryFromBundle(t *testing.T, path string) rekorapi.Entry {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var b struct {
		VerificationMaterial struct {
			TlogEntries []struct {
				LogIndex          string                 `json:"logIndex"`
				LogID             struct{ KeyID string } `json:"logId"`
				IntegratedTime    string                 `json:"integratedTime"`
				CanonicalizedBody string                 `json:"canonicalizedBody"`
				InclusionPromise  struct {
					SignedEntryTimestamp string `json:"signedEntryTimestamp"`
				} `json:"inclusionPromise"`
				InclusionProof struct {
					LogIndex   string
					RootHash   string
					TreeSize   string
					Hashes     []string
					Checkpoint struct{ Envelope string }
				} `json:"inclusionProof"`
			} `json:"tlogEntries"`
		} `json:"verificationMaterial"`
		DsseEnvelope struct{ Payload string } `json:"dsseEnvelope"`
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	tl := b.VerificationMaterial.TlogEntries[0]
	toHex := func(s string) string {
		r, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(r)
	}
	var e rekorapi.Entry
	e.Body = tl.CanonicalizedBody
	e.LogID = toHex(tl.LogID.KeyID)
	e.Attestation = &struct {
		Data string `json:"data"`
	}{Data: b.DsseEnvelope.Payload}
	ip := &rekorapi.InclusionProof{RootHash: toHex(tl.InclusionProof.RootHash), Checkpoint: tl.InclusionProof.Checkpoint.Envelope}
	for _, h := range tl.InclusionProof.Hashes {
		ip.Hashes = append(ip.Hashes, toHex(h))
	}
	json.Unmarshal([]byte(tl.LogIndex), &e.LogIndex)
	json.Unmarshal([]byte(tl.IntegratedTime), &e.IntegratedTime)
	json.Unmarshal([]byte(tl.InclusionProof.LogIndex), &ip.LogIndex)
	json.Unmarshal([]byte(tl.InclusionProof.TreeSize), &ip.TreeSize)
	e.Verification = &struct {
		SignedEntryTimestamp string                   `json:"signedEntryTimestamp"`
		InclusionProof       *rekorapi.InclusionProof `json:"inclusionProof"`
	}{SignedEntryTimestamp: tl.InclusionPromise.SignedEntryTimestamp, InclusionProof: ip}
	return e
}

func TestBundleFromRekorEntryParses(t *testing.T) {
	path := realBundle(t)
	orig, err := ParseBundle(path)
	if err != nil {
		t.Fatal(err)
	}
	bundleJSON, statement, err := BundleFromRekorEntry(entryFromBundle(t, path))
	if err != nil {
		t.Fatal(err)
	}
	rebuilt, err := ParseBundleBytes(bundleJSON)
	if err != nil {
		t.Fatal(err)
	}
	if rebuilt.LogIndex != orig.LogIndex || rebuilt.SignerIdentity != orig.SignerIdentity || rebuilt.OIDCIssuer != orig.OIDCIssuer {
		t.Fatalf("rebuilt bundle disagrees with original: %+v vs %+v", rebuilt, orig)
	}
	if string(statement) != string(orig.Statement) {
		t.Fatal("statement differs")
	}
}

func TestBundleFromRekorEntryRejectsTamperedPayload(t *testing.T) {
	path := realBundle(t)
	e := entryFromBundle(t, path)
	e.Attestation.Data = base64.StdEncoding.EncodeToString([]byte(`{"_type":"x"}`))
	if _, _, err := BundleFromRekorEntry(e); err == nil {
		t.Fatal("expected payloadHash mismatch error")
	}
}

// Needs cosign on PATH and reaches Sigstore's public TUF root (the same
// thing every `anchor verify` already does); does not touch Rekor.
func TestBundleFromRekorEntryVerifiesWithCosign(t *testing.T) {
	if _, err := exec.LookPath("cosign"); err != nil {
		t.Skip("cosign not installed")
	}
	path := realBundle(t)
	bundleJSON, _, err := BundleFromRekorEntry(entryFromBundle(t, path))
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "rebuilt.bundle.json")
	if err := os.WriteFile(out, bundleJSON, 0o644); err != nil {
		t.Fatal(err)
	}
	pt := "https://anchor.dev/schema-manifest/v1"
	if filepath.Base(path)[:9] == "rotation-" {
		pt = "https://anchor.dev/identity-rotation/v1"
	}
	if err := VerifyBundleNoClaims(context.Background(), out, pt); err != nil {
		t.Fatalf("cosign rejected the rebuilt bundle: %v", err)
	}
}
