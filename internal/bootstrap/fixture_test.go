package bootstrap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"anchor/internal/predicate"
	"anchor/internal/rekorapi"
)

// This file turns the readable JSON scenarios in testdata into the Rekor
// entries Discover actually consumes: real X.509 certificates with the SAN
// and Fulcio issuer extension Anchor reads, real DSSE payloads, and bodies
// whose payloadHash matches, all assembled the way the public log returns
// them.
//
// The scenarios are JSON so a reviewer can read what each case *means*
// without decoding base64; the crypto scaffolding is generated here
// because committing it would make the fixtures unreadable and would not
// make them any more real — the signatures are never checked in these
// tests. Verification itself is stubbed, deliberately: the point of these
// tests is that Anchor's history reconstruction can be exercised without
// writing anything to the permanent public log.

// scenario mirrors a testdata/*.json file.
type scenario struct {
	Name              string       `json:"name"`
	Note              string       `json:"note"`
	ToolID            string       `json:"toolId"`
	BootstrapIdentity string       `json:"bootstrapIdentity"`
	MaxEntries        int          `json:"maxEntries"`
	Entries           []entrySpec  `json:"entries"`
	Want              wantScenario `json:"want"`
}

// entrySpec is one entry in the fake log.
type entrySpec struct {
	LogIndex int64  `json:"logIndex"`
	Signer   string `json:"signer"`
	// IndexedUnder overrides which identity Rekor's index returns this
	// entry for, so a test can present an entry that isn't signed by the
	// identity it was found under.
	IndexedUnder string `json:"indexedUnder,omitempty"`
	// Kind is "schema-manifest", "identity-rotation", or "other".
	Kind string `json:"kind"`
	// ToolID overrides the scenario's tool id inside the predicate.
	ToolID string `json:"toolId,omitempty"`

	SchemaHash         string  `json:"schemaHash,omitempty"`
	PreviousSchemaHash *string `json:"previousSchemaHash,omitempty"`
	SchemaVersion      string  `json:"schemaVersion,omitempty"`
	OldIdentity        string  `json:"oldIdentity,omitempty"`
	NewIdentity        string  `json:"newIdentity,omitempty"`
	Timestamp          string  `json:"timestamp,omitempty"`

	// PredicateType, for Kind "other": some unrelated attestation that
	// happens to be signed by the same identity.
	PredicateType string `json:"predicateType,omitempty"`

	// NoPayload drops the DSSE payload, the way the public Rekor instance
	// does for "dsse" entry kinds.
	NoPayload bool `json:"noPayload,omitempty"`
	// FailsVerification makes the stub verifier reject this entry.
	FailsVerification bool `json:"failsVerification,omitempty"`
	// NotKeyless replaces the certificate with a bare public key.
	NotKeyless bool `json:"notKeyless,omitempty"`
}

type wantScenario struct {
	// Error, if set, is a substring the returned error must contain.
	Error string `json:"error,omitempty"`
	// ErrorKind, if set, is "cap" or "no-payload".
	ErrorKind string `json:"errorKind,omitempty"`

	Manifests          int      `json:"manifests"`
	Rotations          int      `json:"rotations"`
	NotAnchor          int      `json:"notAnchor"`
	FailedVerification int      `json:"failedVerification"`
	NoPayload          int      `json:"noPayload"`
	Identities         []string `json:"identities"`

	// Problems and Chain are what history.Check must make of the
	// reconstructed history, rooted at the bootstrap identity.
	Problems []string `json:"problems"`
	Chain    []string `json:"chain"`
}

// testSigner issues the certificates the fake entries carry.
type testSigner struct {
	key *ecdsa.PrivateKey
}

func newTestSigner(t *testing.T) *testSigner {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &testSigner{key: key}
}

// fulcioIssuerOID is the extension Anchor reads the OIDC issuer out of.
var fulcioIssuerOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}

const testIssuer = "https://accounts.google.com"

// certPEM issues a leaf certificate binding email as a SAN and recording
// the OIDC issuer, which is all Anchor reads out of a Fulcio cert.
func (s *testSigner) certPEM(t *testing.T, email string) []byte {
	t.Helper()
	issuerExt, err := asn1.Marshal(testIssuer)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(time.Now().UnixNano()),
		Subject:        pkix.Name{CommonName: "anchor test"},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(time.Hour),
		EmailAddresses: []string{email},
		ExtraExtensions: []pkix.Extension{
			{Id: fulcioIssuerOID, Value: issuerExt},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &s.key.PublicKey, s.key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// statementFor builds the in-toto statement an entry carries.
func statementFor(t *testing.T, sc scenario, spec entrySpec) []byte {
	t.Helper()
	toolID := spec.ToolID
	if toolID == "" {
		toolID = sc.ToolID
	}
	ts := spec.Timestamp
	if ts == "" {
		ts = "2026-01-01T00:00:00Z"
	}

	switch spec.Kind {
	case "schema-manifest":
		stmt, err := predicate.BuildSchemaManifestStatement(toolID, spec.SchemaHash, predicate.SchemaManifest{
			ToolID:             toolID,
			PublisherIdentity:  spec.Signer,
			SchemaVersion:      spec.SchemaVersion,
			PreviousSchemaHash: spec.PreviousSchemaHash,
			Timestamp:          ts,
		})
		if err != nil {
			t.Fatal(err)
		}
		b, err := stmt.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return b

	case "identity-rotation":
		// The rotation document's own hash; nothing in history analysis
		// reads it, so any well-formed digest will do.
		sum := sha256.Sum256([]byte(fmt.Sprintf("rotation-%d", spec.LogIndex)))
		stmt, err := predicate.BuildIdentityRotationStatement(toolID, predicate.IdentityRotation{
			ToolID:      toolID,
			OldIdentity: spec.OldIdentity,
			NewIdentity: spec.NewIdentity,
			Timestamp:   ts,
		}, "sha256:"+hex.EncodeToString(sum[:]))
		if err != nil {
			t.Fatal(err)
		}
		b, err := stmt.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return b

	case "other":
		pt := spec.PredicateType
		if pt == "" {
			pt = "https://slsa.dev/provenance/v1"
		}
		sum := sha256.Sum256([]byte(fmt.Sprintf("other-%d", spec.LogIndex)))
		b, err := json.Marshal(map[string]any{
			"_type":         predicate.StatementType,
			"subject":       []map[string]any{{"name": toolID, "digest": map[string]string{"sha256": hex.EncodeToString(sum[:])}}},
			"predicateType": pt,
			"predicate":     map[string]any{"unrelated": true},
		})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	t.Fatalf("unknown entry kind %q", spec.Kind)
	return nil
}

// buildEntry assembles the Rekor entry the public log would return for a
// cosign-produced "dsse" entry.
func buildEntry(t *testing.T, s *testSigner, sc scenario, spec entrySpec) rekorapi.Entry {
	t.Helper()
	statement := statementFor(t, sc, spec)
	payloadB64 := base64.StdEncoding.EncodeToString(statement)
	sum := sha256.Sum256(statement)

	verifier := s.certPEM(t, spec.Signer)
	if spec.NotKeyless {
		pub, err := x509.MarshalPKIXPublicKey(&s.key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		verifier = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub})
	}

	body, err := json.Marshal(map[string]any{
		"kind":       "dsse",
		"apiVersion": "0.0.1",
		"spec": map[string]any{
			"payloadHash": map[string]string{"algorithm": "sha256", "value": hex.EncodeToString(sum[:])},
			"signatures": []map[string]string{{
				// Never checked here: the Verifier is stubbed, because
				// producing a genuinely Rekor-logged signature would mean
				// writing to the permanent public log.
				"signature": base64.StdEncoding.EncodeToString([]byte("test-signature")),
				"verifier":  base64.StdEncoding.EncodeToString(verifier),
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	e := rekorapi.Entry{
		UUID:           fmt.Sprintf("%064x", spec.LogIndex),
		Body:           base64.StdEncoding.EncodeToString(body),
		IntegratedTime: 1767225600 + spec.LogIndex,
		LogIndex:       spec.LogIndex,
		LogID:          strings.Repeat("ab", 32),
	}
	if !spec.NoPayload {
		e.Attestation = &rekorapi.Attestation{Data: payloadB64}
	}
	e.Verification = &rekorapi.Verification{
		SignedEntryTimestamp: base64.StdEncoding.EncodeToString([]byte("test-set")),
		InclusionProof: &rekorapi.InclusionProof{
			LogIndex:   spec.LogIndex,
			RootHash:   strings.Repeat("cd", 32),
			TreeSize:   spec.LogIndex + 1,
			Hashes:     []string{strings.Repeat("ef", 32)},
			Checkpoint: "test-checkpoint",
		},
	}
	return e
}

// stubVerifier accepts every bundle except the log indexes a scenario
// marked as failing. It recovers the log index from the bundle filename
// Discover writes.
type stubVerifier struct {
	reject map[int64]bool
	calls  int
}

func (v *stubVerifier) VerifyBundle(_ context.Context, bundlePath, _ string) error {
	v.calls++
	base := filepath.Base(bundlePath)
	base = strings.TrimSuffix(strings.TrimPrefix(base, "rekor-"), ".bundle.json")
	idx, err := strconv.ParseInt(base, 10, 64)
	if err != nil {
		return fmt.Errorf("stub verifier: unexpected bundle name %q", bundlePath)
	}
	if v.reject[idx] {
		return fmt.Errorf("stub verifier: rejecting entry %d", idx)
	}
	return nil
}

// buildFake wires a scenario's entries into a fake Rekor log.
func buildFake(t *testing.T, sc scenario) (*rekorapi.Fake, *stubVerifier) {
	t.Helper()
	s := newTestSigner(t)
	fake := rekorapi.NewFake()
	stub := &stubVerifier{reject: map[int64]bool{}}
	for _, spec := range sc.Entries {
		indexedUnder := spec.IndexedUnder
		if indexedUnder == "" {
			indexedUnder = spec.Signer
		}
		fake.Add(indexedUnder, buildEntry(t, s, sc, spec))
		if spec.FailsVerification {
			stub.reject[spec.LogIndex] = true
		}
	}
	return fake, stub
}
