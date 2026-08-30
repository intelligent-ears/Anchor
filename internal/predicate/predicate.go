// Package predicate constructs the in-toto v1 Statements that Anchor signs.
//
// Anchor defines two predicate types:
//
//   - SchemaManifestType: attests "this exact canonicalized schema, for this
//     toolId, was published by this identity at this time." This is the
//     provenance record checked on every `anchor verify`.
//   - IdentityRotationType: attests "the identity that signs schema updates
//     for this toolId is changing from X to Y, and I (X) am authorizing it."
//     This is signed by the OLD identity, so a client can distinguish a
//     deliberate handoff from an attacker simply switching accounts.
//
// Both predicates are wrapped in a standard in-toto v1 Statement
// (https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
// before being handed to `cosign attest-blob --statement`.
package predicate

import (
	"encoding/json"
	"fmt"
	"strings"
)

// StatementType is the fixed in-toto v1 Statement "_type" value.
const StatementType = "https://in-toto.io/Statement/v1"

// Predicate type URIs. These are Anchor-specific; they are not registered
// with any central authority, which is normal for in-toto — a predicate
// type is just a URI both signer and verifier agree to interpret the same
// way.
const (
	SchemaManifestType   = "https://anchor.dev/schema-manifest/v1"
	IdentityRotationType = "https://anchor.dev/identity-rotation/v1"
)

// ResourceDescriptor is the in-toto v1 subject/material descriptor. Only the
// fields Anchor uses are modeled.
type ResourceDescriptor struct {
	Name   string            `json:"name,omitempty"`
	Digest map[string]string `json:"digest,omitempty"`
}

// Statement is the in-toto v1 Statement envelope. Predicate is left as
// json.RawMessage so callers can plug in either predicate type and the
// field survives round-tripping byte-for-byte.
type Statement struct {
	Type          string               `json:"_type"`
	Subject       []ResourceDescriptor `json:"subject"`
	PredicateType string               `json:"predicateType"`
	Predicate     json.RawMessage      `json:"predicate"`
}

// SchemaManifest is Anchor's predicate for a schema revision.
type SchemaManifest struct {
	ToolID             string  `json:"toolId"`
	PublisherIdentity  string  `json:"publisherIdentity"`
	SchemaVersion      string  `json:"schemaVersion"`
	PreviousSchemaHash *string `json:"previousSchemaHash"` // nullable: null for a tool's first published revision
	Timestamp          string  `json:"timestamp"`          // RFC 3339
}

// IdentityRotation is Anchor's predicate for an identity handoff. It is
// signed by OldIdentity to authorize NewIdentity as the tool's publisher
// going forward.
type IdentityRotation struct {
	ToolID      string `json:"toolId"`
	OldIdentity string `json:"oldIdentity"`
	NewIdentity string `json:"newIdentity"`
	Timestamp   string `json:"timestamp"` // RFC 3339
	Reason      string `json:"reason,omitempty"`
}

// hexDigest strips the "sha256:" prefix Anchor uses internally, since
// in-toto's digest set wants a bare hex string keyed by algorithm name.
func hexDigest(prefixed string) (string, error) {
	const prefix = "sha256:"
	if !strings.HasPrefix(prefixed, prefix) {
		return "", fmt.Errorf("expected a %q-prefixed digest, got %q", prefix, prefixed)
	}
	return strings.TrimPrefix(prefixed, prefix), nil
}

// BuildSchemaManifestStatement builds the Statement that gets signed by
// `anchor sign`. subjectName is the toolId (so the signed subject reads as
// "this toolId has digest X"), and schemaHash is the JCS-canonical
// sha256 hash of the schema (in "sha256:<hex>" form).
func BuildSchemaManifestStatement(toolID, schemaHash string, m SchemaManifest) (*Statement, error) {
	hex, err := hexDigest(schemaHash)
	if err != nil {
		return nil, err
	}
	predicateJSON, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal schema-manifest predicate: %w", err)
	}
	return &Statement{
		Type: StatementType,
		Subject: []ResourceDescriptor{
			{Name: toolID, Digest: map[string]string{"sha256": hex}},
		},
		PredicateType: SchemaManifestType,
		Predicate:     predicateJSON,
	}, nil
}

// BuildIdentityRotationStatement builds the Statement signed by
// `anchor rotate-identity`. There is no schema content to speak of here, so
// the subject digest is taken over the canonicalized predicate itself —
// the rotation record's own content is what's being attested to.
func BuildIdentityRotationStatement(toolID string, r IdentityRotation, rotationDocHash string) (*Statement, error) {
	hex, err := hexDigest(rotationDocHash)
	if err != nil {
		return nil, err
	}
	predicateJSON, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal identity-rotation predicate: %w", err)
	}
	return &Statement{
		Type: StatementType,
		Subject: []ResourceDescriptor{
			{Name: toolID, Digest: map[string]string{"sha256": hex}},
		},
		PredicateType: IdentityRotationType,
		Predicate:     predicateJSON,
	}, nil
}

// Marshal serializes the Statement to JSON bytes suitable for
// `cosign attest-blob --statement`.
func (s *Statement) Marshal() ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}
