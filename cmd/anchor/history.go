package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"anchor/internal/history"
	"anchor/internal/predicate"
	"anchor/internal/signer"
	"anchor/internal/state"
)

// verifyRecordCrypto cryptographically re-verifies a cached record's bundle
// (signature, Fulcio chain, Rekor inclusion proof). When the schema blob it
// was computed over is cached it also checks the blob matches the
// statement's subject; records discovered from Rekor have no such blob, and
// rely on the subject digest inside the (verified) statement instead.
func verifyRecordCrypto(ctx context.Context, rec state.LogRecord) error {
	predType := predicate.SchemaManifestType
	if rec.Kind == state.KindIdentityRotation {
		predType = predicate.IdentityRotationType
	}
	if rec.CanonicalPath != "" {
		if _, err := os.Stat(rec.CanonicalPath); err == nil {
			return signer.VerifyBundle(ctx, rec.BundlePath, rec.CanonicalPath, predType)
		}
	}
	return signer.VerifyBundleNoClaims(ctx, rec.BundlePath, predType)
}

// collectAttestations returns the verified view of every schema-manifest
// attestation Anchor has on file for toolID. Each record's bundle is
// re-verified cryptographically, and the fields used for history analysis
// (schemaHash, previousSchemaHash, signer) are read out of the verified,
// signed statement and certificate — not from the editable log-index.json.
func collectAttestations(ctx context.Context, st *state.Store, toolID string) ([]history.Attestation, error) {
	var out []history.Attestation
	for _, rec := range st.SchemaManifests(toolID) {
		if err := verifyRecordCrypto(ctx, rec); err != nil {
			return nil, fmt.Errorf("attestation at Rekor index %d failed re-verification: %w", rec.RekorLogIndex, err)
		}
		info, err := signer.ParseBundle(rec.BundlePath)
		if err != nil {
			return nil, fmt.Errorf("parsing bundle for Rekor index %d: %w", rec.RekorLogIndex, err)
		}
		stmt, err := predicate.ParseStatement(info.Statement)
		if err != nil {
			return nil, fmt.Errorf("Rekor index %d: %w", rec.RekorLogIndex, err)
		}
		hash, err := stmt.SubjectHash()
		if err != nil {
			return nil, fmt.Errorf("Rekor index %d: %w", rec.RekorLogIndex, err)
		}
		m, err := stmt.SchemaManifest()
		if err != nil {
			return nil, fmt.Errorf("Rekor index %d: %w", rec.RekorLogIndex, err)
		}
		if m.ToolID != toolID {
			return nil, fmt.Errorf("Rekor index %d is filed under tool %q locally but its signed statement says %q", rec.RekorLogIndex, toolID, m.ToolID)
		}
		out = append(out, history.Attestation{
			Kind:               history.KindSchemaManifest,
			ToolID:             m.ToolID,
			Signer:             info.SignerIdentity,
			Issuer:             info.OIDCIssuer,
			Timestamp:          m.Timestamp,
			RekorUUID:          rec.RekorUUID,
			RekorLogIndex:      info.LogIndex,
			SchemaHash:         hash,
			PreviousSchemaHash: m.PreviousSchemaHash,
			SchemaVersion:      m.SchemaVersion,
		})
	}
	return out, nil
}

// forkedReport renders the FORKED verdict for a set of history problems.
func forkedReport(toolID string, problems []history.Problem) string {
	var b strings.Builder
	b.WriteString("FORKED: divergent schema history detected\n")
	fmt.Fprintf(&b, "  Tool:        %s\n", toolID)
	for _, p := range problems {
		fmt.Fprintf(&b, "  Problem:     %s\n", p.Message)
		for _, a := range p.Involved {
			prev := "none (claims to be the first revision)"
			if a.PreviousSchemaHash != nil {
				prev = *a.PreviousSchemaHash
			}
			fmt.Fprintf(&b, "    - Rekor index %d, v%s, signed by %s\n        schema hash:   %s\n        previous hash: %s\n",
				a.RekorLogIndex, a.SchemaVersion, a.Signer, a.SchemaHash, prev)
		}
	}
	b.WriteString("  This tool's signed history is not a single linear chain: more than one line of\n")
	b.WriteString("  revisions exists on the public record, or a revision's claimed predecessor is\n")
	b.WriteString("  missing. A validly-signed second branch is how tool shadowing looks. This is a\n")
	b.WriteString("  provenance finding only — Anchor makes no judgment about which branch's content is\n")
	b.WriteString("  safe. Do not approve either until the publisher explains the divergence.\n")
	return b.String()
}
