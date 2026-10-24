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

// collectAttestations returns the verified view of every attestation
// Anchor has on file for toolID — schema revisions and identity rotations
// both, since the rotations are what tell the history checks which
// identities are one publisher.
//
// Each record's bundle is re-verified cryptographically, and every field
// the checks use (schemaHash, previousSchemaHash, signer) is read out of
// the verified, signed statement and certificate — not from the editable
// log-index.json, which is only ever a set of pointers.
func collectAttestations(ctx context.Context, st *state.Store, toolID string) ([]history.Attestation, error) {
	recs := append(st.SchemaManifests(toolID), st.Rotations(toolID)...)
	out := make([]history.Attestation, 0, len(recs))
	for _, rec := range recs {
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
		att, err := history.FromStatement(stmt, toolID, history.Source{
			RekorUUID:      rec.RekorUUID,
			RekorLogIndex:  info.LogIndex,
			SignerIdentity: info.SignerIdentity,
			OIDCIssuer:     info.OIDCIssuer,
		})
		if err != nil {
			return nil, fmt.Errorf("Rekor index %d: %w", rec.RekorLogIndex, err)
		}
		out = append(out, att)
	}
	return out, nil
}

// forkedReport renders the FORKED verdict. Its job is to name the exact
// log entries that disagree — a verdict a reader can't check against the
// public log themselves isn't worth much — and to be clear about what the
// finding does and does not mean.
func forkedReport(toolID string, rep history.Report, lineage history.Lineage) string {
	var b strings.Builder
	b.WriteString("FORKED: divergent schema history detected\n")
	fmt.Fprintf(&b, "  Tool:        %s\n", toolID)
	if lineage.Root() != "" {
		fmt.Fprintf(&b, "  Publisher:   %s\n", strings.Join(lineage.Identities(), ", "))
	}
	for _, p := range rep.Problems {
		fmt.Fprintf(&b, "  %-12s %s\n", problemLabel(p.Kind)+":", p.Message)
		for _, a := range p.Involved {
			prev := "none (claims to be the first revision)"
			if a.PreviousSchemaHash != nil {
				prev = *a.PreviousSchemaHash
			}
			version := a.SchemaVersion
			if version == "" {
				version = "(no version label)"
			}
			fmt.Fprintf(&b, "    - Rekor index %d, v%s, signed by %s\n", a.RekorLogIndex, version, a.Signer)
			fmt.Fprintf(&b, "        Rekor UUID:    %s\n", a.RekorUUID)
			fmt.Fprintf(&b, "        schema hash:   %s\n", a.SchemaHash)
			fmt.Fprintf(&b, "        previous hash: %s\n", prev)
		}
	}
	if hasKind(rep, history.ProblemFork) {
		b.WriteString("\n  What this means: the same signing identity published two mutually exclusive\n")
		b.WriteString("  lines of history for this tool — it told different clients different stories\n")
		b.WriteString("  about which revision follows which. That is equivocation, and it is visible\n")
		b.WriteString("  here only because the transparency log keeps both stories.\n")
		b.WriteString("\n  Provenance cannot tell you which line is the right one. Both branches are\n")
		b.WriteString("  genuinely signed by the publisher, so there is no signature to disbelieve.\n")
		b.WriteString("  Anchor's finding is only that the history is not linear; it makes no judgment\n")
		b.WriteString("  about whether either branch's content is safe. Do not approve either until the\n")
		b.WriteString("  publisher explains the divergence.\n")
	} else {
		b.WriteString("\n  What this means: this tool's revisions do not form a single chain. A revision\n")
		b.WriteString("  names a predecessor that is missing from the retrievable history, or was logged\n")
		b.WriteString("  before the revision it claims to follow. Either some revisions cannot be\n")
		b.WriteString("  retrieved, or ones that exist are being withheld.\n")
		b.WriteString("\n  Provenance cannot tell you which. What it can say is that the history on offer\n")
		b.WriteString("  is incomplete, so \"this is the latest revision\" is not something any of these\n")
		b.WriteString("  attestations establishes. Anchor makes no judgment about the content either way.\n")
	}
	if len(rep.OffLineage) > 0 {
		fmt.Fprintf(&b, "\n  (%d further attestation(s) for this tool were signed by identities outside this\n", len(rep.OffLineage))
		b.WriteString("  publisher's lineage. They are not part of the history above and are not what\n")
		b.WriteString("  makes it non-linear; an unrelated signer is a separate question.)\n")
	}
	return b.String()
}

func hasKind(rep history.Report, k history.ProblemKind) bool {
	for _, p := range rep.Problems {
		if p.Kind == k {
			return true
		}
	}
	return false
}

// problemLabel gives each problem kind a heading a reader can act on.
func problemLabel(k history.ProblemKind) string {
	switch k {
	case history.ProblemFork:
		return "Fork"
	case history.ProblemGap:
		return "Gap"
	case history.ProblemOrder:
		return "Order"
	}
	return "Problem"
}
