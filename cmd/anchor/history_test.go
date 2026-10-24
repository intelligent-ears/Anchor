package main

import (
	"strings"
	"testing"

	"anchor/internal/history"
	"anchor/internal/state"
)

func manifest(idx int64, uuid, hash string, prev *string, signer string) history.Attestation {
	return history.Attestation{
		Kind: history.KindSchemaManifest, ToolID: "fresh_tool", Signer: signer,
		RekorLogIndex: idx, RekorUUID: uuid, SchemaHash: hash, PreviousSchemaHash: prev,
		SchemaVersion: "1.0.1",
	}
}

func TestForkedReportNamesBothEntries(t *testing.T) {
	prev := "sha256:aaa"
	atts := []history.Attestation{
		manifest(0, "uuid-aaa", "sha256:aaa", nil, "p@example.com"),
		manifest(1, "uuid-bbb", "sha256:bbb", &prev, "p@example.com"),
		manifest(2, "uuid-ccc", "sha256:ccc", &prev, "p@example.com"),
	}
	lineage := history.NewLineage("p@example.com", atts)
	rep := history.Check(atts, lineage)
	if !hasKind(rep, history.ProblemFork) {
		t.Fatalf("expected a fork, got %+v", rep.Problems)
	}
	out := forkedReport("fresh_tool", rep, lineage)

	// A reader has to be able to go and look both entries up themselves.
	for _, want := range []string{
		"FORKED: divergent schema history detected",
		"fresh_tool",
		"p@example.com",
		"uuid-bbb", "uuid-ccc",
		"sha256:bbb", "sha256:ccc",
		"sha256:aaa", // the disputed predecessor
		"Rekor index 1", "Rekor index 2",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q:\n%s", want, out)
		}
	}
	// And has to be told what a fork does and does not prove.
	for _, want := range []string{"equivocation", "Provenance cannot tell you which line is the right one", "no judgment"} {
		if !strings.Contains(out, want) {
			t.Errorf("report does not explain %q:\n%s", want, out)
		}
	}
}

func TestForkedReportForAGapDoesNotClaimEquivocation(t *testing.T) {
	// A gap is not evidence that the publisher told two stories; it is
	// evidence that the history on offer is incomplete. Saying otherwise
	// would overstate what provenance found.
	prev := "sha256:missing"
	atts := []history.Attestation{manifest(7, "uuid-bbb", "sha256:bbb", &prev, "p@example.com")}
	lineage := history.NewLineage("p@example.com", atts)
	rep := history.Check(atts, lineage)
	if !hasKind(rep, history.ProblemGap) {
		t.Fatalf("expected a gap, got %+v", rep.Problems)
	}
	out := forkedReport("fresh_tool", rep, lineage)
	if strings.Contains(out, "equivocation") {
		t.Errorf("gap report claims equivocation:\n%s", out)
	}
	for _, want := range []string{"Gap:", "sha256:missing", "incomplete"} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q:\n%s", want, out)
		}
	}
}

func TestForkedReportMentionsOffLineageAttestations(t *testing.T) {
	prev := "sha256:aaa"
	atts := []history.Attestation{
		manifest(0, "uuid-aaa", "sha256:aaa", nil, "p@example.com"),
		manifest(1, "uuid-bbb", "sha256:bbb", &prev, "p@example.com"),
		manifest(2, "uuid-ccc", "sha256:ccc", &prev, "p@example.com"),
		manifest(3, "uuid-ddd", "sha256:ddd", &prev, "attacker@evil.example"),
	}
	lineage := history.NewLineage("p@example.com", atts)
	rep := history.Check(atts, lineage)
	out := forkedReport("fresh_tool", rep, lineage)
	if strings.Contains(out, "uuid-ddd") {
		t.Errorf("off-lineage entry presented as part of the fork:\n%s", out)
	}
	if !strings.Contains(out, "outside this") {
		t.Errorf("report does not mention the off-lineage attestation:\n%s", out)
	}
}

func TestPublisherLineagePrefersTheUserSuppliedIdentity(t *testing.T) {
	// A bootstrap identity came from the user; a known-good came from this
	// client's own earlier decision. Either is a valid root, but the
	// explicit one the user just typed wins.
	atts := []history.Attestation{
		{Kind: history.KindIdentityRotation, Signer: "old@example.com", OldIdentity: "old@example.com", NewIdentity: "new@example.com"},
	}
	kg := state.LastKnownGood{PublisherIdentity: "old@example.com"}

	if got := publisherLineage("someone@example.com", kg, true, atts).Root(); got != "someone@example.com" {
		t.Errorf("root = %q, want the --bootstrap-from-identity value", got)
	}
	if got := publisherLineage("", kg, true, atts).Root(); got != "old@example.com" {
		t.Errorf("root = %q, want the known-good identity", got)
	}

	// No root at all: every signer in this client's own index counts.
	any := publisherLineage("", state.LastKnownGood{}, false, atts)
	if any.Root() != "" {
		t.Errorf("expected AnySigner, got root %q", any.Root())
	}
	if !any.Has("whoever@example.com") {
		t.Error("AnySigner rejected a signer")
	}
}

func TestPublisherLineageSpansAnAttestedRotation(t *testing.T) {
	// The live rotation case: the client's known-good is the identity that
	// signed most recently, while the first revision was signed by the one
	// it rotated away from. Both have to be in the lineage, or that first
	// revision would read as a gap.
	atts := []history.Attestation{
		manifest(10, "u10", "sha256:aaa", nil, "old@example.com"),
		{Kind: history.KindIdentityRotation, RekorLogIndex: 20, Signer: "old@example.com",
			OldIdentity: "old@example.com", NewIdentity: "new@example.com"},
		manifest(30, "u30", "sha256:bbb", sptr("sha256:aaa"), "new@example.com"),
	}
	lineage := publisherLineage("", state.LastKnownGood{PublisherIdentity: "new@example.com"}, true, atts)
	rep := history.Check(atts, lineage)
	if !rep.OK() {
		t.Fatalf("rotation across the chain reported as a problem: %+v", rep.Problems)
	}
	if len(rep.Chain) != 2 {
		t.Errorf("chain has %d revision(s), want 2", len(rep.Chain))
	}
	if len(rep.OffLineage) != 0 {
		t.Errorf("%d revision(s) wrongly excluded from the publisher's history", len(rep.OffLineage))
	}
}

func sptr(s string) *string { return &s }
