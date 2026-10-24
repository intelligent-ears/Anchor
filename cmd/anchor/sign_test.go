package main

import (
	"path/filepath"
	"testing"

	"anchor/internal/history"
	"anchor/internal/state"
)

func openStore(t *testing.T) *state.Store {
	t.Helper()
	st, err := state.Open(filepath.Join(t.TempDir(), ".anchor"))
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func logManifest(st *state.Store, logIndex int64, timestamp, hash string) {
	st.AppendLog(state.LogRecord{
		Kind: state.KindSchemaManifest, ToolID: "send_email",
		RekorLogIndex: logIndex, Timestamp: timestamp, SchemaHash: hash,
	})
}

func TestPreviousSchemaHashIsNilForAFirstRevision(t *testing.T) {
	st := openStore(t)
	if got := previousSchemaHashFor(st, "send_email"); got != nil {
		t.Errorf("previousSchemaHash = %q for a tool with no history, want nil", *got)
	}
}

func TestPreviousSchemaHashNamesTheLastLoggedRevision(t *testing.T) {
	st := openStore(t)
	// Timestamps deliberately disagree with log order: the publisher's own
	// clock is not what decides the chain.
	logManifest(st, 100, "2030-01-01T00:00:00Z", "sha256:aaa")
	logManifest(st, 200, "2020-01-01T00:00:00Z", "sha256:bbb")

	got := previousSchemaHashFor(st, "send_email")
	if got == nil {
		t.Fatal("previousSchemaHash = nil, want the last logged revision")
	}
	if *got != "sha256:bbb" {
		t.Errorf("previousSchemaHash = %q, want sha256:bbb (Rekor index 200)", *got)
	}
}

func TestPreviousSchemaHashIsPerTool(t *testing.T) {
	st := openStore(t)
	logManifest(st, 100, "2026-01-01T00:00:00Z", "sha256:aaa")
	if got := previousSchemaHashFor(st, "some_other_tool"); got != nil {
		t.Errorf("previousSchemaHash = %q, want nil — another tool's history is not this tool's parent", *got)
	}
}

// What sign writes must be what verify accepts: chaining each revision
// onto previousSchemaHashFor's answer has to produce a history that passes
// the linearity check.
func TestSignedChainPassesTheLinearityCheck(t *testing.T) {
	st := openStore(t)
	hashes := []string{"sha256:aaa", "sha256:bbb", "sha256:ccc"}
	var atts []history.Attestation
	for i, h := range hashes {
		prev := previousSchemaHashFor(st, "send_email")
		idx := int64(100 * (i + 1))
		atts = append(atts, history.Attestation{
			Kind: history.KindSchemaManifest, ToolID: "send_email", Signer: "p@example.com",
			RekorLogIndex: idx, RekorUUID: h, SchemaHash: h, PreviousSchemaHash: prev,
		})
		logManifest(st, idx, "2026-01-01T00:00:00Z", h)
	}

	rep := history.Check(atts, history.NewLineage("p@example.com", atts))
	if !rep.OK() {
		t.Fatalf("a chain built the way sign builds it failed the check: %+v", rep.Problems)
	}
	if len(rep.Chain) != len(hashes) {
		t.Errorf("chain has %d revisions, want %d", len(rep.Chain), len(hashes))
	}
}

// The gotcha the README documents: signing a tool's second revision from a
// state dir that has not seen the first produces a second claim to be the
// start of history, which a verifier holding both reads as a fork. This
// test pins that behaviour so the failure is a known one rather than a
// surprise.
func TestSigningFromAnEmptyStateDirForksAnExistingHistory(t *testing.T) {
	first := history.Attestation{
		Kind: history.KindSchemaManifest, ToolID: "send_email", Signer: "p@example.com",
		RekorLogIndex: 100, RekorUUID: "u100", SchemaHash: "sha256:aaa",
	}

	fresh := openStore(t) // a second machine, with no record of the first revision
	second := history.Attestation{
		Kind: history.KindSchemaManifest, ToolID: "send_email", Signer: "p@example.com",
		RekorLogIndex: 200, RekorUUID: "u200", SchemaHash: "sha256:bbb",
		PreviousSchemaHash: previousSchemaHashFor(fresh, "send_email"),
	}
	if second.PreviousSchemaHash != nil {
		t.Fatalf("expected a nil parent from an empty state dir, got %q", *second.PreviousSchemaHash)
	}

	atts := []history.Attestation{first, second}
	rep := history.Check(atts, history.NewLineage("p@example.com", atts))
	if !hasKind(rep, history.ProblemFork) {
		t.Errorf("expected a fork, got %+v", rep.Problems)
	}
}
