package history

import "testing"

func sp(s string) *string { return &s }

func manifest(idx int64, hash string, prev *string) Attestation {
	return Attestation{Kind: schemaManifest, ToolID: "t", Signer: "pub@example.com",
		SchemaHash: hash, PreviousSchemaHash: prev, RekorLogIndex: idx}
}

func kinds(ps []Problem) []ProblemKind {
	var out []ProblemKind
	for _, p := range ps {
		out = append(out, p.Kind)
	}
	return out
}

func TestLinearChainIsClean(t *testing.T) {
	ps := CheckLinear([]Attestation{
		manifest(30, "C", sp("B")),
		manifest(10, "A", nil), // deliberately out of slice order: log index decides
		manifest(20, "B", sp("A")),
	})
	if len(ps) != 0 {
		t.Fatalf("expected clean history, got %v", ps)
	}
}

func TestEmptyAndRotationsOnly(t *testing.T) {
	if ps := CheckLinear(nil); len(ps) != 0 {
		t.Fatalf("empty history flagged: %v", ps)
	}
	rot := Attestation{Kind: "identity-rotation", RekorLogIndex: 5, OldIdentity: "a@x", NewIdentity: "b@x"}
	if ps := CheckLinear([]Attestation{rot}); len(ps) != 0 {
		t.Fatalf("rotation-only history flagged: %v", ps)
	}
}

// The tool-shadowing scenario: two validly signed revisions, same
// previousSchemaHash, different schemaHash.
func TestForkSamePreviousDifferentHash(t *testing.T) {
	ps := CheckLinear([]Attestation{
		manifest(10, "A", nil),
		manifest(20, "B", sp("A")),
		manifest(30, "B-evil", sp("A")),
	})
	if len(ps) != 1 || ps[0].Kind != ProblemFork {
		t.Fatalf("expected exactly one fork, got %v", kinds(ps))
	}
	if len(ps[0].Involved) != 2 {
		t.Fatalf("expected both forking revisions to be reported, got %d", len(ps[0].Involved))
	}
}

func TestForkTwoGenesisRevisions(t *testing.T) {
	ps := CheckLinear([]Attestation{manifest(10, "A", nil), manifest(20, "A2", nil)})
	if len(ps) != 1 || ps[0].Kind != ProblemFork {
		t.Fatalf("expected a fork between two first revisions, got %v", kinds(ps))
	}
}

func TestGapUnknownPrevious(t *testing.T) {
	ps := CheckLinear([]Attestation{manifest(10, "A", nil), manifest(20, "C", sp("B-never-seen"))})
	if len(ps) != 1 || ps[0].Kind != ProblemGap {
		t.Fatalf("expected a gap, got %v", kinds(ps))
	}
}

func TestGapFirstSeenRevisionHasPredecessor(t *testing.T) {
	// Partial history: we only retrieved B, which claims a predecessor.
	ps := CheckLinear([]Attestation{manifest(20, "B", sp("A"))})
	if len(ps) != 1 || ps[0].Kind != ProblemGap {
		t.Fatalf("expected a gap, got %v", kinds(ps))
	}
}

func TestOutOfOrderPredecessor(t *testing.T) {
	// B claims A as predecessor but was logged before A existed.
	ps := CheckLinear([]Attestation{manifest(10, "B", sp("A")), manifest(20, "A", nil)})
	if len(ps) != 1 || ps[0].Kind != ProblemOrder {
		t.Fatalf("expected an ordering problem, got %v", kinds(ps))
	}
}

func TestIdenticalResignIsNotAFork(t *testing.T) {
	ps := CheckLinear([]Attestation{
		manifest(10, "A", nil),
		manifest(20, "A", nil), // same content signed again from a fresh state dir
		manifest(30, "B", sp("A")),
	})
	if len(ps) != 0 {
		t.Fatalf("duplicate attestation of identical content flagged: %v", ps)
	}
}

func TestRollbackIsLinear(t *testing.T) {
	ps := CheckLinear([]Attestation{
		manifest(10, "A", nil),
		manifest(20, "B", sp("A")),
		manifest(30, "A", sp("B")), // deliberately reverting to the earlier content
	})
	if len(ps) != 0 {
		t.Fatalf("rollback through the chain flagged: %v", ps)
	}
}
