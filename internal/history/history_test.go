package history

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// scenario is the shape of the JSON fixtures in testdata. Each one
// describes a history in the same vocabulary the checks use, plus what
// Check is expected to make of it, so a new case is a new file rather than
// new code.
type scenario struct {
	Name         string        `json:"name"`
	Note         string        `json:"note"`
	ToolID       string        `json:"toolId"`
	Root         string        `json:"root"`
	Attestations []Attestation `json:"attestations"`
	Want         struct {
		// Problems is the ProblemKinds expected, in order.
		Problems []ProblemKind `json:"problems"`
		// Chain and OffLineage are schema hashes, in the order Check
		// should put them in.
		Chain      []string `json:"chain"`
		OffLineage []string `json:"offLineage"`
		// Lineage is every identity expected in the lineage, root first.
		Lineage []string `json:"lineage"`
		// ForkInvolved, when set, is the schema hashes the fork problem
		// must name — the entries that disagree.
		ForkInvolved []string `json:"forkInvolved"`
	} `json:"want"`
}

func loadScenarios(t *testing.T) []scenario {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("testdata", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no fixtures found in testdata")
	}
	out := make([]scenario, 0, len(paths))
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var s scenario
		if err := json.Unmarshal(b, &s); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if s.Name == "" {
			s.Name = filepath.Base(p)
		}
		for i := range s.Attestations {
			if s.Attestations[i].ToolID == "" {
				s.Attestations[i].ToolID = s.ToolID
			}
		}
		out = append(out, s)
	}
	return out
}

func TestCheckFixtures(t *testing.T) {
	for _, sc := range loadScenarios(t) {
		t.Run(sc.Name, func(t *testing.T) {
			lineage := NewLineage(sc.Root, sc.Attestations)
			assertIdentities(t, "lineage", lineage.Identities(), sc.Want.Lineage)

			rep := Check(sc.Attestations, lineage)

			if got := kinds(rep.Problems); !equalKinds(got, sc.Want.Problems) {
				t.Errorf("problems = %v, want %v\n%s", got, sc.Want.Problems, render(rep))
			}
			assertHashes(t, "chain", rep.Chain, sc.Want.Chain)
			assertHashes(t, "offLineage", rep.OffLineage, sc.Want.OffLineage)
			if rep.OK() != (len(sc.Want.Problems) == 0) {
				t.Errorf("OK() = %v with problems %v", rep.OK(), kinds(rep.Problems))
			}

			if len(sc.Want.ForkInvolved) > 0 {
				var fork *Problem
				for i := range rep.Problems {
					if rep.Problems[i].Kind == ProblemFork {
						fork = &rep.Problems[i]
						break
					}
				}
				if fork == nil {
					t.Fatalf("expected a fork problem, got %v", kinds(rep.Problems))
				}
				assertHashes(t, "fork.Involved", fork.Involved, sc.Want.ForkInvolved)
				// A fork report is only actionable if it says which log
				// entries disagree, so every involved entry needs its
				// Rekor coordinates.
				for _, a := range fork.Involved {
					if a.RekorUUID == "" || a.RekorLogIndex == 0 {
						t.Errorf("fork involves an entry with no Rekor coordinates: %+v", a)
					}
				}
			}
		})
	}
}

// TestFixturesCoverTheDocumentedCases guards against a fixture being
// deleted or renamed out of the set the design relies on.
func TestFixturesCoverTheDocumentedCases(t *testing.T) {
	seen := map[ProblemKind]bool{}
	var linear, dupes, rotations int
	for _, sc := range loadScenarios(t) {
		for _, k := range sc.Want.Problems {
			seen[k] = true
		}
		if len(sc.Want.Problems) == 0 && len(sc.Attestations) > 0 {
			linear++
		}
		if len(sc.Attestations) > len(sc.Want.Chain)+len(sc.Want.OffLineage) {
			dupes++ // something was collapsed or is a rotation
		}
		for _, a := range sc.Attestations {
			if a.Kind == KindIdentityRotation {
				rotations++
			}
		}
	}
	for _, k := range []ProblemKind{ProblemFork, ProblemGap, ProblemOrder} {
		if !seen[k] {
			t.Errorf("no fixture produces a %q problem", k)
		}
	}
	if linear == 0 {
		t.Error("no fixture describes a clean non-empty history")
	}
	if dupes == 0 {
		t.Error("no fixture exercises collapsing or rotations")
	}
	if rotations == 0 {
		t.Error("no fixture exercises an identity rotation")
	}
}

func TestAnySignerAcceptsEveryIdentity(t *testing.T) {
	// With no declared root, a client's own local index is all it ever
	// claimed to trust, so every signer in it counts — and a second line
	// of history inside that index is still a fork.
	atts := []Attestation{
		{Kind: KindSchemaManifest, Signer: "a@example.com", RekorLogIndex: 10, RekorUUID: "u10", SchemaHash: "sha256:aaaa"},
		{Kind: KindSchemaManifest, Signer: "b@example.com", RekorLogIndex: 20, RekorUUID: "u20", SchemaHash: "sha256:bbbb", PreviousSchemaHash: sp("sha256:aaaa")},
		{Kind: KindSchemaManifest, Signer: "c@example.com", RekorLogIndex: 30, RekorUUID: "u30", SchemaHash: "sha256:cccc", PreviousSchemaHash: sp("sha256:aaaa")},
	}
	rep := Check(atts, AnySigner())
	if len(rep.OffLineage) != 0 {
		t.Errorf("AnySigner excluded %d attestation(s)", len(rep.OffLineage))
	}
	if got := kinds(rep.Problems); len(got) != 1 || got[0] != ProblemFork {
		t.Errorf("problems = %v, want one fork", got)
	}
}

func TestLineageIgnoresRotationsForOtherIdentities(t *testing.T) {
	atts := []Attestation{
		{Kind: KindIdentityRotation, Signer: "x@example.com", OldIdentity: "x@example.com", NewIdentity: "y@example.com"},
		{Kind: KindIdentityRotation, Signer: "p@example.com", OldIdentity: "p@example.com", NewIdentity: "q@example.com"},
	}
	l := NewLineage("p@example.com", atts)
	if l.Has("x@example.com") || l.Has("y@example.com") {
		t.Errorf("lineage leaked into an unrelated rotation: %v", l.Identities())
	}
	if !l.Has("q@example.com") {
		t.Errorf("lineage did not follow its own rotation: %v", l.Identities())
	}
	if l.Root() != "p@example.com" {
		t.Errorf("Root() = %q", l.Root())
	}
}

func TestLineageFollowsChainedRotations(t *testing.T) {
	atts := []Attestation{
		{Kind: KindIdentityRotation, Signer: "a@example.com", OldIdentity: "a@example.com", NewIdentity: "b@example.com"},
		{Kind: KindIdentityRotation, Signer: "b@example.com", OldIdentity: "b@example.com", NewIdentity: "c@example.com"},
	}
	for _, root := range []string{"a@example.com", "b@example.com", "c@example.com"} {
		l := NewLineage(root, atts)
		for _, want := range []string{"a@example.com", "b@example.com", "c@example.com"} {
			if !l.Has(want) {
				t.Errorf("root %s: lineage %v is missing %s", root, l.Identities(), want)
			}
		}
	}
}

// helpers

func sp(s string) *string { return &s }

func kinds(ps []Problem) []ProblemKind {
	out := make([]ProblemKind, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.Kind)
	}
	return out
}

func equalKinds(got, want []ProblemKind) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func assertHashes(t *testing.T, label string, got []Attestation, want []string) {
	t.Helper()
	var hashes []string
	for _, a := range got {
		hashes = append(hashes, a.SchemaHash)
	}
	if len(hashes) != len(want) {
		t.Errorf("%s = %v, want %v", label, hashes, want)
		return
	}
	for i := range hashes {
		if hashes[i] != want[i] {
			t.Errorf("%s = %v, want %v", label, hashes, want)
			return
		}
	}
}

func assertIdentities(t *testing.T, label string, got, want []string) {
	t.Helper()
	if len(want) == 0 {
		return
	}
	if len(got) != len(want) {
		t.Errorf("%s = %v, want %v", label, got, want)
		return
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("%s = %v, want %v", label, got, want)
			return
		}
	}
}

func render(r Report) string {
	b, _ := json.MarshalIndent(r, "", "  ")
	return string(b)
}
