// Package history reasons about the sequence of attestations Anchor knows
// about for one tool, independent of where they came from (the local
// log-index, or discovery from the public Rekor log).
//
// The one rule it enforces: a tool's schema-manifest attestations must form
// a single strict linear chain. Each revision's previousSchemaHash has to
// name the revision attested immediately before it (in Rekor log order),
// and the first revision's has to be null.
//
// Two different revisions that both claim the same predecessor are a
// **schema history fork**: the publisher has equivocated, putting two
// mutually exclusive lines of history on the public record, both validly
// signed. A previousSchemaHash that names nothing in the retrievable
// history is a gap.
//
// "Schema history fork" is this project's term for the threat, chosen
// deliberately: SAF-MCP (the OpenSSF Secure Agentic Framework) already
// uses "tool shadowing" (SAF-T1008) for a different attack — one server
// defining a tool that interferes with another server's trusted tool. That
// is not what this package detects.
//
// This is about provenance, not content: nothing here looks at what a
// schema says, only at whether the signed history is consistent. A clean
// linear chain does not mean the newest revision is safe, and a fork does
// not say which branch is the honest one — only that the publisher cannot
// have been telling everyone the same story.
package history

import (
	"fmt"
	"sort"

	"anchor/internal/identity"
)

// Attestation is the part of a verified schema-manifest or identity-
// rotation attestation that history analysis cares about. Every field
// must come from a cryptographically verified source (the signed
// statement and the Fulcio certificate), never from an unverified cache.
//
// The JSON tags are for the test fixtures in testdata, which describe
// histories in the same vocabulary the checks use.
type Attestation struct {
	Kind          string `json:"kind"` // KindSchemaManifest or KindIdentityRotation
	ToolID        string `json:"toolId,omitempty"`
	Signer        string `json:"signer,omitempty"` // identity from the Fulcio certificate
	Issuer        string `json:"issuer,omitempty"`
	Timestamp     string `json:"timestamp,omitempty"` // publisher-claimed, RFC 3339
	RekorUUID     string `json:"rekorUuid,omitempty"`
	RekorLogIndex int64  `json:"rekorLogIndex,omitempty"`

	// schema-manifest
	SchemaHash         string  `json:"schemaHash,omitempty"`
	PreviousSchemaHash *string `json:"previousSchemaHash,omitempty"`
	SchemaVersion      string  `json:"schemaVersion,omitempty"`

	// identity-rotation
	OldIdentity string `json:"oldIdentity,omitempty"`
	NewIdentity string `json:"newIdentity,omitempty"`
}

// Attestation kinds, matching the log-index record kinds.
const (
	KindSchemaManifest   = "schema-manifest"
	KindIdentityRotation = "identity-rotation"
)

// ProblemKind classifies why a history is not a strict linear chain.
type ProblemKind string

const (
	// ProblemFork: two different revisions claim the same predecessor.
	ProblemFork ProblemKind = "fork"
	// ProblemGap: a revision's previousSchemaHash matches nothing in the
	// retrievable history.
	ProblemGap ProblemKind = "gap"
	// ProblemOrder: no fork or gap, but a revision does not follow the one
	// logged immediately before it (e.g. it claims a predecessor that was
	// only logged later).
	ProblemOrder ProblemKind = "order"
)

// Problem describes one way the history fails to be linear. Involved
// carries the attestations a human needs in order to see the divergence —
// for a fork, every revision that claims the disputed predecessor.
type Problem struct {
	Kind     ProblemKind
	Message  string
	Involved []Attestation
}

// Lineage is the set of signing identities a client treats as one
// publisher for a tool: a root identity it got from somewhere it trusts,
// plus every identity joined to that root by an attested identity
// rotation.
//
// This is what keeps a legitimate handoff from reading as a fork. After
// `anchor rotate-identity`, a tool's history is signed partly by the old
// identity and partly by the new one; both are the same publisher, so both
// belong to the same chain. Conversely, a revision signed by an identity
// *outside* the lineage is not a fork at all — it is an impostor, which is
// a different finding (FLAGGED) and is left to the caller.
type Lineage struct {
	root string
	ids  []string
	all  bool
}

// AnySigner is the lineage to use when no root identity has been declared:
// every signer in the supplied attestations counts as the publisher. This
// is the honest reading of a trust-on-first-use client's local state, where
// whatever it has recorded is all it ever claimed to trust.
func AnySigner() Lineage { return Lineage{all: true} }

// NewLineage walks the attested identity rotations in atts to find every
// identity connected to root.
//
// Rotation links are followed in both directions. A rotation old -> new
// says "these two identities are the same publisher", and a client may
// hold either end as its root: a client that trusted the tool before the
// handoff knows only the old identity, while one that bootstrapped after
// it may know only the new one. Both have to be able to see the whole
// chain, or the half signed by the other identity would look like a gap.
//
// A rotation is only a link if its signer really is the identity it claims
// to be handing off from. That is the whole point of the rotation
// predicate: the new identity cannot authorize itself.
func NewLineage(root string, atts []Attestation) Lineage {
	type edge struct{ a, b string }
	var edges []edge
	for _, a := range atts {
		if a.Kind != KindIdentityRotation {
			continue
		}
		if a.OldIdentity == "" || a.NewIdentity == "" {
			continue
		}
		// Signed by the identity handing off, or it authorizes nothing.
		if a.Signer != "" && !identity.Equal(a.Signer, a.OldIdentity) {
			continue
		}
		edges = append(edges, edge{a.OldIdentity, a.NewIdentity})
	}

	l := Lineage{root: root, ids: []string{root}}
	for grew := true; grew; {
		grew = false
		for _, e := range edges {
			for _, pair := range [][2]string{{e.a, e.b}, {e.b, e.a}} {
				if l.Has(pair[0]) && !l.Has(pair[1]) {
					l.ids = append(l.ids, pair[1])
					grew = true
				}
			}
		}
	}
	return l
}

// Has reports whether id is part of this lineage.
func (l Lineage) Has(id string) bool {
	if l.all {
		return true
	}
	for _, known := range l.ids {
		if identity.Equal(known, id) {
			return true
		}
	}
	return false
}

// Root returns the identity the lineage was built from, or "" for
// AnySigner.
func (l Lineage) Root() string { return l.root }

// Identities returns every identity in the lineage, root first.
func (l Lineage) Identities() []string { return append([]string(nil), l.ids...) }

// Report is the outcome of a linearity check.
type Report struct {
	// Problems is every way the history fails to be a strict linear chain.
	// Empty means the chain is linear.
	Problems []Problem
	// Chain is the accepted schema-manifest attestations, deduplicated and
	// in Rekor log order — the history the checks were run over.
	Chain []Attestation
	// OffLineage is the schema-manifest attestations for this tool that
	// were signed by an identity outside the lineage, and so were not
	// treated as part of the publisher's history. They are reported, not
	// checked: an unrelated signer attesting a schema is an identity
	// finding, not a fork.
	OffLineage []Attestation
}

// OK reports whether the history is a single strict linear chain.
func (r Report) OK() bool { return len(r.Problems) == 0 }

// Check verifies that the schema-manifest attestations in atts that were
// signed by the given lineage form one strict linear chain, ordered by
// Rekor log index. Identity-rotation attestations shape the lineage (see
// NewLineage) but are not themselves links in the schema chain.
//
// Exact duplicates (same schemaHash and same previousSchemaHash — e.g. the
// same schema signed twice) are collapsed: re-attesting identical content
// doesn't create a divergent history.
func Check(atts []Attestation, lineage Lineage) Report {
	var rep Report
	var seq []Attestation
	for _, a := range atts {
		if a.Kind != KindSchemaManifest {
			continue
		}
		if lineage.Has(a.Signer) {
			seq = append(seq, a)
		} else {
			rep.OffLineage = append(rep.OffLineage, a)
		}
	}
	sort.SliceStable(seq, func(i, j int) bool { return seq[i].RekorLogIndex < seq[j].RekorLogIndex })

	seen := map[string]bool{}
	deduped := make([]Attestation, 0, len(seq))
	for _, a := range seq {
		k := a.SchemaHash + "\x00" + prevKey(a.PreviousSchemaHash)
		if seen[k] {
			continue
		}
		seen[k] = true
		deduped = append(deduped, a)
	}
	seq = deduped
	rep.Chain = seq

	known := map[string]bool{}
	for _, a := range seq {
		known[a.SchemaHash] = true
	}

	// Forks: more than one distinct schemaHash claiming the same predecessor.
	byPrev := map[string][]Attestation{}
	var prevOrder []string
	for _, a := range seq {
		k := prevKey(a.PreviousSchemaHash)
		if _, ok := byPrev[k]; !ok {
			prevOrder = append(prevOrder, k)
		}
		byPrev[k] = append(byPrev[k], a)
	}
	for _, k := range prevOrder {
		group := byPrev[k]
		hashes := map[string]bool{}
		for _, a := range group {
			hashes[a.SchemaHash] = true
		}
		if len(hashes) > 1 {
			what := "previousSchemaHash " + k
			if k == "" {
				what = "no previousSchemaHash (each claims to be the first revision)"
			}
			rep.Problems = append(rep.Problems, Problem{
				Kind:     ProblemFork,
				Message:  fmt.Sprintf("%d different schema revisions all claim %s", len(hashes), what),
				Involved: group,
			})
		}
	}

	// Gaps: a predecessor that matches nothing we can see.
	for _, a := range seq {
		if a.PreviousSchemaHash != nil && !known[*a.PreviousSchemaHash] {
			rep.Problems = append(rep.Problems, Problem{
				Kind: ProblemGap,
				Message: fmt.Sprintf("revision %s names previousSchemaHash %s, which matches no attestation in the retrievable history",
					a.SchemaHash, *a.PreviousSchemaHash),
				Involved: []Attestation{a},
			})
		}
	}

	// Strict ordering, only worth reporting if nothing more specific fired.
	if len(rep.Problems) == 0 {
		for i, a := range seq {
			var want *string
			if i > 0 {
				h := seq[i-1].SchemaHash
				want = &h
			}
			if prevKey(want) != prevKey(a.PreviousSchemaHash) {
				rep.Problems = append(rep.Problems, Problem{
					Kind: ProblemOrder,
					Message: fmt.Sprintf("revision %s (Rekor index %d) does not follow the revision logged immediately before it",
						a.SchemaHash, a.RekorLogIndex),
					Involved: []Attestation{a},
				})
				break
			}
		}
	}
	return rep
}

func prevKey(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
