// Package history reasons about the sequence of attestations Anchor knows
// about for one tool, independent of where they came from (the local
// log-index, or discovery from the public Rekor log).
//
// The one rule it enforces: a tool's schema-manifest attestations must form
// a single strict linear chain. Each revision's previousSchemaHash has to
// name the revision attested immediately before it (in Rekor log order),
// and the first revision's has to be null. Two different revisions that
// both claim the same predecessor are a fork — exactly the "tool shadowing"
// shape, where a validly-signed second line of history exists beside the
// one a client approved. A previousSchemaHash that names nothing in the
// retrievable history is a gap.
//
// This is about provenance, not content: nothing here looks at what a
// schema says, only at whether the signed history is consistent.
package history

import (
	"fmt"
	"sort"
)

// Attestation is the part of a verified schema-manifest or identity-
// rotation attestation that history analysis cares about. Every field
// must come from a cryptographically verified source (the signed
// statement and the Fulcio certificate), never from an unverified cache.
type Attestation struct {
	Kind          string // "schema-manifest" or "identity-rotation"
	ToolID        string
	Signer        string // identity from the Fulcio certificate
	Issuer        string
	Timestamp     string // publisher-claimed, RFC 3339
	RekorUUID     string
	RekorLogIndex int64

	// schema-manifest
	SchemaHash         string
	PreviousSchemaHash *string
	SchemaVersion      string

	// identity-rotation
	OldIdentity string
	NewIdentity string
}

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

// Problem describes one way the history fails to be linear.
type Problem struct {
	Kind     ProblemKind
	Message  string
	Involved []Attestation
}

// Attestation kinds, matching the log-index record kinds.
const (
	KindSchemaManifest   = "schema-manifest"
	KindIdentityRotation = "identity-rotation"
)

const schemaManifest = KindSchemaManifest

// CheckLinear verifies that the schema-manifest attestations in atts form
// one strict linear chain, ordered by Rekor log index. It returns nil for a
// clean history. Identity-rotation attestations are ignored here.
//
// Exact duplicates (same schemaHash and same previousSchemaHash — e.g. the
// same schema signed twice) are collapsed: re-attesting identical content
// doesn't create a divergent history.
func CheckLinear(atts []Attestation) []Problem {
	var seq []Attestation
	for _, a := range atts {
		if a.Kind == schemaManifest {
			seq = append(seq, a)
		}
	}
	sort.SliceStable(seq, func(i, j int) bool { return seq[i].RekorLogIndex < seq[j].RekorLogIndex })

	seen := map[string]bool{}
	deduped := seq[:0:0]
	for _, a := range seq {
		k := a.SchemaHash + "\x00" + prevKey(a.PreviousSchemaHash)
		if seen[k] {
			continue
		}
		seen[k] = true
		deduped = append(deduped, a)
	}
	seq = deduped

	known := map[string]bool{}
	for _, a := range seq {
		known[a.SchemaHash] = true
	}

	var problems []Problem

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
			problems = append(problems, Problem{
				Kind:     ProblemFork,
				Message:  fmt.Sprintf("%d different schema revisions all claim %s", len(hashes), what),
				Involved: group,
			})
		}
	}

	// Gaps: a predecessor that matches nothing we can see.
	for _, a := range seq {
		if a.PreviousSchemaHash != nil && !known[*a.PreviousSchemaHash] {
			problems = append(problems, Problem{
				Kind: ProblemGap,
				Message: fmt.Sprintf("revision %s names previousSchemaHash %s, which matches no attestation in the retrievable history",
					a.SchemaHash, *a.PreviousSchemaHash),
				Involved: []Attestation{a},
			})
		}
	}

	// Strict ordering, only worth reporting if nothing more specific fired.
	if len(problems) == 0 {
		for i, a := range seq {
			var want *string
			if i > 0 {
				h := seq[i-1].SchemaHash
				want = &h
			}
			if prevKey(want) != prevKey(a.PreviousSchemaHash) {
				problems = append(problems, Problem{
					Kind: ProblemOrder,
					Message: fmt.Sprintf("revision %s (Rekor index %d) does not follow the revision logged immediately before it",
						a.SchemaHash, a.RekorLogIndex),
					Involved: []Attestation{a},
				})
				break
			}
		}
	}
	return problems
}

func prevKey(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
