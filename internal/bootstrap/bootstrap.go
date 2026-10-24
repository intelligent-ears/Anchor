// Package bootstrap reconstructs a tool's attestation history from the
// public Rekor log alone, with no pre-existing local state.
//
// It exists because Anchor's normal verify path reads a local pointer
// index (internal/state) that only the client which did the signing has.
// A second client — a different machine, a fresh checkout, anyone who just
// received a schema — has nothing to compare against. Rekor cannot be
// searched by Anchor's custom predicate fields like toolId, but it *can*
// be searched by signer identity, so a client that knows who the publisher
// is supposed to be can pull that identity's entries, keep the ones that
// are Anchor attestations for the tool in question, and rebuild the
// history from them.
//
// # The trust rule
//
// The identity handed to Discover must come from the user, or from
// out-of-band configuration the user controls. It must NEVER be taken from
// the schema being verified, or from anything else the publisher of that
// schema controls. An attacker who can choose which identity you trust can
// simply name their own: they would then have a perfectly linear,
// perfectly signed history, all of it theirs. Nothing in this package can
// detect that, because there is nothing wrong with it — the error was in
// where the identity came from.
//
// What a successful bootstrap proves is therefore narrow: *this is the
// history Rekor holds for that identity*. It does not prove that the
// identity is the right publisher for the tool. That makes it
// trust-on-first-use, and callers must say so.
package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"anchor/internal/history"
	"anchor/internal/identity"
	"anchor/internal/predicate"
	"anchor/internal/rekorapi"
	"anchor/internal/signer"
	"anchor/internal/state"
)

// DefaultMaxEntries bounds how many Rekor entries one identity may have
// before Discover refuses. The bound matters because a partial scan of a
// history is indistinguishable from a history with revisions missing: it
// would present as a gap, or worse, as a clean short chain. Refusing is
// the only answer that doesn't quietly weaken the check.
const DefaultMaxEntries = 2000

// Verifier is the cryptographic check Discover applies to every candidate
// entry: signature, Fulcio certificate chain, Rekor inclusion proof. It is
// an interface so the reconstruction logic can be unit-tested without
// cosign on PATH — never so that it can be skipped in production.
type Verifier interface {
	VerifyBundle(ctx context.Context, bundlePath, predicateType string) error
}

// CosignVerifier is the real Verifier: it shells out to cosign.
type CosignVerifier struct{}

func (CosignVerifier) VerifyBundle(ctx context.Context, bundlePath, predicateType string) error {
	return signer.VerifyBundleNoClaims(ctx, bundlePath, predicateType)
}

// Options configures one discovery run.
type Options struct {
	// ToolID is the tool whose history is being rebuilt.
	ToolID string
	// Identity is the claimed publisher identity to start from. See the
	// package comment: it must come from the user, not from the schema.
	Identity string
	// MaxEntries caps how many Rekor entries a single identity may have.
	// Zero means DefaultMaxEntries.
	MaxEntries int
	// Rekor is the read-only log client.
	Rekor rekorapi.Client
	// Verifier checks each candidate entry cryptographically.
	Verifier Verifier
	// BundleDir is where reconstructed bundles are written, so cosign has
	// a file to verify. Entries that don't survive verification are
	// removed again.
	BundleDir string
	// Progress, if set, receives human-readable progress lines.
	Progress io.Writer
}

// Result is what one discovery run found.
type Result struct {
	// Records are local pointer records for every verified attestation,
	// ready to be appended to a state.Store.
	Records []state.LogRecord
	// Attestations is the same set in the form history.Check wants.
	Attestations []history.Attestation
	// Identities is every identity scanned, in the order they were
	// reached: the claimed one first, then each successor named by an
	// attested rotation.
	Identities []string

	// Counters, for an honest report of what the scan did and did not see.
	Scanned            int // Rekor entries fetched and examined
	Manifests          int // schema-manifest attestations kept
	Rotations          int // identity-rotation attestations kept
	NotAnchor          int // entries that aren't Anchor attestations for this tool
	FailedVerification int // entries that failed cryptographic verification
	NoPayload          int // entries Rekor returned without their DSSE payload
}

// CapExceededError means an identity has more Rekor entries than the scan
// was allowed to examine. Discover returns it instead of scanning a prefix,
// because a truncated history is not a history.
type CapExceededError struct {
	Identity string
	Count    int
	Cap      int
}

func (e *CapExceededError) Error() string {
	return fmt.Sprintf("identity %s has %d Rekor entries, more than the %d this scan is allowed to examine; "+
		"scanning only part of them would hide revisions and make the history look linear when it may not be. "+
		"Raise the cap to scan all of them",
		e.Identity, e.Count, e.Cap)
}

// NoPayloadError means Rekor returned entries for the identity but none of
// them carried the DSSE payload, so no predicate could be read back. On
// the public instance this is the expected outcome for "dsse" entry kinds,
// which record only a payload hash — see the README's known limitations.
type NoPayloadError struct {
	Identity string
	Count    int
}

func (e *NoPayloadError) Error() string {
	return fmt.Sprintf("public Rekor returned no attestation payload for any of identity %s's %d entries: "+
		"\"dsse\" entries expose only a payload hash, so Anchor's predicate (toolId, previousSchemaHash) "+
		"cannot be recovered from Rekor alone; the signer's bundles must be obtained out-of-band",
		e.Identity, e.Count)
}

// Discover rebuilds toolID's history from the public log, starting at the
// claimed identity and following every attested identity rotation it finds
// to that identity's successors. Every entry kept has been verified
// cryptographically, and every field in the result is read out of the
// verified statement and certificate — nothing is taken from an entry's
// unverified body.
//
// The returned Attestations are ready for history.Check; Discover does not
// itself judge whether the history is linear.
func Discover(ctx context.Context, opts Options) (*Result, error) {
	if opts.ToolID == "" {
		return nil, fmt.Errorf("bootstrap: no tool id")
	}
	if opts.Identity == "" {
		return nil, fmt.Errorf("bootstrap: no identity to start from")
	}
	if opts.Rekor == nil {
		return nil, fmt.Errorf("bootstrap: no Rekor client")
	}
	if opts.Verifier == nil {
		return nil, fmt.Errorf("bootstrap: no verifier")
	}
	if opts.BundleDir == "" {
		return nil, fmt.Errorf("bootstrap: no bundle directory")
	}
	maxEntries := opts.MaxEntries
	if maxEntries <= 0 {
		maxEntries = DefaultMaxEntries
	}

	res := &Result{}
	queue := []string{opts.Identity}
	visited := map[string]bool{}
	seenLogIndex := map[int64]bool{}

	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		key := strings.ToLower(id)
		if visited[key] {
			continue
		}
		visited[key] = true
		res.Identities = append(res.Identities, id)

		uuids, err := searchIdentity(ctx, opts.Rekor, id)
		if err != nil {
			return nil, err
		}
		if len(uuids) > maxEntries {
			return nil, &CapExceededError{Identity: id, Count: len(uuids), Cap: maxEntries}
		}
		progressf(opts.Progress, "  %s: %d Rekor entr%s to examine\n", id, len(uuids), plural(len(uuids)))

		entries, err := opts.Rekor.GetEntries(ctx, uuids)
		if err != nil {
			return nil, err
		}
		res.Scanned += len(entries)

		noPayload := 0
		for _, e := range entries {
			if e.Attestation == nil || e.Attestation.Data == "" {
				noPayload++
			}
		}
		res.NoPayload += noPayload
		if len(entries) > 0 && noPayload == len(entries) {
			return nil, &NoPayloadError{Identity: id, Count: len(entries)}
		}

		for _, e := range entries {
			if seenLogIndex[e.LogIndex] {
				continue
			}
			seenLogIndex[e.LogIndex] = true

			found, err := examine(ctx, opts, id, e)
			if err != nil {
				switch {
				case errIsVerification(err):
					res.FailedVerification++
					progressf(opts.Progress, "  skipping Rekor index %d: failed cryptographic verification\n", e.LogIndex)
				default:
					res.NotAnchor++
				}
				continue
			}
			res.Records = append(res.Records, found.record)
			res.Attestations = append(res.Attestations, found.attestation)
			if found.record.Kind == state.KindIdentityRotation {
				res.Rotations++
				if found.next != "" {
					queue = append(queue, found.next)
				}
			} else {
				res.Manifests++
			}
		}
	}
	return res, nil
}

// searchIdentity asks the index for an identity, also trying its lowercased
// form. Rekor's index is built from the certificate's SAN as issued, and an
// OIDC provider may normalize case differently from however a user typed
// the identity (see internal/identity).
func searchIdentity(ctx context.Context, client rekorapi.Client, id string) ([]string, error) {
	variants := []string{id}
	if lower := strings.ToLower(id); lower != id {
		variants = append(variants, lower)
	}
	seen := map[string]bool{}
	var uuids []string
	for _, v := range variants {
		found, err := client.SearchByEmail(ctx, v)
		if err != nil {
			return nil, fmt.Errorf("searching Rekor for %s: %w", v, err)
		}
		for _, u := range found {
			if !seen[u] {
				seen[u] = true
				uuids = append(uuids, u)
			}
		}
	}
	return uuids, nil
}

type candidate struct {
	record      state.LogRecord
	attestation history.Attestation
	next        string // for a rotation: the identity being handed off to
}

// verificationError marks the one failure mode worth telling the user
// about individually: an entry that looked like an Anchor attestation but
// did not survive cryptographic verification.
type verificationError struct{ err error }

func (e *verificationError) Error() string { return e.err.Error() }
func (e *verificationError) Unwrap() error { return e.err }

func errIsVerification(err error) bool {
	var ve *verificationError
	return errors.As(err, &ve)
}

// examine turns one Rekor entry into a verified record, or an error saying
// why it isn't one. The order of operations matters: everything before the
// verifier call is an unverified pre-filter whose only job is to avoid
// running cosign on unrelated entries, and every value kept afterwards is
// re-read from the bundle the verifier accepted.
func examine(ctx context.Context, opts Options, signerID string, e rekorapi.Entry) (*candidate, error) {
	bundleJSON, statementBytes, err := signer.BundleFromRekorEntry(e)
	if err != nil {
		return nil, fmt.Errorf("not a keyless DSSE entry: %w", err)
	}
	pre, err := predicate.ParseStatement(statementBytes)
	if err != nil {
		return nil, fmt.Errorf("not an in-toto statement: %w", err)
	}
	if pre.PredicateType != predicate.SchemaManifestType && pre.PredicateType != predicate.IdentityRotationType {
		return nil, fmt.Errorf("not an Anchor predicate: %q", pre.PredicateType)
	}

	if err := os.MkdirAll(opts.BundleDir, 0o755); err != nil {
		return nil, err
	}
	bundlePath := filepath.Join(opts.BundleDir, fmt.Sprintf("rekor-%d.bundle.json", e.LogIndex))
	if err := os.WriteFile(bundlePath, bundleJSON, 0o644); err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			os.Remove(bundlePath)
		}
	}()

	if err := opts.Verifier.VerifyBundle(ctx, bundlePath, pre.PredicateType); err != nil {
		return nil, &verificationError{err}
	}

	// From here on, only the verified bundle is believed.
	info, err := signer.ParseBundleBytes(bundleJSON)
	if err != nil {
		return nil, err
	}
	if !identity.Equal(info.SignerIdentity, signerID) {
		return nil, fmt.Errorf("entry is signed by %q, not the %q it was indexed under", info.SignerIdentity, signerID)
	}
	stmt, err := predicate.ParseStatement(info.Statement)
	if err != nil {
		return nil, err
	}
	att, err := history.FromStatement(stmt, opts.ToolID, history.Source{
		RekorUUID:      e.UUID,
		RekorLogIndex:  e.LogIndex,
		SignerIdentity: info.SignerIdentity,
		OIDCIssuer:     info.OIDCIssuer,
	})
	if err != nil {
		return nil, err
	}

	rec := state.LogRecord{
		ToolID:        opts.ToolID,
		RekorUUID:     e.UUID,
		RekorLogIndex: e.LogIndex,
		Timestamp:     att.Timestamp,
		BundlePath:    bundlePath,
	}
	c := &candidate{attestation: att}
	switch att.Kind {
	case history.KindSchemaManifest:
		rec.Kind = state.KindSchemaManifest
		rec.PublisherIdentity = info.SignerIdentity // the certificate, not the predicate's claim
		rec.OIDCIssuer = info.OIDCIssuer
		rec.SchemaHash = att.SchemaHash
		rec.SchemaVersion = att.SchemaVersion
	case history.KindIdentityRotation:
		// A rotation means "I, oldIdentity, authorize newIdentity". If the
		// certificate says someone else signed it, the statement is not
		// what it claims to be, and recording it under the signer's name
		// would silently reinterpret it as that signer's own handoff.
		// Reject it instead: the new identity cannot authorize itself, and
		// nobody can authorize a handoff on a third party's behalf.
		if !identity.Equal(att.OldIdentity, info.SignerIdentity) {
			return nil, fmt.Errorf("rotation claims to hand off from %q but was signed by %q",
				att.OldIdentity, info.SignerIdentity)
		}
		rec.Kind = state.KindIdentityRotation
		rec.OldIdentity = info.SignerIdentity
		rec.NewIdentity = att.NewIdentity
		c.next = att.NewIdentity
	}
	c.record = rec
	keep = true
	return c, nil
}

func progressf(w io.Writer, format string, args ...any) {
	if w == nil {
		return
	}
	fmt.Fprintf(w, format, args...)
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}
