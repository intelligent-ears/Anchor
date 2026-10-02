package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"anchor/internal/identity"
	"anchor/internal/predicate"
	"anchor/internal/rekorapi"
	"anchor/internal/signer"
	"anchor/internal/state"
)

// maxBootstrapEntries bounds how many Rekor entries one identity may have
// before discovery refuses: a truncated history would look like gaps.
const maxBootstrapEntries = 2000

// bootstrapFromIdentity reconstructs toolID's attestation history from the
// public Rekor log, with no prior local state. It searches Rekor for every
// entry signed by the claimed identity, keeps only Anchor predicates for
// this toolId, cryptographically verifies each one with cosign, and follows
// attested identity rotations to the identity's successors. Verified
// records are added to st. The claimed identity itself is trusted only as
// far as the caller trusts wherever they got it from (trust on first use).
func bootstrapFromIdentity(ctx context.Context, st *state.Store, toolID, claimed string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	fmt.Printf("Bootstrapping history for tool %q from Rekor, starting at identity %s\n", toolID, claimed)
	fmt.Println("  (read-only lookup; the claimed identity is trusted on first use — verify it out-of-band)")

	queue := []string{claimed}
	visited := map[string]bool{}
	added, manifests, rotations := 0, 0, 0

	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		if visited[strings.ToLower(id)] {
			continue
		}
		visited[strings.ToLower(id)] = true

		variants := []string{id}
		if lower := strings.ToLower(id); lower != id {
			variants = append(variants, lower)
		}
		seenUUID := map[string]bool{}
		var uuids []string
		for _, v := range variants {
			found, err := rekorapi.SearchByEmail(ctx, v)
			if err != nil {
				return err
			}
			for _, u := range found {
				if !seenUUID[u] {
					seenUUID[u] = true
					uuids = append(uuids, u)
				}
			}
		}
		if len(uuids) > maxBootstrapEntries {
			return fmt.Errorf("identity %s has %d Rekor entries (limit %d); refusing to reconstruct a possibly truncated history", id, len(uuids), maxBootstrapEntries)
		}
		fmt.Printf("  %s: %d Rekor entr%s to examine\n", id, len(uuids), plural(len(uuids)))

		entries, err := rekorapi.GetEntries(ctx, uuids)
		if err != nil {
			return err
		}
		noPayload := 0
		for _, e := range entries {
			if e.Attestation == nil || e.Attestation.Data == "" {
				noPayload++
			}
		}
		if len(entries) > 0 && noPayload == len(entries) {
			return fmt.Errorf("public Rekor returned no attestation payload for any of identity %s's %d entries: DSSE entries expose only a payload hash, so the predicate (toolId, previousSchemaHash) can't be recovered from Rekor alone; the signer's bundle must be obtained out-of-band", id, len(entries))
		}
		for _, e := range entries {
			if st.HasLogIndex(toolID, e.LogIndex) {
				continue
			}
			rec, next, ok := candidateRecord(ctx, st, toolID, id, e)
			if !ok {
				continue
			}
			st.AppendLog(rec)
			added++
			if rec.Kind == state.KindIdentityRotation {
				rotations++
				if next != "" {
					queue = append(queue, next)
				}
			} else {
				manifests++
			}
		}
	}
	if err := st.Save(); err != nil {
		return fmt.Errorf("saving local state: %w", err)
	}
	fmt.Printf("  Discovered %d new attestation(s): %d schema revision(s), %d identity rotation(s)\n", added, manifests, rotations)
	return nil
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

// candidateRecord turns one Rekor entry into a verified local record, or
// reports ok=false if it isn't an Anchor attestation for toolID signed by
// signerID (or fails verification). For identity rotations it also returns
// the identity being rotated to, if the rotation is well-formed.
func candidateRecord(ctx context.Context, st *state.Store, toolID, signerID string, e rekorapi.Entry) (rec state.LogRecord, next string, ok bool) {
	bundleJSON, statementBytes, err := signer.BundleFromRekorEntry(e)
	if err != nil {
		return rec, "", false // not a keyless DSSE entry Anchor could have produced
	}
	// Unverified pre-filter, only to avoid running cosign on unrelated
	// entries. Everything kept is re-read from the verified bundle below.
	pre, err := predicate.ParseStatement(statementBytes)
	if err != nil || (pre.PredicateType != predicate.SchemaManifestType && pre.PredicateType != predicate.IdentityRotationType) {
		return rec, "", false
	}

	dir, err := st.BundleDir(toolID)
	if err != nil {
		return rec, "", false
	}
	bundlePath := filepath.Join(dir, fmt.Sprintf("rekor-%d.bundle.json", e.LogIndex))
	if err := os.WriteFile(bundlePath, bundleJSON, 0o644); err != nil {
		return rec, "", false
	}
	keep := false
	defer func() {
		if !keep {
			os.Remove(bundlePath)
		}
	}()
	if err := signer.VerifyBundleNoClaims(ctx, bundlePath, pre.PredicateType); err != nil {
		fmt.Fprintf(os.Stderr, "  skipping Rekor index %d: failed cryptographic verification\n", e.LogIndex)
		return rec, "", false
	}
	info, err := signer.ParseBundleBytes(bundleJSON)
	if err != nil || !identity.Equal(info.SignerIdentity, signerID) {
		return rec, "", false
	}
	stmt, err := predicate.ParseStatement(info.Statement)
	if err != nil {
		return rec, "", false
	}

	base := state.LogRecord{
		ToolID:        toolID,
		RekorUUID:     e.UUID,
		RekorLogIndex: e.LogIndex,
		BundlePath:    bundlePath,
	}
	switch stmt.PredicateType {
	case predicate.SchemaManifestType:
		m, err := stmt.SchemaManifest()
		hash, herr := stmt.SubjectHash()
		if err != nil || herr != nil || m.ToolID != toolID {
			return rec, "", false
		}
		base.Kind = state.KindSchemaManifest
		base.Timestamp = m.Timestamp
		base.PublisherIdentity = info.SignerIdentity // the certificate, not the predicate's claim
		base.OIDCIssuer = info.OIDCIssuer
		base.SchemaHash = hash
		base.SchemaVersion = m.SchemaVersion
		keep = true
		return base, "", true
	case predicate.IdentityRotationType:
		r, err := stmt.IdentityRotation()
		if err != nil || r.ToolID != toolID {
			return rec, "", false
		}
		base.Kind = state.KindIdentityRotation
		base.Timestamp = r.Timestamp
		base.OldIdentity = info.SignerIdentity
		base.NewIdentity = r.NewIdentity
		keep = true
		// Only follow the rotation if the signer really is the identity the
		// rotation says it is handing off from.
		if identity.Equal(r.OldIdentity, info.SignerIdentity) {
			next = r.NewIdentity
		}
		return base, next, true
	}
	return rec, "", false
}
