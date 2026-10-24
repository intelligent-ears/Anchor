package history

import (
	"fmt"

	"anchor/internal/predicate"
)

// Source is where a verified attestation was found, and who signed it.
// SignerIdentity and OIDCIssuer must come from the Fulcio certificate in
// the bundle cosign just verified — never from the predicate's own
// publisherIdentity field, which is only the signer's claim about itself.
type Source struct {
	RekorUUID      string
	RekorLogIndex  int64
	SignerIdentity string
	OIDCIssuer     string
}

// FromStatement maps a verified in-toto Statement onto the history view of
// an attestation. It is the single place that decides what a statement
// means for history analysis, shared by the local-state path
// (cmd/anchor) and Rekor discovery (internal/bootstrap), so the two cannot
// drift apart.
//
// The caller must have cryptographically verified the bundle this
// statement came out of first. FromStatement does no verification; it only
// refuses statements that aren't Anchor's, or that are filed under the
// wrong tool.
func FromStatement(stmt *predicate.Statement, toolID string, src Source) (Attestation, error) {
	base := Attestation{
		ToolID:        toolID,
		Signer:        src.SignerIdentity,
		Issuer:        src.OIDCIssuer,
		RekorUUID:     src.RekorUUID,
		RekorLogIndex: src.RekorLogIndex,
	}

	switch stmt.PredicateType {
	case predicate.SchemaManifestType:
		m, err := stmt.SchemaManifest()
		if err != nil {
			return Attestation{}, err
		}
		if m.ToolID != toolID {
			return Attestation{}, fmt.Errorf("statement is for tool %q, not %q", m.ToolID, toolID)
		}
		hash, err := stmt.SubjectHash()
		if err != nil {
			return Attestation{}, err
		}
		base.Kind = KindSchemaManifest
		base.Timestamp = m.Timestamp
		base.SchemaHash = hash
		base.PreviousSchemaHash = m.PreviousSchemaHash
		base.SchemaVersion = m.SchemaVersion
		return base, nil

	case predicate.IdentityRotationType:
		r, err := stmt.IdentityRotation()
		if err != nil {
			return Attestation{}, err
		}
		if r.ToolID != toolID {
			return Attestation{}, fmt.Errorf("statement is for tool %q, not %q", r.ToolID, toolID)
		}
		base.Kind = KindIdentityRotation
		base.Timestamp = r.Timestamp
		base.OldIdentity = r.OldIdentity
		base.NewIdentity = r.NewIdentity
		return base, nil
	}
	return Attestation{}, fmt.Errorf("not an Anchor predicate: %q", stmt.PredicateType)
}
