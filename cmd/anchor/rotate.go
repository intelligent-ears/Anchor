package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"anchor/internal/canon"
	"anchor/internal/identity"
	"anchor/internal/predicate"
	"anchor/internal/rekorapi"
	"anchor/internal/signer"
	"anchor/internal/state"
)

func runRotateIdentity(args []string) error {
	fs := flag.NewFlagSet("anchor rotate-identity", flag.ExitOnError)
	toolID := fs.String("tool-id", "", "tool identifier whose publisher identity is rotating (required)")
	newIdentity := fs.String("new-identity", "", "the new identity authorized to sign future revisions (required)")
	reason := fs.String("reason", "", "optional human-readable reason for the rotation")
	stateDir := fs.String("state-dir", ".anchor", "local Anchor state directory")
	fs.Parse(args)

	if *toolID == "" || *newIdentity == "" {
		return fmt.Errorf("--tool-id and --new-identity are required")
	}

	st, err := state.Open(*stateDir)
	if err != nil {
		return fmt.Errorf("opening local state: %w", err)
	}
	kg, ok := st.KnownGood[*toolID]
	if !ok {
		return fmt.Errorf("no known-good identity on file for tool %q — sign at least one schema revision first", *toolID)
	}
	oldIdentity := kg.PublisherIdentity

	timestamp := time.Now().UTC().Format(time.RFC3339)
	rotation := predicate.IdentityRotation{
		ToolID:      *toolID,
		OldIdentity: oldIdentity,
		NewIdentity: *newIdentity,
		Timestamp:   timestamp,
		Reason:      *reason,
	}
	rotationDoc, err := json.MarshalIndent(rotation, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling rotation record: %w", err)
	}
	canonical, hash, err := canon.CanonicalizeAndHash(rotationDoc)
	if err != nil {
		return fmt.Errorf("canonicalizing rotation record: %w", err)
	}
	statement, err := predicate.BuildIdentityRotationStatement(*toolID, rotation, hash)
	if err != nil {
		return fmt.Errorf("building in-toto statement: %w", err)
	}
	statementJSON, err := statement.Marshal()
	if err != nil {
		return fmt.Errorf("marshaling statement: %w", err)
	}

	bundleDir, err := st.BundleDir(*toolID)
	if err != nil {
		return fmt.Errorf("preparing bundle cache dir: %w", err)
	}
	hexHash := strings.TrimPrefix(hash, "sha256:")
	canonicalPath := filepath.Join(bundleDir, "rotation-"+hexHash+".canonical.json")
	statementPath := filepath.Join(bundleDir, "rotation-"+hexHash+".statement.json")
	bundlePath := filepath.Join(bundleDir, "rotation-"+hexHash+".bundle.json")

	if err := os.WriteFile(canonicalPath, canonical, 0o644); err != nil {
		return fmt.Errorf("caching canonical rotation record: %w", err)
	}
	if err := os.WriteFile(statementPath, statementJSON, 0o644); err != nil {
		return fmt.Errorf("caching statement: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Signing identity-rotation statement for tool %q: %s -> %s\n", *toolID, oldIdentity, *newIdentity)
	fmt.Fprintln(os.Stderr, "IMPORTANT: sign in as the CURRENT identity ("+oldIdentity+") when prompted.")
	ctx := context.Background()
	if err := signer.AttestStatement(ctx, statementPath, bundlePath); err != nil {
		return err
	}

	info, err := signer.ParseBundle(bundlePath)
	if err != nil {
		return fmt.Errorf("parsing signed bundle: %w", err)
	}

	rctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	entry, err := rekorapi.GetByLogIndex(rctx, info.LogIndex)
	if err != nil {
		return fmt.Errorf("signed successfully, but failed to confirm the entry live on Rekor: %w", err)
	}

	// Record what the certificate actually says, not what we intended —
	// this is what makes the bridge check in `verify` self-defending: if
	// the wrong account signed this, OldIdentity here won't equal the
	// tool's real known-good identity, and HasRotationBridge simply won't
	// match it later.
	st.AppendLog(state.LogRecord{
		Kind:          state.KindIdentityRotation,
		ToolID:        *toolID,
		RekorUUID:     entry.UUID,
		RekorLogIndex: info.LogIndex,
		Timestamp:     timestamp,
		OldIdentity:   info.SignerIdentity,
		NewIdentity:   *newIdentity,
		BundlePath:    bundlePath,
		CanonicalPath: canonicalPath,
	})

	if !identity.Equal(info.SignerIdentity, oldIdentity) {
		if err := st.Save(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to persist local state: %v\n", err)
		}
		return fmt.Errorf(
			"signed in as %q but this tool's known-good identity is %q. "+
				"The attestation is public on Rekor (log index %d) but Anchor will NOT treat it as "+
				"an authorized rotation, since it wasn't signed by the current identity",
			info.SignerIdentity, oldIdentity, info.LogIndex)
	}

	st.KnownGood[*toolID] = state.LastKnownGood{
		ToolID:            *toolID,
		SchemaHash:        kg.SchemaHash,
		PublisherIdentity: *newIdentity,
		SchemaVersion:     kg.SchemaVersion,
		UpdatedAt:         timestamp,
	}
	if err := st.Save(); err != nil {
		return fmt.Errorf("saving local state: %w", err)
	}

	fmt.Printf("OK: identity rotation signed and logged to Rekor.\n")
	fmt.Printf("  Rekor UUID:  %s\n", entry.UUID)
	fmt.Printf("  Rekor index: %d\n", info.LogIndex)
	fmt.Printf("  %s -> %s\n", oldIdentity, *newIdentity)
	fmt.Println("  Future `anchor verify` calls will accept schema revisions signed by the new identity.")
	return nil
}
