package main

import (
	"context"
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

func runSign(args []string) error {
	fs := flag.NewFlagSet("anchor sign", flag.ExitOnError)
	toolID := fs.String("tool-id", "", "tool identifier this schema belongs to (required)")
	publisherIdentity := fs.String("publisher-identity", "", "the OIDC identity (email or URI) you are about to sign in as — cross-checked against the Fulcio cert after signing (required)")
	schemaVersion := fs.String("schema-version", "", "human-readable version label for this revision (required)")
	stateDir := fs.String("state-dir", ".anchor", "local Anchor state directory")
	fs.Parse(args)

	if fs.NArg() != 1 {
		return fmt.Errorf("usage: anchor sign --tool-id <id> --publisher-identity <id> --schema-version <v> <schema-file>")
	}
	if *toolID == "" || *publisherIdentity == "" || *schemaVersion == "" {
		return fmt.Errorf("--tool-id, --publisher-identity, and --schema-version are all required")
	}
	schemaFile := fs.Arg(0)

	raw, err := os.ReadFile(schemaFile)
	if err != nil {
		return fmt.Errorf("reading schema file: %w", err)
	}
	canonical, hash, err := canon.CanonicalizeAndHash(raw)
	if err != nil {
		return fmt.Errorf("canonicalizing schema: %w", err)
	}

	st, err := state.Open(*stateDir)
	if err != nil {
		return fmt.Errorf("opening local state: %w", err)
	}

	var previousHash *string
	if latest, ok := st.LatestSchemaManifest(*toolID); ok {
		h := latest.SchemaHash
		previousHash = &h
	}

	timestamp := time.Now().UTC().Format(time.RFC3339)
	manifest := predicate.SchemaManifest{
		ToolID:             *toolID,
		PublisherIdentity:  *publisherIdentity,
		SchemaVersion:      *schemaVersion,
		PreviousSchemaHash: previousHash,
		Timestamp:          timestamp,
	}
	statement, err := predicate.BuildSchemaManifestStatement(*toolID, hash, manifest)
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
	canonicalPath := filepath.Join(bundleDir, hexHash+".canonical.json")
	statementPath := filepath.Join(bundleDir, hexHash+".statement.json")
	bundlePath := filepath.Join(bundleDir, hexHash+".bundle.json")

	if err := os.WriteFile(canonicalPath, canonical, 0o644); err != nil {
		return fmt.Errorf("caching canonical schema: %w", err)
	}
	if err := os.WriteFile(statementPath, statementJSON, 0o644); err != nil {
		return fmt.Errorf("caching statement: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Signing schema-manifest statement for tool %q (schema hash %s)...\n", *toolID, hash)
	fmt.Fprintln(os.Stderr, "This uses Sigstore's keyless flow: complete the OIDC login it prompts for.")
	ctx := context.Background()
	if err := signer.AttestStatement(ctx, statementPath, bundlePath); err != nil {
		return err
	}

	info, err := signer.ParseBundle(bundlePath)
	if err != nil {
		return fmt.Errorf("parsing signed bundle: %w", err)
	}

	if !identity.Equal(info.SignerIdentity, *publisherIdentity) {
		return fmt.Errorf(
			"signed in as %q but --publisher-identity was %q. "+
				"The attestation is already public on Rekor (log index %d) and cannot be retracted, "+
				"but Anchor will not record it as this tool's known-good identity",
			info.SignerIdentity, *publisherIdentity, info.LogIndex)
	}

	rctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	entry, err := rekorapi.GetByLogIndex(rctx, info.LogIndex)
	if err != nil {
		return fmt.Errorf("signed successfully, but failed to confirm the entry live on Rekor: %w", err)
	}

	st.AppendLog(state.LogRecord{
		Kind:              state.KindSchemaManifest,
		ToolID:            *toolID,
		RekorUUID:         entry.UUID,
		RekorLogIndex:     info.LogIndex,
		PublisherIdentity: info.SignerIdentity,
		OIDCIssuer:        info.OIDCIssuer,
		SchemaHash:        hash,
		SchemaVersion:     *schemaVersion,
		Timestamp:         timestamp,
		BundlePath:        bundlePath,
		CanonicalPath:     canonicalPath,
	})
	st.KnownGood[*toolID] = state.LastKnownGood{
		ToolID:            *toolID,
		SchemaHash:        hash,
		PublisherIdentity: info.SignerIdentity,
		SchemaVersion:     *schemaVersion,
		UpdatedAt:         timestamp,
	}
	if err := st.Save(); err != nil {
		return fmt.Errorf("saving local state: %w", err)
	}

	fmt.Printf("OK: signed and logged to Rekor.\n")
	fmt.Printf("  Rekor UUID:  %s\n", entry.UUID)
	fmt.Printf("  Rekor index: %d\n", info.LogIndex)
	fmt.Printf("  Signer:      %s (issuer: %s)\n", info.SignerIdentity, info.OIDCIssuer)
	fmt.Printf("  Schema hash: %s\n", hash)
	return nil
}
