package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"anchor/internal/canon"
	"anchor/internal/diff"
	"anchor/internal/history"
	"anchor/internal/identity"
	"anchor/internal/rekorapi"
	"anchor/internal/state"
)

func runVerify(args []string) error {
	fs := flag.NewFlagSet("anchor verify", flag.ExitOnError)
	toolID := fs.String("tool-id", "", "tool identifier to verify against (required)")
	stateDir := fs.String("state-dir", ".anchor", "local Anchor state directory")
	bootstrapIdentity := fs.String("bootstrap-from-identity", "", "discover this tool's attestation history on the public Rekor log from signer identity <id> (claimed out-of-band), instead of relying only on local state")
	fs.Parse(args)

	if fs.NArg() != 1 {
		return fmt.Errorf("usage: anchor verify --tool-id <id> <schema-file>")
	}
	if *toolID == "" {
		return fmt.Errorf("--tool-id is required")
	}
	schemaFile := fs.Arg(0)

	raw, err := os.ReadFile(schemaFile)
	if err != nil {
		return fmt.Errorf("reading schema file: %w", err)
	}
	liveCanonical, liveHash, err := canon.CanonicalizeAndHash(raw)
	if err != nil {
		return fmt.Errorf("canonicalizing schema: %w", err)
	}

	st, err := state.Open(*stateDir)
	if err != nil {
		return fmt.Errorf("opening local state: %w", err)
	}

	ctx := context.Background()

	if *bootstrapIdentity != "" {
		if err := bootstrapFromIdentity(ctx, st, *toolID, *bootstrapIdentity); err != nil {
			return fmt.Errorf("bootstrapping history from Rekor: %w", err)
		}
	}

	if _, ok := st.LatestSchemaManifest(*toolID); !ok {
		if *bootstrapIdentity != "" {
			fmt.Printf("BLOCKED: no Anchor attestations for tool %q found on Rekor under identity %q (or any identity it rotated to).\n", *toolID, *bootstrapIdentity)
			return silentExit(1)
		}
		fmt.Printf("BLOCKED: no attested revision found for tool %q — nothing to verify against.\n", *toolID)
		fmt.Println("Run `anchor sign` first, pass --bootstrap-from-identity <publisher>, or double-check --tool-id / --state-dir.")
		return silentExit(1)
	}

	// Does the live schema's hash match ANYTHING Anchor has ever signed for
	// this tool? If not, it's an unattested change — the core rug-pull case.
	matched, ok := st.FindByHash(*toolID, liveHash)
	if !ok {
		fmt.Println("BLOCKED: unattested schema change detected")
		fmt.Printf("  Tool:        %s\n", *toolID)
		fmt.Printf("  Live hash:   %s\n", liveHash)
		fmt.Println("  This hash does not match any attestation on record. Either the schema was")
		fmt.Println("  edited without being signed, or this is a tampered/rug-pulled copy.")
		return silentExit(1)
	}

	if err := reverify(ctx, matched); err != nil {
		return fmt.Errorf("the matching local attestation record failed re-verification: %w", err)
	}
	// A record discovered from Rekor has no cached schema file; the live
	// schema hashes to the verified subject digest, so cache it for diffs.
	if matched.CanonicalPath == "" {
		cp := strings.TrimSuffix(matched.BundlePath, ".bundle.json") + ".canonical.json"
		if err := os.WriteFile(cp, liveCanonical, 0o644); err == nil {
			st.SetCanonicalPath(*toolID, matched.RekorLogIndex, cp)
		}
	}

	// The signed history must be one strict linear chain.
	atts, err := collectAttestations(ctx, st, *toolID)
	if err != nil {
		return err
	}
	if problems := history.CheckLinear(atts); len(problems) > 0 {
		fmt.Print(forkedReport(*toolID, problems))
		return silentExit(1)
	}

	kg, hadKnownGood := st.KnownGood[*toolID]

	// First time verifying this tool locally: nothing to compare identity
	// against yet, so trust-on-first-use against whatever is validly
	// attested.
	if !hadKnownGood {
		fmt.Println("OK: schema matches latest attested revision.")
		fmt.Println("  (no prior local record for this tool — trusting this attested revision on first use)")
		printSigner(matched)
		saveKnownGood(st, *toolID, matched)
		return nil
	}

	if identity.Equal(matched.PublisherIdentity, kg.PublisherIdentity) {
		if liveHash == kg.SchemaHash {
			fmt.Println("OK: schema matches latest attested revision.")
		} else {
			fmt.Println("OK: routine update from known publisher.")
			printDiffAgainst(st, *toolID, kg.SchemaHash, liveCanonical)
		}
		printSigner(matched)
		saveKnownGood(st, *toolID, matched)
		return nil
	}

	// Identity differs from the last approved one. Only acceptable if an
	// attested rotation record, signed by the OLD identity, bridges it.
	rotation, bridged := st.HasRotationBridge(*toolID, kg.PublisherIdentity, matched.PublisherIdentity)
	if bridged {
		if err := reverify(ctx, rotation); err != nil {
			return fmt.Errorf("the identity-rotation record failed re-verification: %w", err)
		}
		fmt.Println("OK: schema matches latest attested revision.")
		fmt.Printf("  Publisher identity rotated: %s -> %s (attested rotation, Rekor index %d)\n",
			rotation.OldIdentity, rotation.NewIdentity, rotation.RekorLogIndex)
		if liveHash != kg.SchemaHash {
			printDiffAgainst(st, *toolID, kg.SchemaHash, liveCanonical)
		}
		printSigner(matched)
		saveKnownGood(st, *toolID, matched)
		return nil
	}

	fmt.Println("FLAGGED: publisher identity changed without an attested rotation")
	fmt.Printf("  Tool:            %s\n", *toolID)
	fmt.Printf("  Last approved:   %s\n", kg.PublisherIdentity)
	fmt.Printf("  Now signed by:   %s (issuer: %s)\n", matched.PublisherIdentity, matched.OIDCIssuer)
	fmt.Println("  No identity-rotation attestation on file authorizes this change.")
	fmt.Println("  Treat this as a possible rug pull: an attacker publishing under a new identity")
	fmt.Println("  would look exactly like this. If the rotation is legitimate, the OLD identity")
	fmt.Println("  must run `anchor rotate-identity` to authorize it.")
	return silentExit(1)
}

// reverify re-checks a cached local record cryptographically against the
// public Sigstore infrastructure: valid signature and cert chain, and a
// live (not just cached) confirmation that the entry is really on Rekor.
// This is what stops a compromised/edited local state.json from silently
// forging trust — the local files are only ever treated as pointers.
func reverify(ctx context.Context, rec state.LogRecord) error {
	if err := verifyRecordCrypto(ctx, rec); err != nil {
		return err
	}
	rctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if _, err := rekorapi.GetByUUID(rctx, rec.RekorUUID); err != nil {
		return fmt.Errorf("could not confirm entry live on the public Rekor log: %w", err)
	}
	return nil
}

func printSigner(rec state.LogRecord) {
	fmt.Printf("  Signer:      %s (issuer: %s)\n", rec.PublisherIdentity, rec.OIDCIssuer)
	fmt.Printf("  Rekor UUID:  %s (index %d)\n", rec.RekorUUID, rec.RekorLogIndex)
}

func printDiffAgainst(st *state.Store, toolID, oldHash string, newCanonical []byte) {
	old, ok := st.FindByHash(toolID, oldHash)
	if !ok {
		return // shouldn't happen: oldHash came from st.KnownGood, which is only ever set from a logged record
	}
	if old.CanonicalPath == "" {
		fmt.Println("  (previous revision's content isn't cached locally — only its hash is attested — so no diff is available)")
		return
	}
	oldCanonical, err := os.ReadFile(old.CanonicalPath)
	if err != nil {
		fmt.Printf("  (could not load previous revision to diff: %v)\n", err)
		return
	}
	changes, err := diff.Compute(oldCanonical, newCanonical)
	if err != nil {
		fmt.Printf("  (could not compute diff: %v)\n", err)
		return
	}
	fmt.Println("  Changes from previously known-good revision (for human review):")
	fmt.Print(diff.Render(changes))
}

func saveKnownGood(st *state.Store, toolID string, matched state.LogRecord) {
	st.KnownGood[toolID] = state.LastKnownGood{
		ToolID:            toolID,
		SchemaHash:        matched.SchemaHash,
		PublisherIdentity: matched.PublisherIdentity,
		SchemaVersion:     matched.SchemaVersion,
		UpdatedAt:         time.Now().UTC().Format(time.RFC3339),
	}
	if err := st.Save(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to persist updated local state: %v\n", err)
	}
}
