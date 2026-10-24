package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"anchor/internal/bootstrap"
	"anchor/internal/canon"
	"anchor/internal/diff"
	"anchor/internal/history"
	"anchor/internal/identity"
	"anchor/internal/rekorapi"
	"anchor/internal/state"
)

// bootstrapHelp is the --bootstrap-from-identity flag's help text. The
// trust rule is in it because the flag is unsafe without it: an identity
// taken from the schema being verified lets the publisher of that schema
// choose who you trust.
const bootstrapHelp = "rebuild this tool's attestation history from the public Rekor log, " +
	"searching from signer identity <id>, instead of relying on local state. " +
	"The identity MUST come from you or from out-of-band config you control — " +
	"NEVER from the schema being verified, or an attacker could simply name their own " +
	"identity and present a perfectly signed history of their own. " +
	"This is trust-on-first-use: it proves the history Rekor holds for that identity, " +
	"not that the identity is the tool's rightful publisher."

func runVerify(args []string) error {
	fs := flag.NewFlagSet("anchor verify", flag.ExitOnError)
	toolID := fs.String("tool-id", "", "tool identifier to verify against (required)")
	stateDir := fs.String("state-dir", ".anchor", "local Anchor state directory")
	bootstrapIdentity := fs.String("bootstrap-from-identity", "", bootstrapHelp)
	maxBootstrapEntries := fs.Int("max-bootstrap-entries", bootstrap.DefaultMaxEntries,
		"with --bootstrap-from-identity, the most Rekor entries one identity may have before the scan refuses. "+
			"Anchor will not report on a partial scan: a history missing revisions can look perfectly linear")
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
		if err := runBootstrap(ctx, st, *toolID, *bootstrapIdentity, *maxBootstrapEntries); err != nil {
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

	kg, hadKnownGood := st.KnownGood[*toolID]

	// The signed history must be one strict linear chain. Checking it needs
	// a root identity: whom does this client consider the publisher? Every
	// identity joined to that root by an attested rotation counts as the
	// same publisher, so a legitimate handoff is a link in the chain rather
	// than a second line of history.
	atts, err := collectAttestations(ctx, st, *toolID)
	if err != nil {
		return err
	}
	lineage := publisherLineage(*bootstrapIdentity, kg, hadKnownGood, atts)
	rep := history.Check(atts, lineage)
	if !rep.OK() {
		fmt.Print(forkedReport(*toolID, rep, lineage))
		return silentExit(1)
	}

	// First time verifying this tool locally: nothing to compare identity
	// against yet, so trust-on-first-use against whatever is validly
	// attested.
	if !hadKnownGood {
		fmt.Println("OK: schema matches latest attested revision.")
		if *bootstrapIdentity != "" {
			fmt.Printf("  (history rebuilt from the public Rekor log under identity %s, with no prior local state —\n", *bootstrapIdentity)
			fmt.Println("   trust-on-first-use: the chain is proven, the choice of publisher identity is yours)")
		} else {
			fmt.Println("  (no prior local record for this tool — trusting this attested revision on first use)")
		}
		printHistorySummary(rep)
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
		printHistorySummary(rep)
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
		printHistorySummary(rep)
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

// publisherLineage decides whose history is being checked.
//
// The root has to come from somewhere the publisher of the schema cannot
// choose. There are two such places, in order of preference:
//
//  1. the identity the user passed to --bootstrap-from-identity, which by
//     the flag's contract came from the user or their own config;
//  2. the identity this client previously approved and recorded locally,
//     which is its own earlier decision.
//
// With neither — a client whose local index exists but has no known-good
// entry yet — there is no declared publisher to root a lineage at, so
// every signer in that index counts (history.AnySigner). That is the
// honest reading: the index is this client's own record of what it has
// seen, and a second line of history inside it is still a fork.
func publisherLineage(bootstrapIdentity string, kg state.LastKnownGood, hadKnownGood bool, atts []history.Attestation) history.Lineage {
	switch {
	case bootstrapIdentity != "":
		return history.NewLineage(bootstrapIdentity, atts)
	case hadKnownGood && kg.PublisherIdentity != "":
		return history.NewLineage(kg.PublisherIdentity, atts)
	}
	return history.AnySigner()
}

// printHistorySummary states what the linearity check actually covered, so
// an OK verdict says how much history it is an OK over.
func printHistorySummary(rep history.Report) {
	n := len(rep.Chain)
	switch n {
	case 0:
		fmt.Println("  History:     no attested revisions in this publisher's chain")
	case 1:
		fmt.Println("  History:     1 attested revision (nothing to chain yet)")
	default:
		fmt.Printf("  History:     %d attested revisions, one linear chain (previousSchemaHash verified end to end)\n", n)
	}
	if len(rep.OffLineage) > 0 {
		fmt.Printf("  Note:        %d attestation(s) for this tool were signed by identities outside this\n", len(rep.OffLineage))
		fmt.Println("               publisher's lineage and were not treated as part of its history.")
	}
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
