package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"anchor/internal/bootstrap"
	"anchor/internal/rekorapi"
	"anchor/internal/state"
)

// runBootstrap discovers toolID's attestation history on the public Rekor
// log, starting from an identity the *user* supplied, and records what it
// verified in st. It is the no-local-state path: a second client that has
// never signed anything can still get a history to check.
//
// The claimed identity is trust-on-first-use. See internal/bootstrap for
// why it must never be read out of the schema being verified.
func runBootstrap(ctx context.Context, st *state.Store, toolID, claimed string, maxEntries int) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	fmt.Printf("Bootstrapping history for tool %q from Rekor, starting at identity %s\n", toolID, claimed)
	fmt.Println("  Trust-on-first-use: this proves the history Rekor holds for that identity. It does")
	fmt.Println("  NOT prove the identity is the tool's rightful publisher — that has to come from")
	fmt.Println("  you, out of band. Read-only; nothing is signed or submitted.")

	dir, err := st.BundleDir(toolID)
	if err != nil {
		return err
	}

	res, err := bootstrap.Discover(ctx, bootstrap.Options{
		ToolID:     toolID,
		Identity:   claimed,
		MaxEntries: maxEntries,
		Rekor:      rekorapi.New(),
		Verifier:   bootstrap.CosignVerifier{},
		BundleDir:  dir,
		Progress:   os.Stdout,
	})
	if err != nil {
		return explainDiscoveryFailure(err)
	}

	for _, rec := range res.Records {
		if st.HasLogIndex(toolID, rec.RekorLogIndex) {
			continue
		}
		st.AppendLog(rec)
	}
	if err := st.Save(); err != nil {
		return fmt.Errorf("saving local state: %w", err)
	}

	fmt.Printf("  Scanned %d Rekor entr%s across %d identit%s; kept %d schema revision(s) and %d identity rotation(s)\n",
		res.Scanned, plural(res.Scanned), len(res.Identities), plural(len(res.Identities)), res.Manifests, res.Rotations)
	if res.FailedVerification > 0 {
		fmt.Printf("  %d entr%s looked like Anchor attestation(s) but failed cryptographic verification and were discarded\n",
			res.FailedVerification, plural(res.FailedVerification))
	}
	if res.NoPayload > 0 {
		fmt.Printf("  %d entr%s returned by Rekor without their DSSE payload, so their predicate could not be read\n",
			res.NoPayload, plural(res.NoPayload))
	}
	return nil
}

// explainDiscoveryFailure turns the two failures a user can act on into
// advice, rather than leaving them to read a wrapped error.
func explainDiscoveryFailure(err error) error {
	var capErr *bootstrap.CapExceededError
	if errors.As(err, &capErr) {
		return fmt.Errorf("%w.\nPass --max-bootstrap-entries %d (or higher) to scan all of them. "+
			"Anchor will not report on a partial scan: a history missing revisions can look perfectly linear",
			capErr, capErr.Count)
	}
	var noPayload *bootstrap.NoPayloadError
	if errors.As(err, &noPayload) {
		return fmt.Errorf("%w.\nThis is a limitation of the public Rekor instance, not of the identity you named — "+
			"see \"Known limitations\" in the README", noPayload)
	}
	return err
}

// plural is the "entry"/"entries", "identity"/"identities" suffix.
func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}
