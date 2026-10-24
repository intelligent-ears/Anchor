package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"anchor/internal/history"
	"anchor/internal/rekorapi"
)

func loadScenarios(t *testing.T) []scenario {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("testdata", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no fixtures found in testdata")
	}
	out := make([]scenario, 0, len(paths))
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var sc scenario
		if err := json.Unmarshal(b, &sc); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if sc.Name == "" {
			sc.Name = filepath.Base(p)
		}
		out = append(out, sc)
	}
	return out
}

func TestDiscoverFixtures(t *testing.T) {
	for _, sc := range loadScenarios(t) {
		t.Run(sc.Name, func(t *testing.T) {
			fake, stub := buildFake(t, sc)
			bundleDir := t.TempDir()
			res, err := Discover(context.Background(), Options{
				ToolID:     sc.ToolID,
				Identity:   sc.BootstrapIdentity,
				MaxEntries: sc.MaxEntries,
				Rekor:      fake,
				Verifier:   stub,
				BundleDir:  bundleDir,
			})

			if sc.Want.ErrorKind != "" || sc.Want.Error != "" {
				if err == nil {
					t.Fatalf("expected an error, got a result: %s", renderResult(res))
				}
				if sc.Want.Error != "" && !strings.Contains(err.Error(), sc.Want.Error) {
					t.Errorf("error %q does not contain %q", err, sc.Want.Error)
				}
				switch sc.Want.ErrorKind {
				case "cap":
					var capErr *CapExceededError
					if !errors.As(err, &capErr) {
						t.Errorf("error is %T, want *CapExceededError", err)
					}
				case "no-payload":
					var npErr *NoPayloadError
					if !errors.As(err, &npErr) {
						t.Errorf("error is %T, want *NoPayloadError", err)
					}
				case "":
				default:
					t.Fatalf("fixture asks for unknown errorKind %q", sc.Want.ErrorKind)
				}
				return
			}
			if err != nil {
				t.Fatalf("Discover: %v", err)
			}

			if res.Manifests != sc.Want.Manifests {
				t.Errorf("manifests = %d, want %d", res.Manifests, sc.Want.Manifests)
			}
			if res.Rotations != sc.Want.Rotations {
				t.Errorf("rotations = %d, want %d", res.Rotations, sc.Want.Rotations)
			}
			if res.NotAnchor != sc.Want.NotAnchor {
				t.Errorf("notAnchor = %d, want %d", res.NotAnchor, sc.Want.NotAnchor)
			}
			if res.FailedVerification != sc.Want.FailedVerification {
				t.Errorf("failedVerification = %d, want %d", res.FailedVerification, sc.Want.FailedVerification)
			}
			if res.NoPayload != sc.Want.NoPayload {
				t.Errorf("noPayload = %d, want %d", res.NoPayload, sc.Want.NoPayload)
			}
			if got, want := strings.Join(res.Identities, ","), strings.Join(sc.Want.Identities, ","); got != want {
				t.Errorf("identities = %q, want %q", got, want)
			}
			if len(res.Records) != len(res.Attestations) {
				t.Errorf("%d records but %d attestations", len(res.Records), len(res.Attestations))
			}

			// Part 1's checks, run on a history rebuilt entirely from the
			// log with no local state file involved.
			lineage := history.NewLineage(sc.BootstrapIdentity, res.Attestations)
			rep := history.Check(res.Attestations, lineage)
			if got := problemKinds(rep); !equalStrings(got, sc.Want.Problems) {
				t.Errorf("problems = %v, want %v", got, sc.Want.Problems)
			}
			if got := chainHashes(rep); !equalStrings(got, sc.Want.Chain) {
				t.Errorf("chain = %v, want %v", got, sc.Want.Chain)
			}

			// Every kept record must point at a bundle that still
			// exists, and every dropped entry's bundle must have been
			// cleaned up rather than left behind for a later run to
			// mistake for something verified.
			for _, r := range res.Records {
				if _, err := os.Stat(r.BundlePath); err != nil {
					t.Errorf("record for Rekor index %d points at a missing bundle: %v", r.RekorLogIndex, err)
				}
			}
			left, err := os.ReadDir(bundleDir)
			if err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			if len(left) != len(res.Records) {
				t.Errorf("bundle dir holds %d file(s) for %d kept record(s) — a dropped entry's bundle was left behind", len(left), len(res.Records))
			}
		})
	}
}

// TestDiscoverRefusesWithoutItsDependencies guards the preconditions: no
// code path may end up verifying nothing, or writing bundles nowhere.
func TestDiscoverRefusesWithoutItsDependencies(t *testing.T) {
	full := Options{
		ToolID: "t", Identity: "p@example.com",
		Rekor: rekorapi.NewFake(), Verifier: &stubVerifier{}, BundleDir: t.TempDir(),
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Options)
	}{
		{"no tool id", func(o *Options) { o.ToolID = "" }},
		{"no identity", func(o *Options) { o.Identity = "" }},
		{"no rekor client", func(o *Options) { o.Rekor = nil }},
		{"no verifier", func(o *Options) { o.Verifier = nil }},
		{"no bundle dir", func(o *Options) { o.BundleDir = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := full
			tc.mutate(&opts)
			if _, err := Discover(context.Background(), opts); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

func TestDiscoverPropagatesSearchFailure(t *testing.T) {
	// A rate-limited or unavailable Rekor must fail the bootstrap, never
	// present as "this identity published nothing".
	fake := rekorapi.NewFake()
	fake.SearchErr = fmt.Errorf("Rekor returned 429 Too Many Requests")
	_, err := Discover(context.Background(), Options{
		ToolID: "send_email", Identity: "pub@example.com",
		Rekor: fake, Verifier: &stubVerifier{}, BundleDir: t.TempDir(),
	})
	if err == nil {
		t.Fatal("expected the search failure to propagate")
	}
	if !strings.Contains(err.Error(), "429") {
		t.Errorf("error lost the cause: %v", err)
	}
}

func TestDiscoverSearchesLowercasedVariant(t *testing.T) {
	// Fulcio records the identity as the OIDC provider normalized it,
	// which need not be the case the user typed.
	sc := scenario{
		ToolID:            "send_email",
		BootstrapIdentity: "Pub@Example.com",
		Entries: []entrySpec{
			{LogIndex: 1, Signer: "pub@example.com", IndexedUnder: "pub@example.com",
				Kind: "schema-manifest", SchemaHash: "sha256:a001", SchemaVersion: "1.0.0"},
		},
	}
	fake, stub := buildFake(t, sc)
	res, err := Discover(context.Background(), Options{
		ToolID: sc.ToolID, Identity: sc.BootstrapIdentity,
		Rekor: fake, Verifier: stub, BundleDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Manifests != 1 {
		t.Errorf("manifests = %d, want 1; searches were %v", res.Manifests, fake.Searches)
	}
}

func TestDefaultMaxEntriesApplies(t *testing.T) {
	// A zero cap must mean the default, never "unlimited".
	fake := rekorapi.NewFake()
	for i := range DefaultMaxEntries + 1 {
		fake.Add("pub@example.com", rekorapi.Entry{UUID: fmt.Sprintf("%064x", i), LogIndex: int64(i)})
	}
	_, err := Discover(context.Background(), Options{
		ToolID: "send_email", Identity: "pub@example.com",
		Rekor: fake, Verifier: &stubVerifier{}, BundleDir: t.TempDir(),
	})
	var capErr *CapExceededError
	if !errors.As(err, &capErr) {
		t.Fatalf("error is %T (%v), want *CapExceededError", err, err)
	}
	if capErr.Cap != DefaultMaxEntries {
		t.Errorf("cap = %d, want %d", capErr.Cap, DefaultMaxEntries)
	}
}

// helpers

func problemKinds(r history.Report) []string {
	out := make([]string, 0, len(r.Problems))
	for _, p := range r.Problems {
		out = append(out, string(p.Kind))
	}
	return out
}

func chainHashes(r history.Report) []string {
	out := make([]string, 0, len(r.Chain))
	for _, a := range r.Chain {
		out = append(out, a.SchemaHash)
	}
	return out
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func renderResult(r *Result) string {
	b, _ := json.MarshalIndent(r, "", "  ")
	return string(b)
}
