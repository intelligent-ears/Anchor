package state

import (
	"path/filepath"
	"testing"
)

func manifest(logIndex int64, timestamp, hash string) LogRecord {
	return LogRecord{
		Kind: KindSchemaManifest, ToolID: "send_email",
		RekorLogIndex: logIndex, Timestamp: timestamp, SchemaHash: hash,
	}
}

// newStore opens a store in a temp dir, so nothing here touches the
// repository's own .anchor state.
func newStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), ".anchor"))
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// A record's Timestamp is the publisher's own claim and can say anything —
// a wrong clock, a deliberate lie, or just two signs inside the same
// second. Rekor's log index is the one ordering everyone agrees on, and
// internal/history checks linearity in that order, so the store has to
// hand records back in it.
func TestRecordsAreOrderedByLogIndexNotTimestamp(t *testing.T) {
	st := newStore(t)
	st.AppendLog(manifest(300, "2020-01-01T00:00:00Z", "sha256:ccc")) // claims to be oldest
	st.AppendLog(manifest(100, "2030-01-01T00:00:00Z", "sha256:aaa")) // claims to be newest
	st.AppendLog(manifest(200, "2025-01-01T00:00:00Z", "sha256:bbb"))

	got := st.SchemaManifests("send_email")
	want := []string{"sha256:aaa", "sha256:bbb", "sha256:ccc"}
	if len(got) != len(want) {
		t.Fatalf("got %d records, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].SchemaHash != want[i] {
			t.Fatalf("order = %v, want %v", hashes(got), want)
		}
	}

	latest, ok := st.LatestSchemaManifest("send_email")
	if !ok {
		t.Fatal("no latest manifest")
	}
	if latest.SchemaHash != "sha256:ccc" {
		t.Errorf("latest = %s (index %d), want sha256:ccc — the last one logged, whatever its timestamp claims",
			latest.SchemaHash, latest.RekorLogIndex)
	}
}

func TestRotationsAreOrderedByLogIndex(t *testing.T) {
	st := newStore(t)
	st.AppendLog(LogRecord{Kind: KindIdentityRotation, ToolID: "send_email", RekorLogIndex: 50,
		Timestamp: "2030-01-01T00:00:00Z", OldIdentity: "b@x", NewIdentity: "c@x"})
	st.AppendLog(LogRecord{Kind: KindIdentityRotation, ToolID: "send_email", RekorLogIndex: 20,
		Timestamp: "2031-01-01T00:00:00Z", OldIdentity: "a@x", NewIdentity: "b@x"})

	got := st.Rotations("send_email")
	if len(got) != 2 || got[0].OldIdentity != "a@x" || got[1].OldIdentity != "b@x" {
		t.Errorf("rotations out of log order: %+v", got)
	}
	// And they must not leak into the schema chain.
	if n := len(st.SchemaManifests("send_email")); n != 0 {
		t.Errorf("rotations counted as %d schema manifest(s)", n)
	}
}

func TestFindByHashPrefersTheMostRecentlyLogged(t *testing.T) {
	st := newStore(t)
	st.AppendLog(manifest(100, "2026-01-01T00:00:00Z", "sha256:aaa"))
	st.AppendLog(manifest(200, "2026-01-02T00:00:00Z", "sha256:bbb"))
	st.AppendLog(manifest(300, "2026-01-03T00:00:00Z", "sha256:aaa")) // a rollback to earlier content

	rec, ok := st.FindByHash("send_email", "sha256:aaa")
	if !ok {
		t.Fatal("hash not found")
	}
	if rec.RekorLogIndex != 300 {
		t.Errorf("found Rekor index %d, want 300 (the latest attestation of that content)", rec.RekorLogIndex)
	}
}

func TestHasRotationBridgeIsCaseInsensitiveForEmails(t *testing.T) {
	st := newStore(t)
	st.AppendLog(LogRecord{Kind: KindIdentityRotation, ToolID: "send_email", RekorLogIndex: 10,
		OldIdentity: "24UEC247@lnmiit.ac.in", NewIdentity: "new@gmail.com"})

	if _, ok := st.HasRotationBridge("send_email", "24uec247@lnmiit.ac.in", "NEW@gmail.com"); !ok {
		t.Error("a case difference broke the rotation bridge")
	}
	if _, ok := st.HasRotationBridge("send_email", "someone@else.com", "new@gmail.com"); ok {
		t.Error("bridged a rotation that was never attested")
	}
}

func TestSaveAndReopenRoundTrips(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".anchor")
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	st.AppendLog(manifest(100, "2026-01-01T00:00:00Z", "sha256:aaa"))
	st.KnownGood["send_email"] = LastKnownGood{ToolID: "send_email", SchemaHash: "sha256:aaa", PublisherIdentity: "p@x"}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := reopened.LatestSchemaManifest("send_email"); !ok || got.SchemaHash != "sha256:aaa" {
		t.Errorf("log did not survive a round trip: %+v", got)
	}
	if reopened.KnownGood["send_email"].PublisherIdentity != "p@x" {
		t.Errorf("known-good did not survive a round trip: %+v", reopened.KnownGood)
	}
	if !reopened.HasLogIndex("send_email", 100) {
		t.Error("HasLogIndex does not see the restored record")
	}
}

func hashes(recs []LogRecord) []string {
	out := make([]string, 0, len(recs))
	for _, r := range recs {
		out = append(out, r.SchemaHash)
	}
	return out
}
