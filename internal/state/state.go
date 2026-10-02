// Package state manages Anchor's local, per-client persistence:
//
//   - state.json    — trust-on-first-use cache of the last known-good
//     (toolId, schemaHash, publisherIdentity) per tool. This is what a real
//     MCP client would keep between tool invocations, and it's what
//     `anchor verify` diffs the live schema against.
//   - log-index.json — an append-only local mirror of every attestation
//     Anchor has submitted to Rekor, keyed by toolId. This exists because
//     the public Rekor instance supports lookup by artifact hash or by
//     signer identity, but not by arbitrary custom fields like "toolId" —
//     so a client has to remember, locally, which log entries are its own.
//     `verify` treats this index as a set of pointers only: it re-fetches
//     and re-verifies each entry it cares about rather than trusting the
//     cached copy blindly (see internal/signer).
package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"

	"anchor/internal/identity"
)

// LastKnownGood is what a client persists between tool invocations.
type LastKnownGood struct {
	ToolID            string `json:"toolId"`
	SchemaHash        string `json:"schemaHash"`
	PublisherIdentity string `json:"publisherIdentity"`
	SchemaVersion     string `json:"schemaVersion"`
	UpdatedAt         string `json:"updatedAt"`
}

// LogRecord is a local pointer to one attestation Anchor has submitted to
// Rekor. Kind is either "schema-manifest" or "identity-rotation"; the
// fields relevant to the other kind are left zero.
type LogRecord struct {
	Kind          string `json:"kind"`
	ToolID        string `json:"toolId"`
	RekorUUID     string `json:"rekorUuid"`
	RekorLogIndex int64  `json:"rekorLogIndex"`
	Timestamp     string `json:"timestamp"`

	// schema-manifest fields
	PublisherIdentity string `json:"publisherIdentity,omitempty"`
	OIDCIssuer        string `json:"oidcIssuer,omitempty"`
	SchemaHash        string `json:"schemaHash,omitempty"`
	SchemaVersion     string `json:"schemaVersion,omitempty"`

	// identity-rotation fields
	OldIdentity string `json:"oldIdentity,omitempty"`
	NewIdentity string `json:"newIdentity,omitempty"`

	// Local cache paths, so verify/re-verify doesn't need network access
	// to re-derive what was signed.
	BundlePath    string `json:"bundlePath"`
	CanonicalPath string `json:"canonicalPath,omitempty"`
}

const (
	KindSchemaManifest   = "schema-manifest"
	KindIdentityRotation = "identity-rotation"
)

// Store is the loaded contents of .anchor/state.json and
// .anchor/log-index.json for one client.
type Store struct {
	Dir       string
	KnownGood map[string]LastKnownGood `json:"knownGood"`
	Log       map[string][]LogRecord   `json:"log"`
}

func stateFile(dir string) string { return filepath.Join(dir, "state.json") }
func logFile(dir string) string   { return filepath.Join(dir, "log-index.json") }

// Open loads (or initializes) the state store rooted at dir (typically
// "<project>/.anchor"). It is not an error for either file to be missing —
// that's just a client that hasn't signed or verified anything yet.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dir, "bundles"), 0o755); err != nil {
		return nil, err
	}
	s := &Store{
		Dir:       dir,
		KnownGood: map[string]LastKnownGood{},
		Log:       map[string][]LogRecord{},
	}
	if err := loadJSON(stateFile(dir), &s.KnownGood); err != nil {
		return nil, err
	}
	if err := loadJSON(logFile(dir), &s.Log); err != nil {
		return nil, err
	}
	return s, nil
}

func loadJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// Save persists both state.json and log-index.json.
func (s *Store) Save() error {
	if err := saveJSON(stateFile(s.Dir), s.KnownGood); err != nil {
		return err
	}
	return saveJSON(logFile(s.Dir), s.Log)
}

func saveJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// BundleDir returns (creating if needed) the local cache directory for a
// tool's signed bundles and canonical schema snapshots.
func (s *Store) BundleDir(toolID string) (string, error) {
	dir := filepath.Join(s.Dir, "bundles", toolID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

// AppendLog records a new attestation pointer for toolID, most-recent-last
// is not assumed by callers — LatestSchemaManifest/Rotations sort explicitly.
func (s *Store) AppendLog(rec LogRecord) {
	s.Log[rec.ToolID] = append(s.Log[rec.ToolID], rec)
}

// SchemaManifests returns every schema-manifest record for toolID, sorted
// oldest first.
func (s *Store) SchemaManifests(toolID string) []LogRecord {
	return sortedByTime(filterKind(s.Log[toolID], KindSchemaManifest))
}

// Rotations returns every identity-rotation record for toolID, sorted
// oldest first.
func (s *Store) Rotations(toolID string) []LogRecord {
	return sortedByTime(filterKind(s.Log[toolID], KindIdentityRotation))
}

// LatestSchemaManifest returns the most recently signed schema-manifest
// record for toolID, if any.
func (s *Store) LatestSchemaManifest(toolID string) (LogRecord, bool) {
	recs := s.SchemaManifests(toolID)
	if len(recs) == 0 {
		return LogRecord{}, false
	}
	return recs[len(recs)-1], true
}

// FindByHash returns the most recent schema-manifest record for toolID
// whose SchemaHash matches, if any — used to check "does the live schema
// match *some* attested revision, even if not the newest."
func (s *Store) FindByHash(toolID, schemaHash string) (LogRecord, bool) {
	recs := s.SchemaManifests(toolID)
	for i := len(recs) - 1; i >= 0; i-- {
		if recs[i].SchemaHash == schemaHash {
			return recs[i], true
		}
	}
	return LogRecord{}, false
}

// SetCanonicalPath records where the canonical schema for an existing
// record has been cached.
func (s *Store) SetCanonicalPath(toolID string, logIndex int64, path string) {
	for i := range s.Log[toolID] {
		if s.Log[toolID][i].RekorLogIndex == logIndex {
			s.Log[toolID][i].CanonicalPath = path
		}
	}
}

// HasLogIndex reports whether toolID already has a record for the given
// Rekor log index, so discovery doesn't re-add entries Anchor already has.
func (s *Store) HasLogIndex(toolID string, logIndex int64) bool {
	for _, r := range s.Log[toolID] {
		if r.RekorLogIndex == logIndex {
			return true
		}
	}
	return false
}

// HasRotationBridge reports whether an identity-rotation record exists for
// toolID authorizing the handoff from -> to.
func (s *Store) HasRotationBridge(toolID, from, to string) (LogRecord, bool) {
	for _, r := range s.Rotations(toolID) {
		if identity.Equal(r.OldIdentity, from) && identity.Equal(r.NewIdentity, to) {
			return r, true
		}
	}
	return LogRecord{}, false
}

func filterKind(recs []LogRecord, kind string) []LogRecord {
	out := make([]LogRecord, 0, len(recs))
	for _, r := range recs {
		if r.Kind == kind {
			out = append(out, r)
		}
	}
	return out
}

func sortedByTime(recs []LogRecord) []LogRecord {
	sort.SliceStable(recs, func(i, j int) bool { return recs[i].Timestamp < recs[j].Timestamp })
	return recs
}
