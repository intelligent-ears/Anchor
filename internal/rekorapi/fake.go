package rekorapi

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// Fake is an in-memory Client for tests. It exists so Anchor's history
// reconstruction and fork detection can be exercised without talking to
// the public log — and, more importantly, without ever creating new Rekor
// entries, which are permanent and public.
//
// It lives in the non-test file on purpose: the bootstrap and CLI tests
// are in other packages and need it too.
type Fake struct {
	// Entries is every entry the fake log holds, keyed by UUID.
	Entries map[string]Entry
	// ByEmail maps a signer identity to the UUIDs Rekor's index would
	// return for it. Lookup is case-insensitive, matching how the public
	// index behaves for email identities.
	ByEmail map[string][]string

	// SearchErr and GetErr, when set, are returned instead of results —
	// for testing the rate-limited/unavailable paths.
	SearchErr error
	GetErr    error

	// Searches and Fetches record what was asked for, so a test can assert
	// on batching and on not re-fetching.
	Searches []string
	Fetches  [][]string
}

var _ Client = (*Fake)(nil)

// NewFake builds a fake log from entries, indexing each one under the
// signer identity given for it.
func NewFake() *Fake {
	return &Fake{Entries: map[string]Entry{}, ByEmail: map[string][]string{}}
}

// Add files an entry in the fake log and indexes it under signerIdentity.
func (f *Fake) Add(signerIdentity string, e Entry) {
	if f.Entries == nil {
		f.Entries = map[string]Entry{}
	}
	if f.ByEmail == nil {
		f.ByEmail = map[string][]string{}
	}
	f.Entries[e.UUID] = e
	k := strings.ToLower(signerIdentity)
	f.ByEmail[k] = append(f.ByEmail[k], e.UUID)
}

func (f *Fake) SearchByEmail(_ context.Context, email string) ([]string, error) {
	f.Searches = append(f.Searches, email)
	if f.SearchErr != nil {
		return nil, f.SearchErr
	}
	uuids := append([]string(nil), f.ByEmail[strings.ToLower(email)]...)
	sort.Strings(uuids)
	return uuids, nil
}

func (f *Fake) GetEntries(_ context.Context, uuids []string) ([]Entry, error) {
	f.Fetches = append(f.Fetches, append([]string(nil), uuids...))
	if f.GetErr != nil {
		return nil, f.GetErr
	}
	var out []Entry
	for _, u := range uuids {
		if e, ok := f.Entries[u]; ok {
			out = append(out, e)
		}
	}
	return out, nil
}

func (f *Fake) GetByUUID(_ context.Context, uuid string) (*Entry, error) {
	if f.GetErr != nil {
		return nil, f.GetErr
	}
	if e, ok := f.Entries[uuid]; ok {
		return &e, nil
	}
	return nil, fmt.Errorf("fake Rekor: no entry %s", uuid)
}

func (f *Fake) GetByLogIndex(_ context.Context, logIndex int64) (*Entry, error) {
	if f.GetErr != nil {
		return nil, f.GetErr
	}
	for _, e := range f.Entries {
		if e.LogIndex == logIndex {
			return &e, nil
		}
	}
	return nil, fmt.Errorf("fake Rekor: no entry at log index %d", logIndex)
}
