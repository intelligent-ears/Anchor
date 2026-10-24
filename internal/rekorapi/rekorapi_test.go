package rekorapi

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// stubDoer replays canned responses in order and records what it was
// asked for.
type stubDoer struct {
	responses []*http.Response
	errs      []error
	calls     int
	bodies    []string
}

func (d *stubDoer) Do(req *http.Request) (*http.Response, error) {
	i := d.calls
	d.calls++
	if req.Body != nil {
		b, _ := io.ReadAll(req.Body)
		d.bodies = append(d.bodies, string(b))
	} else {
		d.bodies = append(d.bodies, "")
	}
	if i < len(d.errs) && d.errs[i] != nil {
		return nil, d.errs[i]
	}
	if i >= len(d.responses) {
		return nil, fmt.Errorf("stub: unexpected call %d", i+1)
	}
	return d.responses[i], nil
}

func resp(code int, body string, header http.Header) *http.Response {
	if header == nil {
		header = http.Header{}
	}
	return &http.Response{
		StatusCode: code,
		Status:     fmt.Sprintf("%d %s", code, http.StatusText(code)),
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     header,
	}
}

// testClient is an HTTPClient whose waits are recorded instead of slept.
func testClient(d Doer) (*HTTPClient, *[]time.Duration) {
	var slept []time.Duration
	c := New()
	c.BaseURL = "https://rekor.test"
	c.HTTP = d
	c.BaseBackoff = time.Second
	c.MaxBackoff = 4 * time.Second
	c.sleep = func(dur time.Duration) { slept = append(slept, dur) }
	return c, &slept
}

const oneEntry = `{"uuid-1":{"logIndex":42,"body":"","logID":"ab"}}`

func TestRetriesRateLimitAndHonorsRetryAfter(t *testing.T) {
	// A 429 is "ask again", not "no such entry". Getting this wrong would
	// turn Rekor being busy into Anchor reporting that a publisher never
	// signed anything.
	d := &stubDoer{responses: []*http.Response{
		resp(http.StatusTooManyRequests, "slow down", http.Header{"Retry-After": []string{"2"}}),
		resp(http.StatusOK, oneEntry, nil),
	}}
	c, slept := testClient(d)

	e, err := c.GetByLogIndex(context.Background(), 42)
	if err != nil {
		t.Fatalf("GetByLogIndex: %v", err)
	}
	if e.LogIndex != 42 || e.UUID != "uuid-1" {
		t.Errorf("entry = %+v", e)
	}
	if d.calls != 2 {
		t.Errorf("made %d request(s), want 2", d.calls)
	}
	if len(*slept) != 1 || (*slept)[0] != 2*time.Second {
		t.Errorf("waits = %v, want one 2s wait from Retry-After", *slept)
	}
}

func TestRetriesServerErrorsWithExponentialBackoff(t *testing.T) {
	d := &stubDoer{responses: []*http.Response{
		resp(http.StatusServiceUnavailable, "", nil),
		resp(http.StatusBadGateway, "", nil),
		resp(http.StatusOK, oneEntry, nil),
	}}
	c, slept := testClient(d)

	if _, err := c.GetByUUID(context.Background(), "uuid-1"); err != nil {
		t.Fatalf("GetByUUID: %v", err)
	}
	want := []time.Duration{time.Second, 2 * time.Second}
	if len(*slept) != len(want) {
		t.Fatalf("waits = %v, want %v", *slept, want)
	}
	for i := range want {
		if (*slept)[i] != want[i] {
			t.Fatalf("waits = %v, want %v", *slept, want)
		}
	}
}

func TestBackoffIsCapped(t *testing.T) {
	var responses []*http.Response
	for range 5 {
		responses = append(responses, resp(http.StatusServiceUnavailable, "", nil))
	}
	d := &stubDoer{responses: responses}
	c, slept := testClient(d) // MaxAttempts 5, base 1s, cap 4s

	if _, err := c.GetByUUID(context.Background(), "uuid-1"); err == nil {
		t.Fatal("expected failure after exhausting attempts")
	}
	for _, s := range *slept {
		if s > 4*time.Second {
			t.Errorf("waited %v, above the 4s cap: %v", s, *slept)
		}
	}
	if len(*slept) != 4 {
		t.Errorf("waited %d time(s) for 5 attempts, want 4", len(*slept))
	}
}

func TestDoesNotRetryDefinitiveFailures(t *testing.T) {
	// 404 means the entry genuinely isn't there. Retrying would just make
	// a clear answer slow.
	d := &stubDoer{responses: []*http.Response{resp(http.StatusNotFound, "not found", nil)}}
	c, slept := testClient(d)

	_, err := c.GetByUUID(context.Background(), "nope")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error does not report the status: %v", err)
	}
	if d.calls != 1 {
		t.Errorf("made %d request(s), want 1", d.calls)
	}
	if len(*slept) != 0 {
		t.Errorf("waited %v before giving up on a 404", *slept)
	}
}

func TestRetriesRebuildTheRequestBody(t *testing.T) {
	// A POST body can only be read once, so a retry has to rebuild the
	// request. If it didn't, the second attempt would silently ask Rekor
	// for nothing.
	d := &stubDoer{responses: []*http.Response{
		resp(http.StatusTooManyRequests, "", nil),
		resp(http.StatusOK, `["uuid-a","uuid-b"]`, nil),
	}}
	c, _ := testClient(d)

	uuids, err := c.SearchByEmail(context.Background(), "pub@example.com")
	if err != nil {
		t.Fatalf("SearchByEmail: %v", err)
	}
	if len(uuids) != 2 {
		t.Errorf("uuids = %v", uuids)
	}
	if len(d.bodies) != 2 {
		t.Fatalf("recorded %d bodies", len(d.bodies))
	}
	for i, b := range d.bodies {
		if !strings.Contains(b, "pub@example.com") {
			t.Errorf("attempt %d sent body %q, which lost the query", i+1, b)
		}
	}
}

func TestGetEntriesBatchesWithinRekorsLimit(t *testing.T) {
	// Rekor caps entryUUIDs per retrieve request; exceeding it is how a
	// bootstrap of a busy identity would fail halfway through.
	var uuids []string
	for i := range 23 {
		uuids = append(uuids, fmt.Sprintf("uuid-%02d", i))
	}
	var responses []*http.Response
	for range 3 {
		responses = append(responses, resp(http.StatusOK, `[{"uuid-x":{"logIndex":1}}]`, nil))
	}
	d := &stubDoer{responses: responses}
	c, _ := testClient(d)

	entries, err := c.GetEntries(context.Background(), uuids)
	if err != nil {
		t.Fatalf("GetEntries: %v", err)
	}
	if d.calls != 3 {
		t.Errorf("made %d request(s) for 23 uuids, want 3 batches of at most %d", d.calls, maxRetrieveBatch)
	}
	if len(entries) != 3 {
		t.Errorf("got %d entries", len(entries))
	}
	// Every UUID must appear in exactly one batch — none dropped, none
	// asked for twice.
	seen := map[string]int{}
	for _, b := range d.bodies {
		for _, u := range uuids {
			if strings.Contains(b, `"`+u+`"`) {
				seen[u]++
			}
		}
	}
	for _, u := range uuids {
		if seen[u] != 1 {
			t.Errorf("uuid %s appeared in %d batches, want 1", u, seen[u])
		}
	}
}

func TestGetEntriesReportsWhichBatchFailed(t *testing.T) {
	var uuids []string
	for i := range 15 {
		uuids = append(uuids, fmt.Sprintf("uuid-%02d", i))
	}
	d := &stubDoer{responses: []*http.Response{
		resp(http.StatusOK, `[{"uuid-x":{"logIndex":1}}]`, nil),
		resp(http.StatusNotFound, "gone", nil),
	}}
	c, _ := testClient(d)

	_, err := c.GetEntries(context.Background(), uuids)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "of 15") {
		t.Errorf("error does not say how far the scan got: %v", err)
	}
}

func TestRetryAfterParsing(t *testing.T) {
	for _, tc := range []struct {
		header string
		want   time.Duration
		ok     bool
	}{
		{"", 0, false},
		{"5", 5 * time.Second, true},
		{"0", 0, true},
		{"-3", 0, false},
		{"not-a-number", 0, false},
		{"Mon, 02 Jan 2006 15:04:05 GMT", 0, true}, // a date in the past means "now"
	} {
		h := http.Header{}
		if tc.header != "" {
			h.Set("Retry-After", tc.header)
		}
		got, ok := retryAfter(h)
		if ok != tc.ok || got != tc.want {
			t.Errorf("retryAfter(%q) = (%v, %v), want (%v, %v)", tc.header, got, ok, tc.want, tc.ok)
		}
	}
}

func TestContextCancellationStopsRetrying(t *testing.T) {
	d := &stubDoer{responses: []*http.Response{
		resp(http.StatusTooManyRequests, "", nil),
		resp(http.StatusOK, oneEntry, nil),
	}}
	c := New()
	c.BaseURL = "https://rekor.test"
	c.HTTP = d
	c.BaseBackoff = time.Hour // long enough that only cancellation ends the wait
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := c.GetByUUID(ctx, "uuid-1"); err == nil {
		t.Fatal("expected the cancelled context to abort the retry wait")
	}
}
