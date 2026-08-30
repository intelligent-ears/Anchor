// Package diff produces a human-readable summary of what changed between
// two JSON schema revisions. It exists purely for human review — Anchor's
// trust decision (OK/BLOCKED/FLAGGED) never depends on the diff's content,
// only on hashes and signatures. Showing the diff just means a routine,
// correctly-attested update doesn't get auto-approved silently.
package diff

import (
	"encoding/json"
	"fmt"
	"sort"
)

type Kind string

const (
	Added   Kind = "added"
	Removed Kind = "removed"
	Changed Kind = "changed"
)

type Change struct {
	Path string
	Kind Kind
	Old  string
	New  string
}

// Compute flattens both documents to dotted-path -> scalar-string maps and
// diffs them key by key. This reads better than a line-based text diff for
// JSON, where key reordering is common and semantically meaningless.
func Compute(oldRaw, newRaw []byte) ([]Change, error) {
	var oldVal, newVal any
	if err := json.Unmarshal(oldRaw, &oldVal); err != nil {
		return nil, fmt.Errorf("parse old schema: %w", err)
	}
	if err := json.Unmarshal(newRaw, &newVal); err != nil {
		return nil, fmt.Errorf("parse new schema: %w", err)
	}

	oldFlat := map[string]string{}
	newFlat := map[string]string{}
	flatten("", oldVal, oldFlat)
	flatten("", newVal, newFlat)

	paths := map[string]bool{}
	for p := range oldFlat {
		paths[p] = true
	}
	for p := range newFlat {
		paths[p] = true
	}
	sorted := make([]string, 0, len(paths))
	for p := range paths {
		sorted = append(sorted, p)
	}
	sort.Strings(sorted)

	var changes []Change
	for _, p := range sorted {
		o, oOK := oldFlat[p]
		n, nOK := newFlat[p]
		switch {
		case oOK && !nOK:
			changes = append(changes, Change{Path: p, Kind: Removed, Old: o})
		case !oOK && nOK:
			changes = append(changes, Change{Path: p, Kind: Added, New: n})
		case oOK && nOK && o != n:
			changes = append(changes, Change{Path: p, Kind: Changed, Old: o, New: n})
		}
	}
	return changes, nil
}

// flatten walks a decoded JSON value, recording one entry per leaf (scalar
// or empty container) at its dotted path.
func flatten(prefix string, v any, out map[string]string) {
	switch t := v.(type) {
	case map[string]any:
		if len(t) == 0 {
			out[prefix] = "{}"
			return
		}
		for k, val := range t {
			flatten(joinPath(prefix, k), val, out)
		}
	case []any:
		if len(t) == 0 {
			out[prefix] = "[]"
			return
		}
		for i, val := range t {
			flatten(fmt.Sprintf("%s[%d]", prefix, i), val, out)
		}
	case string:
		out[prefix] = fmt.Sprintf("%q", t)
	case nil:
		out[prefix] = "null"
	default:
		b, _ := json.Marshal(t)
		out[prefix] = string(b)
	}
}

func joinPath(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}

// Render formats changes for terminal output. Returns "" (no output line
// expected) if there are no changes.
func Render(changes []Change) string {
	if len(changes) == 0 {
		return "  (no field-level differences)"
	}
	out := ""
	for _, c := range changes {
		switch c.Kind {
		case Added:
			out += fmt.Sprintf("  + %s: %s\n", c.Path, c.New)
		case Removed:
			out += fmt.Sprintf("  - %s: %s\n", c.Path, c.Old)
		case Changed:
			out += fmt.Sprintf("  ~ %s: %s -> %s\n", c.Path, c.Old, c.New)
		}
	}
	return out
}
