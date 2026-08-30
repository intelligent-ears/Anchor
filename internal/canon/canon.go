// Package canon canonicalizes JSON documents per RFC 8785 (JCS) and hashes
// the result. Canonicalization exists so that cosmetic differences —
// re-ordered keys, extra whitespace, a trailing newline — never register as
// a schema change. Only a semantic difference in the JSON value changes the
// hash.
package canon

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/gowebpki/jcs"
)

// Canonicalize parses raw JSON bytes and re-serializes them in JCS
// canonical form (RFC 8785: sorted object keys, minimal whitespace,
// ECMAScript-style number formatting).
func Canonicalize(raw []byte) ([]byte, error) {
	// Reject malformed JSON early with a clearer error than jcs would give.
	if !json.Valid(raw) {
		return nil, fmt.Errorf("input is not valid JSON")
	}
	out, err := jcs.Transform(raw)
	if err != nil {
		return nil, fmt.Errorf("JCS canonicalization failed: %w", err)
	}
	return out, nil
}

// Hash returns the "sha256:<hex>" digest of already-canonicalized bytes.
// The "sha256:" prefix matches in-toto's ResourceDescriptor.digest
// convention so hashes read the same in the predicate as they do here.
func Hash(canonical []byte) string {
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// CanonicalizeAndHash is the common case: read raw schema bytes, produce
// canonical bytes and their digest in one step.
func CanonicalizeAndHash(raw []byte) (canonical []byte, digest string, err error) {
	canonical, err = Canonicalize(raw)
	if err != nil {
		return nil, "", err
	}
	return canonical, Hash(canonical), nil
}
