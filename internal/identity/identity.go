// Package identity compares the identity strings embedded in Fulcio
// certificates (and typed by users on the command line) the way Sigstore's
// own ecosystem treats them in practice.
package identity

import "strings"

// Equal reports whether two identity strings refer to the same signer.
//
// Discovered empirically: Google's OIDC issuer returns an institutional
// Gmail-backed address in whatever case it normalizes to internally (e.g.
// "24UEC247@lnmiit.ac.in"), which need not match the case a human types on
// the command line. Email local-parts are technically case-sensitive per
// RFC 5321, but no mainstream provider enforces that in practice, so
// treating email-shaped identities as case-insensitive avoids exactly the
// false "identity changed" flag a harmless case difference would otherwise
// trigger.
//
// URI-shaped identities (e.g. a GitHub Actions workload identity encoding
// a repo path and ref) are compared case-sensitively, since case is
// meaningful there.
func Equal(a, b string) bool {
	if looksLikeEmail(a) && looksLikeEmail(b) {
		return strings.EqualFold(a, b)
	}
	return a == b
}

func looksLikeEmail(s string) bool {
	return strings.Contains(s, "@") && !strings.Contains(s, "://")
}
