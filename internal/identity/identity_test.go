package identity

import "testing"

func TestEqual(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"24uec247@lnmiit.ac.in", "24UEC247@lnmiit.ac.in", true}, // the case mismatch this package exists to fix
		{"alice@example.com", "bob@example.com", false},
		{"https://github.com/org/repo/.github/workflows/build.yml@refs/heads/main",
			"https://github.com/org/repo/.github/workflows/build.yml@refs/heads/MAIN", false}, // URIs stay case-sensitive
		{"", "", true},
		{"alice@example.com", "", false},
	}
	for _, c := range cases {
		if got := Equal(c.a, c.b); got != c.want {
			t.Errorf("Equal(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}
