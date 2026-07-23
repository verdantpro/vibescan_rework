package store

import "testing"

func TestIsIPLike(t *testing.T) {
	cases := map[string]bool{
		"1.2.3.4":  true,
		"192.168":  true,
		"10.":      true,
		"8.8":      true,
		"nginx":    false,
		"200":      false, // pure digits, no dot → text search, not IP prefix
		"":         false,
		"1.2.3.a":  false,
		"host.com": false,
		"1 .2":     false,
	}
	for in, want := range cases {
		if got := isIPLike(in); got != want {
			t.Errorf("isIPLike(%q) = %v, want %v", in, got, want)
		}
	}
}
