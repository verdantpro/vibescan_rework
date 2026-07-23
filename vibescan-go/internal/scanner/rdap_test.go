package scanner

import "testing"

func TestParseRDAPOwner(t *testing.T) {
	raw := []byte(`{
		"name": "GOGL",
		"remarks": [{"description": ["Google LLC"]}],
		"entities": []
	}`)
	got := parseRDAPOwner(raw)
	if got != "GOGL - Google LLC" {
		t.Fatalf("got %q", got)
	}
}

func TestParseRDAPOwnerEntity(t *testing.T) {
	// Minimal jCard with org.
	raw := []byte(`{
		"name": "NET-1",
		"entities": [{
			"roles": ["registrant"],
			"vcardArray": ["vcard", [
				["version", {}, "text", "4.0"],
				["fn", {}, "text", "Example Person"],
				["org", {}, "text", "Example Org Inc"]
			]]
		}]
	}`)
	got := parseRDAPOwner(raw)
	if got != "NET-1 - Example Org Inc" {
		t.Fatalf("got %q", got)
	}
}

func TestParseRDAPOwnerEmpty(t *testing.T) {
	if parseRDAPOwner([]byte(`{}`)) != "" {
		t.Fatal("expected empty")
	}
	if parseRDAPOwner([]byte(`not json`)) != "" {
		t.Fatal("expected empty for bad json")
	}
}

func TestNet24Key(t *testing.T) {
	if got := net24Key("8.8.8.8"); got != "8.8.8.0/24" {
		t.Fatalf("got %q", got)
	}
}
