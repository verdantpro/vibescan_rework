package scanner

import (
	"net/netip"
	"testing"
)

const nmapFixture = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="8.8.8.8" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18.0" extrainfo="Ubuntu"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
  <host>
    <address addr="1.1.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="cloudflare"/>
      </port>
    </ports>
  </host>
</nmaprun>`

func TestParseNmapXML(t *testing.T) {
	got, err := ParseNmapXML([]byte(nmapFixture))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 hosts, got %d", len(got))
	}
	if b := got["8.8.8.8"][80]; b != "product: nginx version: 1.18.0 extrainfo: Ubuntu" {
		t.Errorf("8.8.8.8:80 banner = %q", b)
	}
	if _, ok := got["8.8.8.8"][22]; ok {
		t.Error("closed port 22 should be excluded")
	}
	if b := got["1.1.1.1"][443]; b != "product: cloudflare" {
		t.Errorf("1.1.1.1:443 banner = %q", b)
	}
}

func TestBlacklistContainsAndRandom(t *testing.T) {
	bl := NewBlacklist([]string{"10.0.0.0/8", "8.8.8.0/24"})
	if !bl.Contains(netip.MustParseAddr("8.8.8.8")) {
		t.Error("8.8.8.8 should be blocked by 8.8.8.0/24")
	}
	if bl.Contains(netip.MustParseAddr("9.9.9.9")) {
		t.Error("9.9.9.9 should not be blocked")
	}

	// Generated IPs must avoid the blacklist and the reserved first octets.
	for i := 0; i < 2000; i++ {
		ip := bl.RandomIP()
		addr := netip.MustParseAddr(ip)
		if bl.Contains(addr) {
			t.Fatalf("generated blacklisted IP: %s", ip)
		}
		a := addr.As4()[0]
		if a == 0 || a == 127 {
			t.Fatalf("first octet must not be 0/127: %s", ip)
		}
	}
}

func TestRandomBatchDistinct(t *testing.T) {
	bl := NewBlacklist(nil)
	batch := bl.RandomBatch(50)
	if len(batch) != 50 {
		t.Fatalf("want 50, got %d", len(batch))
	}
	seen := map[string]bool{}
	for _, ip := range batch {
		if seen[ip] {
			t.Fatalf("duplicate IP: %s", ip)
		}
		seen[ip] = true
	}
}
