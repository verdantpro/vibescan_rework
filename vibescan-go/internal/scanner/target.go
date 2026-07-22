// Package scanner implements the VibeScan agent: random target generation, nmap
// discovery, browser capture, and signed submission to the collector.
package scanner

import (
	"math/rand/v2"
	"net/netip"
	"sync"
)

// Blacklist holds CIDR exclusions and generates random public IPv4 targets that
// avoid them, mirroring common/nettools.py:random_ip.
type Blacklist struct {
	mu   sync.RWMutex
	nets []netip.Prefix
}

// NewBlacklist parses CIDR strings (invalid entries are skipped).
func NewBlacklist(cidrs []string) *Blacklist {
	b := &Blacklist{}
	b.Set(cidrs)
	return b
}

// Set replaces the CIDR set (used on periodic refresh from the collector).
func (b *Blacklist) Set(cidrs []string) {
	nets := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		if p, err := netip.ParsePrefix(c); err == nil {
			nets = append(nets, p.Masked())
		}
	}
	b.mu.Lock()
	b.nets = nets
	b.mu.Unlock()
}

// Contains reports whether addr falls in any excluded CIDR.
func (b *Blacklist) Contains(addr netip.Addr) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, p := range b.nets {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// RandomIP returns a random public IPv4 string not in the blacklist. The first
// octet is 1..254 excluding 127; the rest are 0..254 — matching the Python agent.
func (b *Blacklist) RandomIP() string {
	for {
		a := byte(rand.IntN(255))
		for a == 0 || a == 127 {
			a = byte(rand.IntN(254) + 1)
		}
		addr := netip.AddrFrom4([4]byte{a, byte(rand.IntN(255)), byte(rand.IntN(255)), byte(rand.IntN(255))})
		if !b.Contains(addr) {
			return addr.String()
		}
	}
}

// RandomBatch returns n distinct random target IPs.
func (b *Blacklist) RandomBatch(n int) []string {
	seen := make(map[string]struct{}, n)
	out := make([]string, 0, n)
	for len(out) < n {
		ip := b.RandomIP()
		if _, dup := seen[ip]; dup {
			continue
		}
		seen[ip] = struct{}{}
		out = append(out, ip)
	}
	return out
}
