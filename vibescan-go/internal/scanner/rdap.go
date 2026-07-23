package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// RDAP looks up network ownership for IPv4 addresses via the public RDAP
// bootstrap (rdap.org), with a small in-process cache to stay polite.
// Format matches vibescan_v2/common/nettools.py:whois → "NAME - ORG".
type RDAP struct {
	client *http.Client

	mu    sync.Mutex
	cache map[string]rdapEntry // keyed by /24
}

type rdapEntry struct {
	at  time.Time
	val string
}

const (
	rdapTTL     = 24 * time.Hour
	rdapMaxSize = 10000
	rdapTimeout = 8 * time.Second
)

// NewRDAP builds a lookup client. Safe for concurrent use.
func NewRDAP() *RDAP {
	return &RDAP{
		client: &http.Client{
			Timeout: rdapTimeout,
			// Follow redirects to the authoritative RIR (rdap.org bootstraps).
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("too many RDAP redirects")
				}
				return nil
			},
		},
		cache: make(map[string]rdapEntry),
	}
}

// Lookup returns a short owner string for ip, or "" on any failure.
func (r *RDAP) Lookup(ctx context.Context, ip string) string {
	if r == nil {
		return ""
	}
	ip = strings.TrimSpace(ip)
	if net.ParseIP(ip) == nil {
		return ""
	}
	key := net24Key(ip)

	r.mu.Lock()
	if e, ok := r.cache[key]; ok && time.Since(e.at) < rdapTTL {
		r.mu.Unlock()
		return e.val
	}
	r.mu.Unlock()

	val := r.fetch(ctx, ip)

	r.mu.Lock()
	if len(r.cache) >= rdapMaxSize {
		// Drop arbitrary half of entries (cheap bound; not LRU).
		n := 0
		for k := range r.cache {
			delete(r.cache, k)
			n++
			if n >= rdapMaxSize/2 {
				break
			}
		}
	}
	r.cache[key] = rdapEntry{at: time.Now(), val: val}
	r.mu.Unlock()
	return val
}

func net24Key(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ip
	}
	return parts[0] + "." + parts[1] + "." + parts[2] + ".0/24"
}

func (r *RDAP) fetch(ctx context.Context, ip string) string {
	// rdap.org bootstraps to the correct RIR via redirect.
	url := "https://rdap.org/ip/" + ip
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	req.Header.Set("User-Agent", "vibescan-agent/1.0 (+https://github.com/verdantpro/vibescan_rework)")

	resp, err := r.client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil || len(body) == 0 {
		return ""
	}
	return parseRDAPOwner(body)
}

// rdapResponse is the subset of RDAP IP network JSON we care about.
type rdapResponse struct {
	Name     string `json:"name"`
	Remarks  []struct {
		Description []string `json:"description"`
		Title       string   `json:"title"`
	} `json:"remarks"`
	Entities []rdapEntity `json:"entities"`
}

type rdapEntity struct {
	Roles      []string          `json:"roles"`
	VcardArray json.RawMessage   `json:"vcardArray"`
	Entities   []rdapEntity      `json:"entities"`
	Remarks    []struct {
		Description []string `json:"description"`
	} `json:"remarks"`
}

func parseRDAPOwner(raw []byte) string {
	var doc rdapResponse
	if err := json.Unmarshal(raw, &doc); err != nil {
		return ""
	}

	name := strings.TrimSpace(doc.Name)

	// Prefer network remarks description (often the org/netblock blurb).
	org := ""
	for _, rem := range doc.Remarks {
		if len(rem.Description) > 0 {
			org = strings.TrimSpace(strings.Join(rem.Description, " "))
			if org != "" {
				break
			}
		}
	}

	// Fall back to registrant / abuse entity FN or org from vCard.
	if org == "" {
		org = entityOrg(doc.Entities)
	}

	parts := make([]string, 0, 2)
	if name != "" {
		parts = append(parts, name)
	}
	if org != "" && !strings.EqualFold(org, name) {
		parts = append(parts, org)
	}
	out := strings.Join(parts, " - ")
	// Keep payload/UI compact (matches Python shorten habits for display).
	if len(out) > 256 {
		out = out[:256]
	}
	return out
}

func entityOrg(entities []rdapEntity) string {
	// Prefer registrant, then any entity with a readable name.
	prefer := []string{"registrant", "administrative", "technical", "abuse"}
	for _, role := range prefer {
		if s := findEntityByRole(entities, role); s != "" {
			return s
		}
	}
	return findEntityByRole(entities, "")
}

func findEntityByRole(entities []rdapEntity, role string) string {
	for _, e := range entities {
		if role != "" && !hasRole(e.Roles, role) {
			// Nested entities (common in RIR payloads).
			if s := findEntityByRole(e.Entities, role); s != "" {
				return s
			}
			continue
		}
		if s := vcardName(e.VcardArray); s != "" {
			return s
		}
		for _, rem := range e.Remarks {
			if len(rem.Description) > 0 {
				if d := strings.TrimSpace(rem.Description[0]); d != "" {
					return d
				}
			}
		}
		if s := findEntityByRole(e.Entities, role); s != "" {
			return s
		}
	}
	return ""
}

func hasRole(roles []string, want string) bool {
	for _, r := range roles {
		if strings.EqualFold(r, want) {
			return true
		}
	}
	return false
}

// vcardName extracts fn or org from a jCard vcardArray payload.
// Shape: ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Org"], ...]]
func vcardName(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var top []json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil || len(top) < 2 {
		return ""
	}
	var props [][]json.RawMessage
	if err := json.Unmarshal(top[1], &props); err != nil {
		return ""
	}
	var fn, org string
	for _, p := range props {
		if len(p) < 4 {
			continue
		}
		var name string
		if err := json.Unmarshal(p[0], &name); err != nil {
			continue
		}
		var val any
		if err := json.Unmarshal(p[3], &val); err != nil {
			continue
		}
		switch strings.ToLower(name) {
		case "fn":
			if s, ok := val.(string); ok {
				fn = strings.TrimSpace(s)
			}
		case "org":
			switch v := val.(type) {
			case string:
				org = strings.TrimSpace(v)
			case []any:
				if len(v) > 0 {
					if s, ok := v[0].(string); ok {
						org = strings.TrimSpace(s)
					}
				}
			}
		}
	}
	if org != "" {
		return org
	}
	return fn
}
