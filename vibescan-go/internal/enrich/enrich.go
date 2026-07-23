// Package enrich adds per-IP context to captured hosts using Shodan's free,
// keyless InternetDB (ports/vulns/tags/hostnames/cpes) and — only on demand,
// when an API key is set — the paid Shodan Host API (org/ISP/ASN/product).
//
// The API key never leaves the server; all lookups are cached (in-memory +
// durable via a Cache) and throttled by a shared outbound limiter to stay polite
// and to protect Shodan query credits.
package enrich

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vibescan/vibescan-go/internal/geo"
)

// Record is the normalized enrichment for one IP.
type Record struct {
	IP        string    `json:"ip" bson:"ip"`
	Ports     []int     `json:"ports" bson:"ports"`
	Vulns     []string  `json:"vulns" bson:"vulns"`
	Tags      []string  `json:"tags" bson:"tags"`
	Hostnames []string  `json:"hostnames" bson:"hostnames"`
	CPEs      []string  `json:"cpes" bson:"cpes"`
	Org       string    `json:"org,omitempty" bson:"org,omitempty"`
	ISP       string    `json:"isp,omitempty" bson:"isp,omitempty"`
	ASN       string    `json:"asn,omitempty" bson:"asn,omitempty"`
	Country   string    `json:"country,omitempty" bson:"country,omitempty"`
	City      string    `json:"city,omitempty" bson:"city,omitempty"`
	Products  []string  `json:"products,omitempty" bson:"products,omitempty"`
	LastSeen  time.Time `json:"last_seen,omitempty" bson:"last_seen,omitempty"`
	Sources   []string  `json:"sources" bson:"sources"`
	FetchedAt time.Time `json:"fetched_at" bson:"fetched_at"`
}

// Cache is the durable enrichment store (implemented by internal/store).
type Cache interface {
	ReadEnrichment(ctx context.Context, ipInt int64) (Record, bool, error)
	UpsertEnrichment(ctx context.Context, ipInt int64, rec Record) error
}

var errInvalidIP = errors.New("enrich: invalid ip")

const (
	memMaxSize     = 20000
	requestTimeout = 8 * time.Second
	userAgent      = "vibescan/1.0 (+https://github.com/verdantpro/vibescan_rework)"
)

// Enricher resolves and caches per-IP enrichment.
type Enricher struct {
	cache  Cache
	client *http.Client
	lim    *limiter
	key    string
	ttl    time.Duration

	mu  sync.Mutex
	mem map[int64]memEntry
}

type memEntry struct {
	rec Record
	at  time.Time
}

// NewEnricher builds an Enricher. cache may be nil (in-memory only). apiKey ""
// disables the paid Host API (InternetDB still works). rps throttles outbound
// requests (shared across on-demand + worker); ttl bounds cache freshness.
func NewEnricher(cache Cache, apiKey string, ttl time.Duration, rps float64) *Enricher {
	if ttl <= 0 {
		ttl = 168 * time.Hour
	}
	return &Enricher{
		cache:  cache,
		client: &http.Client{Timeout: requestTimeout},
		lim:    newLimiter(rps),
		key:    apiKey,
		ttl:    ttl,
		mem:    make(map[int64]memEntry),
	}
}

// HasKey reports whether the paid Shodan Host API is configured.
func (e *Enricher) HasKey() bool { return e != nil && e.key != "" }

// Get returns enrichment for ip, from cache when fresh. deep additionally queries
// the paid Host API (when a key is set) for org/ISP/ASN/product; the background
// worker passes deep=false so it never spends query credits.
func (e *Enricher) Get(ctx context.Context, ip string, deep bool) (Record, error) {
	ip = strings.TrimSpace(ip)
	ipInt, ok := geo.IPStrToInt(ip)
	if !ok {
		return Record{}, errInvalidIP
	}
	now := time.Now()

	if rec, ok := e.memGet(ipInt); ok && e.fresh(rec, now, deep) {
		return rec, nil
	}
	if e.cache != nil {
		if rec, ok, _ := e.cache.ReadEnrichment(ctx, ipInt); ok && e.fresh(rec, now, deep) {
			e.memPut(ipInt, rec)
			return rec, nil
		}
	}

	rec := Record{IP: ip, FetchedAt: now, Sources: []string{}}
	if idb, ok := e.internetDB(ctx, ip); ok {
		rec.merge(idb)
	}
	if deep && e.key != "" {
		if sh, ok := e.shodanHost(ctx, ip); ok {
			rec.merge(sh)
		}
	}
	rec.normalize()

	e.memPut(ipInt, rec)
	if e.cache != nil {
		_ = e.cache.UpsertEnrichment(ctx, ipInt, rec)
	}
	return rec, nil
}

// fresh reports whether a cached record is still usable for this request. A deep
// request needs a Shodan-sourced record (only when a key is configured), so a
// shallow (InternetDB-only) cache entry is refetched.
func (e *Enricher) fresh(rec Record, now time.Time, deep bool) bool {
	if now.Sub(rec.FetchedAt) >= e.ttl {
		return false
	}
	if deep && e.key != "" && !rec.hasSource("shodan") {
		return false
	}
	return true
}

func (e *Enricher) memGet(ipInt int64) (Record, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	m, ok := e.mem[ipInt]
	return m.rec, ok
}

func (e *Enricher) memPut(ipInt int64, rec Record) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.mem) >= memMaxSize {
		n := 0
		for k := range e.mem {
			delete(e.mem, k)
			if n++; n >= memMaxSize/2 {
				break
			}
		}
	}
	e.mem[ipInt] = memEntry{rec: rec, at: time.Now()}
}

func (r Record) hasSource(s string) bool {
	for _, v := range r.Sources {
		if v == s {
			return true
		}
	}
	return false
}

// merge folds another record's fields into r (union of lists, first non-empty
// scalar wins), used to combine InternetDB and Shodan Host results.
func (r *Record) merge(o Record) {
	r.Ports = append(r.Ports, o.Ports...)
	r.Vulns = append(r.Vulns, o.Vulns...)
	r.Tags = append(r.Tags, o.Tags...)
	r.Hostnames = append(r.Hostnames, o.Hostnames...)
	r.CPEs = append(r.CPEs, o.CPEs...)
	r.Products = append(r.Products, o.Products...)
	r.Sources = append(r.Sources, o.Sources...)
	if r.Org == "" {
		r.Org = o.Org
	}
	if r.ISP == "" {
		r.ISP = o.ISP
	}
	if r.ASN == "" {
		r.ASN = o.ASN
	}
	if r.Country == "" {
		r.Country = o.Country
	}
	if r.City == "" {
		r.City = o.City
	}
	if r.LastSeen.IsZero() {
		r.LastSeen = o.LastSeen
	}
}

// normalize dedupes/sorts the list fields and bounds their sizes so a hostile or
// pathological response can't bloat a record.
func (r *Record) normalize() {
	r.Ports = capInts(sortUniqInts(r.Ports), 64)
	r.Vulns = capStrs(sortUniq(r.Vulns), 200)
	r.Tags = capStrs(sortUniq(r.Tags), 32)
	r.Hostnames = capStrs(sortUniq(r.Hostnames), 32)
	r.CPEs = capStrs(sortUniq(r.CPEs), 64)
	r.Products = capStrs(sortUniq(r.Products), 32)
	r.Sources = sortUniq(r.Sources)
	if r.Ports == nil {
		r.Ports = []int{}
	}
	if r.Vulns == nil {
		r.Vulns = []string{}
	}
	if r.Tags == nil {
		r.Tags = []string{}
	}
}

func sortUniq(in []string) []string {
	if len(in) == 0 {
		return in
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func sortUniqInts(in []int) []int {
	if len(in) == 0 {
		return in
	}
	seen := make(map[int]struct{}, len(in))
	out := make([]int, 0, len(in))
	for _, n := range in {
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	sort.Ints(out)
	return out
}

func capStrs(in []string, n int) []string {
	if len(in) > n {
		return in[:n]
	}
	return in
}

func capInts(in []int, n int) []int {
	if len(in) > n {
		return in[:n]
	}
	return in
}

// --- outbound rate limiter (min interval between requests) ---

type limiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

func newLimiter(rps float64) *limiter {
	if rps <= 0 {
		rps = 1
	}
	return &limiter{interval: time.Duration(float64(time.Second) / rps)}
}

func (l *limiter) wait(ctx context.Context) error {
	l.mu.Lock()
	now := time.Now()
	var d time.Duration
	if l.next.After(now) {
		d = l.next.Sub(now)
		l.next = l.next.Add(l.interval)
	} else {
		l.next = now.Add(l.interval)
	}
	l.mu.Unlock()
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
