// Package geo provides IPv4 normalization and MaxMind GeoIP lookups,
// mirroring the relevant helpers in common/shared_utils.py.
package geo

import (
	"encoding/json"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
)

// IPToInt converts a JSON IP value (string like "1.2.3.4" or an integer) into
// its 32-bit integer form and canonical dotted-quad string, mirroring
// common/shared_utils.py:ip_to_int. ok is false for anything that is not a
// valid IPv4 address.
func IPToInt(raw json.RawMessage) (ipInt int64, ipStr string, ok bool) {
	if len(raw) == 0 {
		return 0, "", false
	}

	// Integer form.
	var n int64
	if err := json.Unmarshal(raw, &n); err == nil {
		if n < 0 || n > 0xFFFFFFFF {
			return 0, "", false
		}
		addr := netip.AddrFrom4([4]byte{
			byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n),
		})
		return n, addr.String(), true
	}

	// String form.
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return 0, "", false
	}
	addr, err := netip.ParseAddr(s)
	if err != nil || !addr.Is4() {
		return 0, "", false
	}
	b := addr.As4()
	v := int64(b[0])<<24 | int64(b[1])<<16 | int64(b[2])<<8 | int64(b[3])
	return v, addr.String(), true
}

// IPStrToInt converts a dotted-quad IPv4 string to its 32-bit integer form.
func IPStrToInt(s string) (int64, bool) {
	addr, err := netip.ParseAddr(s)
	if err != nil || !addr.Is4() {
		return 0, false
	}
	b := addr.As4()
	return int64(b[0])<<24 | int64(b[1])<<16 | int64(b[2])<<8 | int64(b[3]), true
}

// AnonymizeIP masks an IPv4 address to /16 granularity ("a.b.x.x"),
// mirroring common/shared_utils.py:anonymize_ip for the IPv4 path.
func AnonymizeIP(ip string) string {
	if ip == "" {
		return ip
	}
	parts := strings.Split(ip, ".")
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1] + ".x.x"
	}
	return "masked"
}

// GeoIP holds a single geolocation record in the exact shape stored by the
// Python collector.
type GeoIP struct {
	IP               string   `bson:"ip" json:"ip"`
	Lat              float64  `bson:"lat" json:"lat"`
	Lon              float64  `bson:"lon" json:"lon"`
	Location         Location `bson:"location" json:"location"`
	City             string   `bson:"city" json:"city"`
	Region           string   `bson:"region" json:"region"`
	Country          string   `bson:"country" json:"country"`
	CountryISO       string   `bson:"country_iso" json:"country_iso"`
	AccuracyRadiusKM *int     `bson:"accuracy_radius_km" json:"accuracy_radius_km"`
}

// Location is a GeoJSON Point ([lon, lat]).
type Location struct {
	Type        string    `bson:"type" json:"type"`
	Coordinates []float64 `bson:"coordinates" json:"coordinates"`
}

// Resolver looks up GeoIP records with a bounded TTL cache, mirroring the
// caching behavior in common/shared_utils.py:lookup_geoip.
type Resolver struct {
	reader *geoip2.Reader

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	at   time.Time
	data GeoIP
}

const (
	cacheTTL     = time.Hour
	cacheMaxSize = 50000
)

// NewResolver opens the MMDB at path. If the database cannot be opened it
// returns a Resolver that always yields no result (matching the Python
// behavior of degrading gracefully when GeoIP is unavailable).
func NewResolver(path string) *Resolver {
	r := &Resolver{cache: make(map[string]cacheEntry)}
	reader, err := geoip2.Open(path)
	if err == nil {
		r.reader = reader
	}
	return r
}

// Lookup returns the geolocation for ip, or (GeoIP{}, false) when the address
// is private/reserved, the database is unavailable, or no location is known.
func (r *Resolver) Lookup(ipStr string) (GeoIP, bool) {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return GeoIP{}, false
	}
	if addr.IsPrivate() || addr.IsLoopback() || addr.IsMulticast() ||
		addr.IsLinkLocalUnicast() || addr.IsUnspecified() {
		return GeoIP{}, false
	}
	if r.reader == nil {
		return GeoIP{}, false
	}

	now := time.Now()

	r.mu.Lock()
	defer r.mu.Unlock()

	if e, ok := r.cache[ipStr]; ok && now.Sub(e.at) < cacheTTL {
		return e.data, true
	}

	rec, err := r.reader.City(addr.AsSlice())
	if err != nil {
		return GeoIP{}, false
	}
	// MaxMind returns a zero-valued record for unknown addresses; treat a
	// missing coordinate pair as "no location", like the Python None check.
	if rec.Location.Latitude == 0 && rec.Location.Longitude == 0 {
		return GeoIP{}, false
	}

	data := GeoIP{
		IP:  ipStr,
		Lat: rec.Location.Latitude,
		Lon: rec.Location.Longitude,
		Location: Location{
			Type:        "Point",
			Coordinates: []float64{rec.Location.Longitude, rec.Location.Latitude},
		},
		City:       rec.City.Names["en"],
		Country:    rec.Country.Names["en"],
		CountryISO: rec.Country.IsoCode,
	}
	if len(rec.Subdivisions) > 0 {
		data.Region = rec.Subdivisions[len(rec.Subdivisions)-1].Names["en"]
	}
	if rec.Location.AccuracyRadius != 0 {
		v := int(rec.Location.AccuracyRadius)
		data.AccuracyRadiusKM = &v
	}

	if len(r.cache) >= cacheMaxSize {
		r.evictLocked(now)
	}
	r.cache[ipStr] = cacheEntry{at: now, data: data}
	return data, true
}

// evictLocked drops expired entries; if none are expired it clears the cache
// to bound memory. Caller must hold r.mu.
func (r *Resolver) evictLocked(now time.Time) {
	removed := false
	for k, v := range r.cache {
		if now.Sub(v.at) >= cacheTTL {
			delete(r.cache, k)
			removed = true
		}
	}
	if !removed {
		r.cache = make(map[string]cacheEntry)
	}
}
