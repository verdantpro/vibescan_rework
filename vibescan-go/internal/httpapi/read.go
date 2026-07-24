package httpapi

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/mongo"

	"github.com/vibescan/vibescan-go/internal/collector"
	"github.com/vibescan/vibescan-go/internal/geo"
	"github.com/vibescan/vibescan-go/internal/media"
	"github.com/vibescan/vibescan-go/internal/store"
)

// tile is the v2 gallery/search entry shape a UI renders.
type tile struct {
	IP              string     `json:"ip"`
	Port            int        `json:"port"`
	Banner          string     `json:"banner"`
	Product         string     `json:"product"`
	HTTPStatus      *int       `json:"http_status"`
	Secured         bool       `json:"secured"`
	Whois           string     `json:"whois"`
	ImageURL        string     `json:"image_url"`
	CaptureHash     string     `json:"capture_hash"`
	CaptureExt      string     `json:"capture_ext"`
	HasFulltext     bool       `json:"has_fulltext"`
	ScreenshotPhash string     `json:"screenshot_phash,omitempty"`
	DomHash         string     `json:"dom_hash,omitempty"`
	CertCN          string     `json:"cert_cn,omitempty"`
	UpdatedAt       string     `json:"updated_at"`
	Geo             *geo.GeoIP `json:"geo,omitempty"`
	// Enrichment summary (present once the host has been enriched).
	VulnCount  int      `json:"vuln_count"`
	Tags       []string `json:"tags,omitempty"`
	ExtraPorts []int    `json:"extra_ports,omitempty"`
	Verdict    string   `json:"verdict,omitempty"`
	Sources    []string `json:"sources,omitempty"`     // enrichment feeds that contributed
	EnrichedAt string   `json:"enriched_at,omitempty"` // RFC3339, last enrichment time
}

// resolveImageURL returns the best image URL for a capture: the R2 public URL
// for r2: references, otherwise the collector's own image endpoint for base64
// captures stored in MongoDB.
func (s *Server) resolveImageURL(d store.ServiceDoc) string {
	cap := d.Capture
	if strings.HasPrefix(cap, "r2:") {
		if s.cfg.R2PublicURL != "" {
			return s.cfg.R2PublicURL + "/" + cap[len("r2:"):]
		}
	}
	if cap == "" || strings.HasPrefix(strings.ToLower(cap), "screenshot_error") {
		return ""
	}
	return "/api/v2/image/" + d.IPStr + "/" + strconv.Itoa(d.Port)
}

func (s *Server) toTile(d store.ServiceDoc) tile {
	ts := d.UpdatedAt
	if ts.IsZero() {
		ts = d.ReceivedAt
	}
	return tile{
		IP:              d.IPStr,
		Port:            d.Port,
		Banner:          strings.TrimSpace(d.Banner),
		Product:         media.ExtractProduct(d.Banner),
		HTTPStatus:      d.HTTPStatus,
		Secured:         d.Secured,
		Whois:           firstWhois(d.Whois),
		ImageURL:        s.resolveImageURL(d),
		CaptureHash:     d.CaptureHash,
		CaptureExt:      d.CaptureExt,
		HasFulltext:     d.HasFulltext,
		ScreenshotPhash: d.ScreenshotPhash,
		DomHash:         d.DomHash,
		CertCN:          d.CertCN,
		UpdatedAt:       ts.UTC().Format(time.RFC3339),
		Geo:             s.resolveGeo(d),
		VulnCount:       d.VulnCount,
		Tags:            d.ShodanTags,
		ExtraPorts:      d.ExtraPorts,
		Verdict:         d.Verdict,
		Sources:         d.Sources,
		EnrichedAt:      enrichedAtStr(d.EnrichedAt),
	}
}

// enrichedAtStr renders the last-enrichment time as RFC3339, or "" if unset.
func enrichedAtStr(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// resolveGeo prefers the stored geoip subdoc; if missing (e.g. mmdb was absent
// at ingest), looks up again so the world map works after GeoIP is mounted.
func (s *Server) resolveGeo(d store.ServiceDoc) *geo.GeoIP {
	if d.GeoIP != nil {
		return d.GeoIP
	}
	if s.geo == nil || d.IPStr == "" {
		return nil
	}
	if g, ok := s.geo.Lookup(d.IPStr); ok {
		cp := g
		return &cp
	}
	return nil
}

func (s *Server) toTiles(docs []store.ServiceDoc) []tile {
	out := make([]tile, 0, len(docs))
	for _, d := range docs {
		out = append(out, s.toTile(d))
	}
	return out
}

func (s *Server) handleGallery(w http.ResponseWriter, r *http.Request) {
	limit := clampInt(queryInt(r, "limit", 200), 1, s.cfg.MaxGallery)
	offset := clampInt(queryInt(r, "offset", 0), 0, 1_000_000)
	screensOnly := queryBool(r, "with_screenshots_only", true)
	// sort=recent → the "Latest signals" rail: strict newest-first, any status.
	recent := strings.EqualFold(r.URL.Query().Get("sort"), "recent")

	// Over-fetch one row so has_more reflects whether a real next page exists,
	// rather than guessing from a full page (the gallery's per-/24 dedup can
	// return exactly `limit` on the final page).
	docs, err := s.store.Gallery(r.Context(), store.ListOpts{
		Limit: limit + 1, Offset: offset, ScreensOnly: screensOnly, Recent: recent,
		MaxTimeMS: s.cfg.AggMaxTimeMS,
	})
	if err != nil {
		s.readError(w, err)
		return
	}
	hasMore := len(docs) > limit
	if hasMore {
		docs = docs[:limit]
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"entries":  s.toTiles(docs),
		"has_more": hasMore,
	})
}

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	limit := clampInt(queryInt(r, "limit", 100), 1, s.cfg.MaxGallery)
	offset := clampInt(queryInt(r, "offset", 0), 0, 1_000_000)

	opts := store.ListOpts{
		Limit: limit + 1, Offset: offset, MaxTimeMS: s.cfg.AggMaxTimeMS,
		Query:   strings.TrimSpace(r.URL.Query().Get("q")),
		Product: strings.TrimSpace(r.URL.Query().Get("product")),
	}
	if v := r.URL.Query().Get("port"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			opts.Port = &n
		}
	}
	if v := r.URL.Query().Get("status"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			opts.StatusCode = &n
		}
	}
	if v := r.URL.Query().Get("secured"); v != "" {
		b := v == "1" || strings.EqualFold(v, "true")
		opts.Secured = &b
	}
	if v := r.URL.Query().Get("has_vulns"); v != "" {
		b := v == "1" || strings.EqualFold(v, "true")
		opts.HasVulns = &b
	}
	opts.Tag = strings.TrimSpace(r.URL.Query().Get("tag"))
	opts.Verdict = strings.TrimSpace(r.URL.Query().Get("verdict"))

	docs, err := s.store.Search(r.Context(), opts)
	if err != nil {
		s.readError(w, err)
		return
	}
	hasMore := len(docs) > limit
	if hasMore {
		docs = docs[:limit]
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"entries":  s.toTiles(docs),
		"has_more": hasMore,
		"query":    opts.Query,
	})
}

func (s *Server) handleServiceDetail(w http.ResponseWriter, r *http.Request) {
	ipInt, ok := geo.IPStrToInt(r.PathValue("ip"))
	port, perr := strconv.Atoi(r.PathValue("port"))
	if !ok || perr != nil {
		http.Error(w, "invalid ip/port", http.StatusBadRequest)
		return
	}
	brief := queryBool(r, "brief", false)
	doc, err := s.store.ServiceDetail(r.Context(), ipInt, port, brief)
	if errors.Is(err, mongo.ErrNoDocuments) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		s.readError(w, err)
		return
	}
	t := s.toTile(*doc)
	// Never expose a real submitter IP for anonymized captures (covers legacy
	// docs that may still have the real IP stored with anon=true).
	submitter := doc.SubmittedBy
	if doc.Anon {
		submitter = collector.AnonSubmittedBy
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"service":      t,
		"fulltext":     doc.Fulltext,
		"favicon_hash": doc.FaviconHash,
		"submitted_by": submitter,
		"anon":         doc.Anon,
		"timestamp":    nonZeroRFC3339(doc.Timestamp),
		"received_at":  nonZeroRFC3339(doc.ReceivedAt),
	})
}

func (s *Server) handleRandomCapture(w http.ResponseWriter, r *http.Request) {
	doc, err := s.store.RandomLanding(r.Context())
	if err != nil {
		s.readError(w, err)
		return
	}
	if doc == nil {
		http.Error(w, "no captures available", http.StatusServiceUnavailable)
		return
	}
	// Always re-derive product from banner so stale landing_image.product
	// (pre-cleanup nmap strings) never leaks into the live viewport.
	product := media.ExtractProduct(doc.Banner)
	if product == "" {
		product = "Unknown"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"image_url":    s.resolveImageURL(*doc),
		"ip":           doc.IPStr,
		"port":         doc.Port,
		"product_name": product,
		"whois":        firstWhois(doc.Whois),
	})
}

// handleEnrich returns Shodan/InternetDB cross-reference for a captured IP. This
// is the on-demand (deep) path: it includes the paid Host API when a key is set.
func (s *Server) handleEnrich(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.EnrichEnabled || s.enricher == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "enrichment disabled"})
		return
	}
	ipInt, ok := geo.IPStrToInt(r.PathValue("ip"))
	if !ok {
		http.Error(w, "invalid ip", http.StatusBadRequest)
		return
	}
	rec, err := s.enricher.Get(r.Context(), r.PathValue("ip"), true)
	if err != nil {
		s.readError(w, err)
		return
	}
	// Push the (deep) verdict + summary onto this IP's result docs so tiles and
	// search reflect what a viewer just computed.
	if s.store.Available() {
		_ = s.store.DenormalizeEnrichment(r.Context(), ipInt, rec)
	}
	writeJSON(w, http.StatusOK, rec)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	tr := clampInt(queryInt(r, "time_range", 1), 1, 8760)
	stats, err := s.store.StatsAggregate(r.Context(), tr, s.cfg.AggMaxTimeMS)
	if err != nil {
		s.readError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

// handleImage serves base64 captures stored in MongoDB, or redirects to the R2
// public URL for r2: references.
func (s *Server) handleImage(w http.ResponseWriter, r *http.Request) {
	ipInt, ok := geo.IPStrToInt(r.PathValue("ip"))
	port, perr := strconv.Atoi(r.PathValue("port"))
	if !ok || perr != nil {
		http.Error(w, "invalid ip/port", http.StatusBadRequest)
		return
	}
	capValue, ext, err := s.store.LoadCapture(r.Context(), ipInt, port)
	if errors.Is(err, mongo.ErrNoDocuments) || capValue == "" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		s.readError(w, err)
		return
	}
	if strings.HasPrefix(capValue, "r2:") {
		if s.cfg.R2PublicURL != "" {
			http.Redirect(w, r, s.cfg.R2PublicURL+"/"+capValue[len("r2:"):], http.StatusFound)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	img, decErr := base64.StdEncoding.DecodeString(capValue)
	if decErr != nil {
		// A capture that won't decode is unservable, not a server fault.
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	contentType := "image/png"
	if ext == "jpg" || ext == "jpeg" || strings.HasPrefix(capValue, "/9j/") {
		contentType = "image/jpeg"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	_, _ = w.Write(img)
}

// readError maps store failures to 503 (the DB is the usual culprit for reads).
func (s *Server) readError(w http.ResponseWriter, _ error) {
	writeJSON(w, http.StatusServiceUnavailable, map[string]any{"offline": true})
}

// --- request helpers -----------------------------------------------------

func queryInt(r *http.Request, key string, def int) int {
	if v := r.URL.Query().Get(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func queryBool(r *http.Request, key string, def bool) bool {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	return v == "1" || strings.EqualFold(v, "true")
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func firstWhois(whois string) string {
	if whois == "" {
		return "unknown"
	}
	if i := strings.Index(whois, " - "); i >= 0 {
		return whois[:i]
	}
	return whois
}

func nonZeroRFC3339(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}
