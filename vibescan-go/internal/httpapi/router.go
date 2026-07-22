// Package httpapi wires the collector's HTTP endpoints. It reproduces the
// legacy v1 routes served by server.py.
package httpapi

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/vibescan/vibescan-go/internal/collector"
	"github.com/vibescan/vibescan-go/internal/config"
	"github.com/vibescan/vibescan-go/internal/geo"
	"github.com/vibescan/vibescan-go/internal/store"
	"github.com/vibescan/vibescan-go/internal/transport"
	"github.com/vibescan/vibescan-go/internal/web"
)

// maxBodyBytes bounds the request body size for submissions.
const maxBodyBytes = 32 << 20 // 32 MiB

// Server holds the HTTP handler dependencies.
type Server struct {
	cfg       *config.Config
	ingestor  *collector.Ingestor
	blacklist *collector.BlacklistCache
	store     *store.Mongo
	geo       *geo.Resolver // optional; enriches tiles when Mongo docs lack geoip
}

// NewServer builds the collector HTTP server. geo may be nil (lookups no-op).
func NewServer(cfg *config.Config, ing *collector.Ingestor, bl *collector.BlacklistCache, st *store.Mongo, geoResolver *geo.Resolver) *Server {
	return &Server{cfg: cfg, ingestor: ing, blacklist: bl, store: st, geo: geoResolver}
}

// Handler returns the configured http.Handler (Go 1.22+ method-pattern mux).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Health + legacy v1 ingest (collector).
	mux.HandleFunc("GET /api/healthz", s.handleHealthz)
	mux.HandleFunc("GET /api/health", s.handleHealth)
	mux.HandleFunc("GET /api/v1/blacklist", s.handleBlacklist)
	mux.HandleFunc("POST /api/v1/results", s.handleResults)

	// v2 read APIs (for the new UI).
	mux.HandleFunc("GET /api/v2/gallery", s.handleGallery)
	mux.HandleFunc("GET /api/v2/search", s.handleSearch)
	mux.HandleFunc("GET /api/v2/stats", s.handleStats)
	mux.HandleFunc("GET /api/v2/random-capture", s.handleRandomCapture)
	mux.HandleFunc("GET /api/v2/services/{ip}/{port}", s.handleServiceDetail)
	mux.HandleFunc("GET /api/v2/image/{ip}/{port}", s.handleImage)

	// Unmatched /api/* → JSON 404 (more specific than the SPA catch-all, so a
	// mistyped API path never returns the HTML shell).
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found", "path": r.URL.Path})
	})

	// Embedded SPA (catch-all; the /api patterns above win by specificity).
	mux.Handle("/", web.Handler())

	return withCORS(mux)
}

// withCORS allows a separately-hosted UI to call the read APIs from the browser.
func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok", "service": "vibescan-collector",
	})
}

func (s *Server) handleBlacklist(w http.ResponseWriter, r *http.Request) {
	cidrs := s.blacklist.Get(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"updated_at":  time.Now().UTC().Format(time.RFC3339),
		"ttl_seconds": int(collector.BlacklistTTL.Seconds()),
		"cidrs":       cidrs,
	})
}

// handleResults decodes and ingests a signed submission. Any client error is
// redirected to the public URL (307), matching server.py's 4xx handling.
func (s *Server) handleResults(w http.ResponseWriter, r *http.Request) {
	var env transport.Envelope
	body := http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := json.NewDecoder(body).Decode(&env); err != nil {
		s.redirect(w, r)
		return
	}

	raw, err := transport.DecodeSubmission(env, s.cfg.SharedKey)
	if err != nil {
		s.redirect(w, r)
		return
	}

	result, err := s.ingestor.Ingest(r.Context(), raw, clientIP(r))
	if err != nil {
		s.redirect(w, r)
		return
	}

	if s.cfg.Debug {
		log.Printf("[collector] stored=%d buffered=%d from=%s", result.Stored, result.Buffered, clientIP(r))
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) redirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, s.cfg.PublicURL, http.StatusTemporaryRedirect)
}

// clientIP resolves the submitter's IP, honoring proxy headers like server.py.
func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return strings.TrimSpace(strings.Split(fwd, ",")[0])
	}
	if real := r.Header.Get("X-Real-IP"); real != "" {
		return strings.TrimSpace(real)
	}
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	if host == "" {
		return "unknown"
	}
	return host
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
