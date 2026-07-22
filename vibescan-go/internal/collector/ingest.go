// Package collector implements the submission ingest pipeline: decode, enrich,
// and persist scan results, mirroring server.py's /api/v1/results handler.
package collector

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vibescan/vibescan-go/internal/config"
	"github.com/vibescan/vibescan-go/internal/geo"
	"github.com/vibescan/vibescan-go/internal/media"
	"github.com/vibescan/vibescan-go/internal/store"
)

// ErrBadRequest signals a client error; the HTTP layer redirects these to the
// public URL, matching the Python server's 4xx handling.
var ErrBadRequest = errors.New("bad request")

// AnonSubmittedBy is stored (and returned publicly) when the agent opts out of
// attribution via no_report / host.anon. Stats already drop this value; using a
// fixed sentinel avoids leaking the scanner's real egress IP.
const AnonSubmittedBy = "0.0.0.0"

// Ingestor holds the dependencies for the ingest pipeline.
type Ingestor struct {
	cfg    *config.Config
	mongo  *store.Mongo
	r2     *store.R2
	geo    *geo.Resolver
	buffer *store.Buffer
}

// NewIngestor builds an Ingestor.
func NewIngestor(cfg *config.Config, m *store.Mongo, r2 *store.R2, g *geo.Resolver, b *store.Buffer) *Ingestor {
	return &Ingestor{cfg: cfg, mongo: m, r2: r2, geo: g, buffer: b}
}

// Result is the ingest summary returned to the client.
type Result struct {
	Stored   int      `json:"stored"`
	Buffered int      `json:"buffered"`
	IPs      []string `json:"ips"`
}

type payload struct {
	GeneratedAt string `json:"generated_at"`
	NoReport    bool   `json:"no_report"`
	Results     []host `json:"results"`
}

type host struct {
	IP       json.RawMessage    `json:"ip"`
	Anon     bool               `json:"anon"`
	Whois    string             `json:"whois"`
	RDNS     *string            `json:"rdns"`
	Services map[string]service `json:"services"`
	Ports    map[string]service `json:"ports"`
}

type service struct {
	Banner          string          `json:"banner"`
	Capture         string          `json:"capture"`
	HTTPStatus      *int            `json:"http_status"`
	Timestamp       json.RawMessage `json:"timestamp"`
	Secured         *bool           `json:"secured"`
	Error           json.RawMessage `json:"error"`
	Fulltext        *string         `json:"fulltext"`
	CertCN          *string         `json:"cert_cn"`
	FaviconHash     *string         `json:"favicon_hash"`
	ScreenshotPhash *string         `json:"screenshot_phash"`
	DomHash         *string         `json:"dom_hash"`
}

// entry is a fully-enriched service pending R2 finalization and persistence.
type entry struct {
	ipInt   int64
	ipStr   string
	port    int
	doc     map[string]any
	capB64  string
	needsR2 bool
	capExt  string
}

// Ingest decodes payload JSON, enforces the replay window, enriches each
// service, uploads captures to R2, and persists via Mongo (buffering failures).
func (ing *Ingestor) Ingest(ctx context.Context, raw []byte, clientIP string) (*Result, error) {
	var p payload
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, ErrBadRequest
	}

	// Enforce a 5-minute submission window to prevent replay (server.py).
	if p.GeneratedAt == "" {
		return nil, ErrBadRequest
	}
	gen, err := parseISOTime(p.GeneratedAt)
	if err != nil {
		return nil, ErrBadRequest
	}
	if d := time.Since(gen); d < -5*time.Minute || d > 5*time.Minute {
		return nil, ErrBadRequest
	}

	now := time.Now().UTC()
	// Payload-level no_report anonymizes every service in the batch.
	batchAnon := p.NoReport

	var entries []entry
	for _, h := range p.Results {
		ipInt, ipStr, ok := geo.IPToInt(h.IP)
		if !ok {
			continue
		}
		services := h.Services
		if services == nil {
			services = h.Ports
		}

		var geoPayload *geo.GeoIP
		if g, found := ing.geo.Lookup(ipStr); found {
			geoPayload = &g
		}

		for portKey, svc := range services {
			port, perr := strconv.Atoi(portKey)
			if perr != nil || port < 1 || port > 65535 {
				continue
			}
			entries = append(entries, ing.buildEntry(h, svc, ipInt, ipStr, port, now, batchAnon, clientIP, geoPayload))
		}
	}

	if len(entries) == 0 {
		return nil, ErrBadRequest
	}

	ing.uploadCaptures(ctx, entries)

	return ing.persist(ctx, entries, now), nil
}

// buildEntry constructs the stored document for one service, applying the same
// normalization and enrichment as server.py — with one intentional OPSEC fix:
// when anonymized, submitted_by is the AnonSubmittedBy sentinel, not the real
// client IP (Python still stores the real IP; we do not).
func (ing *Ingestor) buildEntry(h host, svc service, ipInt int64, ipStr string, port int, now time.Time, batchAnon bool, clientIP string, geoPayload *geo.GeoIP) entry {
	secured := svc.Secured != nil && *svc.Secured
	fulltext := blankToNil(svc.Fulltext)
	dom := normalizeLower(svc.DomHash)
	if dom == nil && fulltext != nil {
		if h := media.DomStructureHash(*fulltext); h != "" {
			dom = &h
		}
	}
	certCN := blankToNil(trimPtr(svc.CertCN))
	favicon := normalizeLower(svc.FaviconHash)
	phash := normalizeLower(svc.ScreenshotPhash)

	capHash, capExt, capOK := media.CaptureHashExt(svc.Capture)

	anon := h.Anon || batchAnon
	submitter := clientIP
	if anon {
		submitter = AnonSubmittedBy
	}

	doc := map[string]any{
		"ip":           ipInt,
		"ip_str":       ipStr,
		"port":         port,
		"whois":        h.Whois,
		"rdns":         h.RDNS,
		"submitted_by": submitter,
		"anon":         anon,
		"updated_at":   now,
		"timestamp":    parseServiceTime(svc.Timestamp, now),
		"capture":      svc.Capture,
		"capture_hash": capHash,
		"capture_ext":  capExt,
		"http_status":  intPtrToAny(svc.HTTPStatus),
		"secured":      secured,
		"banner":       svc.Banner,
		"fulltext":     strPtrToAny(fulltext),
		"error":        rawToAny(svc.Error),
	}
	if geoPayload != nil {
		doc["geoip"] = *geoPayload
	}
	if certCN != nil {
		doc["cert_cn"] = *certCN
	}
	if favicon != nil {
		doc["favicon_hash"] = *favicon
	}
	if phash != nil {
		doc["screenshot_phash"] = *phash
		if chunks := media.SplitPhashChunks(*phash); chunks != nil {
			for k, v := range chunks {
				doc[k] = v
			}
		}
	}
	if dom != nil {
		doc["dom_hash"] = *dom
	}
	if capOK && !secured && svc.HTTPStatus != nil && *svc.HTTPStatus == 200 {
		product := media.ExtractProduct(svc.Banner)
		if product == "" {
			product = "Unknown"
		}
		doc["landing_image"] = map[string]any{
			"port":         strconv.Itoa(port),
			"capture_hash": capHash,
			"capture_ext":  capExt,
			"http_status":  200,
			"secured":      false,
			"product":      product,
		}
	}

	return entry{
		ipInt:   ipInt,
		ipStr:   ipStr,
		port:    port,
		doc:     doc,
		capB64:  svc.Capture,
		needsR2: capOK && ing.r2 != nil,
		capExt:  capExt,
	}
}

// uploadCaptures uploads captures to R2 with bounded concurrency, then rewrites
// each doc's capture field to the r2: reference (or clears it when the upload
// fails and MongoDB fallback is disabled), mirroring server.py.
func (ing *Ingestor) uploadCaptures(ctx context.Context, entries []entry) {
	if ing.r2 == nil {
		return
	}
	sem := make(chan struct{}, ing.cfg.R2UploadConcurrency)
	var wg sync.WaitGroup
	for i := range entries {
		e := &entries[i]
		if !e.needsR2 {
			continue
		}
		wg.Add(1)
		go func(e *entry) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			key, err := ing.r2.Upload(ctx, e.capB64, e.ipStr, e.port, e.capExt)
			if err == nil {
				e.doc["capture"] = "r2:" + key
				return
			}
			if !ing.cfg.R2FallbackToMongo {
				e.doc["capture"] = ""
				e.doc["capture_hash"] = ""
				e.doc["capture_ext"] = ""
				delete(e.doc, "landing_image")
			}
			// Fallback enabled: leave the base64 capture in the document.
		}(e)
	}
	wg.Wait()
}

// persist writes entries to MongoDB in ingest-sized batches, buffering any that
// fail (or all, when MongoDB is unavailable).
func (ing *Ingestor) persist(ctx context.Context, entries []entry, now time.Time) *Result {
	res := &Result{IPs: []string{}}
	batch := ing.cfg.IngestBatchSize

	for start := 0; start < len(entries); start += batch {
		end := start + batch
		if end > len(entries) {
			end = len(entries)
		}
		chunk := entries[start:end]

		ops := make([]store.UpsertOp, len(chunk))
		for i, e := range chunk {
			ops[i] = store.UpsertOp{
				IPInt:      e.ipInt,
				Port:       e.port,
				IPStr:      e.ipStr,
				ReceivedAt: now,
				Doc:        e.doc,
			}
		}

		if !ing.mongo.Available() {
			ing.bufferOps(ops)
			for _, e := range chunk {
				res.Buffered++
				res.IPs = append(res.IPs, e.ipStr)
			}
			continue
		}

		failed, err := ing.mongo.BulkUpsert(ctx, ops)
		if err == nil {
			for _, e := range chunk {
				res.Stored++
				res.IPs = append(res.IPs, e.ipStr)
			}
			continue
		}

		var toBuffer []store.UpsertOp
		for i, e := range chunk {
			if failed[i] {
				res.Buffered++
				toBuffer = append(toBuffer, ops[i])
			} else {
				res.Stored++
			}
			res.IPs = append(res.IPs, e.ipStr)
		}
		ing.bufferOps(toBuffer)
	}
	return res
}

func (ing *Ingestor) bufferOps(ops []store.UpsertOp) {
	if len(ops) == 0 || ing.buffer == nil {
		return
	}
	_ = ing.buffer.Persist(ops)
}

// --- small helpers -------------------------------------------------------

func trimPtr(s *string) *string {
	if s == nil {
		return nil
	}
	v := strings.TrimSpace(*s)
	return &v
}

func blankToNil(s *string) *string {
	if s == nil {
		return nil
	}
	if strings.TrimSpace(*s) == "" {
		return nil
	}
	return s
}

func normalizeLower(s *string) *string {
	if s == nil {
		return nil
	}
	v := strings.ToLower(strings.TrimSpace(*s))
	if v == "" {
		return nil
	}
	return &v
}

func strPtrToAny(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}

func intPtrToAny(n *int) any {
	if n == nil {
		return nil
	}
	return *n
}

func rawToAny(raw json.RawMessage) any {
	if len(raw) == 0 {
		return nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil
	}
	return v
}

func parseISOTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	// Naive timestamp: assume UTC, matching the Python fromisoformat fallback.
	for _, layout := range []string{"2006-01-02T15:04:05.999999", "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, errors.New("invalid timestamp")
}

func parseServiceTime(raw json.RawMessage, fallback time.Time) time.Time {
	if len(raw) == 0 {
		return fallback
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return fallback
	}
	if t, err := parseISOTime(s); err == nil {
		return t
	}
	return fallback
}
