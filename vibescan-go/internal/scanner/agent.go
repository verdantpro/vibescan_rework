package scanner

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vibescan/vibescan-go/internal/media"
)

// Config holds the agent's runtime settings (populated from env in cmd/agent).
type Config struct {
	ServerURL          string
	SharedKey          string
	Ports              []string
	ScanThreads        int
	BatchSize          int
	NmapOptions        string
	CaptureDelay       time.Duration
	CaptureHTTP        bool
	NoReport           bool
	BrowserConcurrency int
	// EnableRDAP looks up network ownership (default true).
	EnableRDAP bool
}

// Agent runs the scan → capture → submit loop.
type Agent struct {
	cfg     Config
	client  *Client
	bl      *Blacklist
	browser *Browser
	rdap    *RDAP
	blNext  time.Time
}

// NewAgent wires the collector client, blacklist, and (optionally) the browser.
func NewAgent(cfg Config, bl *Blacklist, browser *Browser) *Agent {
	a := &Agent{
		cfg:     cfg,
		client:  NewClient(cfg.ServerURL, cfg.SharedKey),
		bl:      bl,
		browser: browser,
	}
	if cfg.EnableRDAP {
		a.rdap = NewRDAP()
	}
	return a
}

// Run loops until ctx is cancelled: refresh blacklist, scan a batch, submit.
func (a *Agent) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if err := a.scanOnce(ctx); err != nil {
			log.Printf("[agent] batch error: %v", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}
}

func (a *Agent) refreshBlacklist(ctx context.Context) {
	if time.Now().Before(a.blNext) {
		return
	}
	cidrs, ttl, err := a.client.FetchBlacklist(ctx)
	if err != nil {
		log.Printf("[agent] blacklist refresh failed (keeping current): %v", err)
		a.blNext = time.Now().Add(5 * time.Minute)
		return
	}
	a.bl.Set(cidrs)
	a.blNext = time.Now().Add(ttl)
	log.Printf("[agent] blacklist refreshed: %d CIDRs", len(cidrs))
}

func (a *Agent) scanOnce(ctx context.Context) error {
	a.refreshBlacklist(ctx)

	ips := a.bl.RandomBatch(a.cfg.BatchSize)
	scanCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	scanned, err := RunNmap(scanCtx, ips, a.cfg.Ports, a.cfg.NmapOptions)
	if err != nil {
		return fmt.Errorf("nmap: %w", err)
	}
	if len(scanned) == 0 {
		return nil // nothing open in this batch
	}

	// Build records concurrently, bounded by ScanThreads.
	var (
		mu      sync.Mutex
		records []map[string]any
		wg      sync.WaitGroup
	)
	sem := make(chan struct{}, max(1, a.cfg.ScanThreads))
	for ip, ports := range scanned {
		wg.Add(1)
		go func(ip string, ports map[int]string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if rec := a.buildHostRecord(ctx, ip, ports); rec != nil {
				mu.Lock()
				records = append(records, rec)
				mu.Unlock()
			}
		}(ip, ports)
	}
	wg.Wait()

	if len(records) == 0 {
		return nil
	}
	summary, err := a.client.Submit(ctx, a.buildPayload(records))
	if err != nil {
		return fmt.Errorf("submit: %w", err)
	}
	log.Printf("[agent] submitted %d hosts → %v", len(records), summary)
	return nil
}

// buildHostRecord assembles one host's payload, capturing screenshots when
// enabled. Services whose capture fails are dropped (matching the Python agent).
// Returns nil when the host yields no usable services.
func (a *Agent) buildHostRecord(ctx context.Context, ip string, ports map[int]string) map[string]any {
	// One RDAP lookup per host (cached by /24); used in payload + stego.
	whoisInfo := ""
	if a.rdap != nil {
		rdapCtx, cancel := context.WithTimeout(ctx, rdapTimeout)
		whoisInfo = a.rdap.Lookup(rdapCtx, ip)
		cancel()
	}

	services := map[string]any{}
	for port, banner := range ports {
		ts := time.Now().UTC().Format(time.RFC3339Nano)
		rec := map[string]any{"banner": banner, "timestamp": ts}

		if a.cfg.CaptureHTTP && a.browser != nil {
			cap := a.browser.Capture(ctx, ip, port)
			if cap.PNGBase64 == "" {
				continue // reject services we couldn't screenshot
			}
			scheme := "http"
			if cap.Secured {
				scheme = "https"
			}
			statusStr := ""
			if cap.Status != nil {
				statusStr = strconv.Itoa(*cap.Status)
			}
			stegoPayload := fmt.Sprintf("timestamp:%s|url:%s://%s:%d|status:%s|whois:%s|banner:%s",
				ts, scheme, ip, port, statusStr, trunc(whoisInfo, 512), trunc(banner, 512))
			rec["capture"] = media.EmbedStegoBase64(cap.PNGBase64, stegoPayload)
			rec["http_status"] = cap.Status
			rec["secured"] = cap.Secured
			if cap.Fulltext != "" {
				rec["fulltext"] = cap.Fulltext
				if dh := media.DomStructureHash(cap.Fulltext); dh != "" {
					rec["dom_hash"] = dh
				}
			}
			if cap.CertCN != "" {
				rec["cert_cn"] = cap.CertCN
			}
			if cap.Phash != "" {
				rec["screenshot_phash"] = cap.Phash
			}
			if cap.FaviconHash != "" {
				rec["favicon_hash"] = cap.FaviconHash
			}
		} else {
			rec["capture"] = ""
			rec["http_status"] = nil
			rec["secured"] = false
		}
		services[strconv.Itoa(port)] = rec
	}
	if len(services) == 0 {
		return nil
	}
	return map[string]any{
		"ip":       ip,
		"services": services,
		"whois":    whoisInfo,
		"rdns":     ptr(ctx, ip),
	}
}

func (a *Agent) buildPayload(records []map[string]any) map[string]any {
	p := map[string]any{
		"version":      1,
		"generated_at": time.Now().UTC().Format(time.RFC3339Nano),
		"results":      records,
	}
	if a.cfg.NoReport {
		p["no_report"] = true
	}
	return p
}

// ptr does a best-effort reverse DNS lookup, returning the first name or "".
func ptr(ctx context.Context, ip string) string {
	c, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(c, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimRight(names[0], ".")
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
