// Command agent is the VibeScan scanner: it generates random IPv4 targets,
// discovers HTTP services with nmap, screenshots them with headless Chromium,
// and submits signed results to the collector. A Go port of client_agent.py.
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/vibescan/vibescan-go/internal/config"
	"github.com/vibescan/vibescan-go/internal/scanner"
	"github.com/vibescan/vibescan-go/internal/store"
)

func main() {
	config.LoadDotenv(".env")

	serverURL := strings.TrimRight(env("VIBESCAN_SERVER_URL", ""), "/")
	if serverURL == "" {
		log.Fatal("VIBESCAN_SERVER_URL is required (the collector base URL, e.g. https://vibescan.example.com)")
	}

	cfg := scanner.Config{
		ServerURL:          serverURL,
		SharedKey:          env("VIBESCAN_SHARED_KEY", "vibescan-default-key"),
		Ports:              splitCSV(env("VIBESCAN_PORTS", "80,8080,8000")),
		ScanThreads:        atoi(env("VIBESCAN_SCAN_THREADS", "2"), 2),
		BatchSize:          atoi(env("VIBESCAN_BATCH_SIZE", "10"), 10),
		NmapOptions:        env("VIBESCAN_NMAP_OPTIONS", "-n -T3"),
		CaptureDelay:       time.Duration(atof(env("VIBESCAN_CAPTURE_DELAY", "2.0"), 2.0) * float64(time.Second)),
		CaptureHTTP:        envBool("VIBESCAN_CAPTURE_HTTP", true),
		NoReport:           envBool("VIBESCAN_NO_REPORT", false),
		BrowserConcurrency: atoi(env("VIBESCAN_BROWSER_CONCURRENCY", "2"), 2),
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Seed the blacklist so the first batch is safe even before the server responds.
	bl := scanner.NewBlacklist(store.DefaultBlacklistSeed)

	var browser *scanner.Browser
	if cfg.CaptureHTTP {
		browser = scanner.NewBrowser(cfg.BrowserConcurrency, cfg.CaptureDelay)
		defer browser.Close()
	}

	agent := scanner.NewAgent(cfg, bl, browser)
	log.Printf("[agent] starting — server=%s ports=%v threads=%d batch=%d capture=%v",
		cfg.ServerURL, cfg.Ports, cfg.ScanThreads, cfg.BatchSize, cfg.CaptureHTTP)

	agent.Run(ctx)
	log.Printf("[agent] stopped")
}

func env(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func envBool(k string, def bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(k)))
	if v == "" {
		return def
	}
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func atoi(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}

func atof(s string, def float64) float64 {
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f
	}
	return def
}
