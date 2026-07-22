package scanner

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vibescan/vibescan-go/internal/media"
)

func testTarget(t *testing.T) (host string, port int, closeFn func()) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><head><title>T</title></head>
			<body><h1>exposed</h1><p>vibescan agent e2e</p><img src=x></body></html>`))
	})
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("icon")) })
	srv := httptest.NewServer(mux)
	u, _ := url.Parse(srv.URL)
	p, _ := strconv.Atoi(u.Port())
	return "127.0.0.1", p, srv.Close
}

func newTestAgent(t *testing.T, serverURL string) (*Agent, func()) {
	t.Helper()
	br := NewBrowser(1, 400*time.Millisecond)
	cfg := Config{ServerURL: serverURL, SharedKey: "vibescan-default-key", CaptureHTTP: true, ScanThreads: 1}
	return NewAgent(cfg, NewBlacklist(nil), br), br.Close
}

// TestBuildHostRecord captures a real page and checks the assembled record:
// screenshot present with a recoverable stego payload, status, phash, dom_hash.
func TestBuildHostRecord(t *testing.T) {
	if testing.Short() {
		t.Skip("browser test")
	}
	host, port, closeTarget := testTarget(t)
	defer closeTarget()
	agent, closeBrowser := newTestAgent(t, "http://unused")
	defer closeBrowser()

	rec := agent.buildHostRecord(context.Background(), host, map[int]string{port: "product: nginx"})
	if rec == nil {
		t.Fatal("nil record (capture failed?)")
	}
	svc := rec["services"].(map[string]any)[strconv.Itoa(port)].(map[string]any)

	capB64, _ := svc["capture"].(string)
	if capB64 == "" {
		t.Fatal("no capture in record")
	}
	raw, err := base64.StdEncoding.DecodeString(capB64)
	if err != nil {
		t.Fatalf("capture not base64: %v", err)
	}
	stego := media.ExtractStego(raw)
	if !strings.Contains(stego, "url:http://127.0.0.1:") {
		t.Errorf("stego payload missing url: %q", stego)
	}
	if st, _ := svc["http_status"].(*int); st == nil || *st != 200 {
		t.Errorf("http_status = %v, want 200", svc["http_status"])
	}
	if ph, _ := svc["screenshot_phash"].(string); len(ph) != 16 {
		t.Errorf("screenshot_phash = %q", svc["screenshot_phash"])
	}
	if _, ok := svc["dom_hash"]; !ok {
		t.Error("expected dom_hash from fulltext")
	}
	if ft, _ := svc["fulltext"].(string); !strings.Contains(ft, "vibescan agent e2e") {
		t.Errorf("fulltext missing content")
	}
}

// TestAgentSubmitLive submits a real captured record to a live collector.
// Set VIBESCAN_TEST_COLLECTOR=http://127.0.0.1:8099 (default shared key) to run.
func TestAgentSubmitLive(t *testing.T) {
	base := os.Getenv("VIBESCAN_TEST_COLLECTOR")
	if base == "" {
		t.Skip("set VIBESCAN_TEST_COLLECTOR to run the live submit test")
	}
	host, port, closeTarget := testTarget(t)
	defer closeTarget()
	agent, closeBrowser := newTestAgent(t, base)
	defer closeBrowser()

	rec := agent.buildHostRecord(context.Background(), host, map[int]string{port: "product: nginx"})
	if rec == nil {
		t.Fatal("nil record")
	}
	summary, err := agent.client.Submit(context.Background(), agent.buildPayload([]map[string]any{rec}))
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	t.Logf("collector response: %v", summary)
	if stored, _ := summary["stored"].(float64); stored < 1 {
		t.Errorf("expected stored>=1, got %v", summary["stored"])
	}
}
