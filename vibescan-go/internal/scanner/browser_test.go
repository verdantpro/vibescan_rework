package scanner

import (
	"bytes"
	"context"
	"encoding/base64"
	"image"
	_ "image/png"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestBrowserCapture drives a real headless Chromium against a local server and
// verifies the full capture surface. Skips if Chromium can't launch.
func TestBrowserCapture(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in -short mode")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`<!doctype html><html><head><title>Hi</title></head>
			<body style="background:#4285f4"><h1>hello</h1><p>vibescan test</p></body></html>`))
	})
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("\x00\x00\x01\x00favicon-bytes"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())

	b := NewBrowser(1, 400*time.Millisecond)
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	c := b.Capture(ctx, "127.0.0.1", port)
	if c.Err != "" {
		t.Fatalf("capture error (Chromium available?): %s", c.Err)
	}
	if c.Status == nil || *c.Status != 200 {
		t.Errorf("status = %v, want 200", c.Status)
	}
	if c.Secured {
		t.Error("http server should not be marked secured")
	}
	if !strings.Contains(c.Fulltext, "vibescan test") {
		t.Errorf("fulltext missing page content: %.80q", c.Fulltext)
	}
	if len(c.Phash) != 16 {
		t.Errorf("phash = %q, want 16 hex chars", c.Phash)
	}
	if c.FaviconHash == "" {
		t.Error("expected a favicon hash")
	}
	png, err := base64.StdEncoding.DecodeString(c.PNGBase64)
	if err != nil {
		t.Fatalf("PNG not base64: %v", err)
	}
	cfg, _, err := image.DecodeConfig(bytes.NewReader(png))
	if err != nil {
		t.Fatalf("screenshot not a valid image: %v", err)
	}
	if cfg.Width == 0 || cfg.Height == 0 {
		t.Errorf("screenshot has zero dimension: %dx%d", cfg.Width, cfg.Height)
	}
	t.Logf("captured %dx%d PNG, status=%d, phash=%s, favicon=%s",
		cfg.Width, cfg.Height, *c.Status, c.Phash, c.FaviconHash)
}
