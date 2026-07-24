package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func get(t *testing.T, h http.Handler, path string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Result()
}

func TestServesRobotsTxt(t *testing.T) {
	res := get(t, Handler(), "/robots.txt")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("content-type = %q, want text/plain", ct)
	}
}

func TestSitemapAndManifestHaveCorrectContentType(t *testing.T) {
	// These ship in the embedded dist; they must be served with an explicit
	// non-HTML content type — never the SPA index.html shell.
	cases := []struct{ path, wantCT string }{
		{"/sitemap.xml", "application/xml"},
		{"/manifest.webmanifest", "application/manifest+json"},
	}
	h := Handler()
	for _, c := range cases {
		res := get(t, h, c.path)
		if res.StatusCode != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", c.path, res.StatusCode)
			continue
		}
		if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, c.wantCT) {
			t.Errorf("%s: content-type = %q, want %q", c.path, ct, c.wantCT)
		}
	}
}

func TestUnknownRouteFallsBackToSPA(t *testing.T) {
	// Client-side routes must resolve to index.html (HTML) on a hard refresh.
	res := get(t, Handler(), "/some/client/route")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content-type = %q, want text/html (SPA shell)", ct)
	}
}
