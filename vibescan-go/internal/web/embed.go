// Package web embeds the built single-page UI and serves it with client-side
// routing support. The dist/ directory is populated by the UI build (see the
// Dockerfile); a placeholder ships in the repo so the module always builds.
package web

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed dist
var distFS embed.FS

//go:embed robots.txt
var robotsTXT []byte

// Handler serves the embedded SPA. Real asset requests are served from dist/;
// any other path falls back to index.html so client routes (/feed, /signal/…)
// resolve on a hard refresh.
func Handler() http.Handler {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		return http.NotFoundHandler()
	}
	fileServer := http.FileServer(http.FS(sub))
	index, _ := fs.ReadFile(sub, "index.html")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Explicit non-SPA endpoints (avoid HTML shell for crawlers). These are
		// served with an explicit Content-Type and a real 404 when absent, so a
		// crawler never receives the SPA index.html in their place.
		switch r.URL.Path {
		case "/robots.txt":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Cache-Control", "public, max-age=3600")
			_, _ = w.Write(robotsTXT)
			return
		case "/sitemap.xml":
			serveDistFile(w, sub, "sitemap.xml", "application/xml; charset=utf-8")
			return
		case "/manifest.webmanifest":
			serveDistFile(w, sub, "manifest.webmanifest", "application/manifest+json; charset=utf-8")
			return
		}

		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if name != "" {
			if info, statErr := fs.Stat(sub, name); statErr == nil && !info.IsDir() {
				// Hashed Vite assets under assets/ are immutable.
				if strings.HasPrefix(name, "assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				}
				fileServer.ServeHTTP(w, r)
				return
			}
		}
		serveIndex(w, index)
	})
}

// serveDistFile serves a build artifact from dist/ with an explicit Content-Type,
// or a real 404 if the UI build did not include it (never the SPA shell).
func serveDistFile(w http.ResponseWriter, sub fs.FS, name, contentType string) {
	b, err := fs.ReadFile(sub, name)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(b)
}

func serveIndex(w http.ResponseWriter, index []byte) {
	if index == nil {
		http.Error(w, "UI not built", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(index)
}
