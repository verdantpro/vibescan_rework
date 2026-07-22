// Command collector is the VibeScan ingest server, a Go reimplementation of
// the FastAPI collector in vibescan_v2/server.py. It accepts signed, compressed
// v1 agent submissions, enriches them, and persists per-service documents to
// MongoDB (buffering to disk when the database is unavailable).
package main

import (
	"context"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/vibescan/vibescan-go/internal/collector"
	"github.com/vibescan/vibescan-go/internal/config"
	"github.com/vibescan/vibescan-go/internal/geo"
	"github.com/vibescan/vibescan-go/internal/httpapi"
	"github.com/vibescan/vibescan-go/internal/store"
)

func main() {
	cfg := config.Load()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// MongoDB is optional at startup: if it's down, we still serve and buffer.
	mongoStore, err := store.Connect(ctx, cfg)
	if err != nil {
		log.Printf("[collector] MongoDB unavailable at startup (%v); buffering writes to disk", err)
	}
	defer mongoStore.Disconnect(context.Background())

	// Seed the CIDR blacklist and ensure indexes in the background so startup
	// never blocks on Mongo.
	go func() {
		if err := mongoStore.SeedBlacklist(context.Background()); err != nil && cfg.Debug {
			log.Printf("[collector] blacklist seed skipped: %v", err)
		}
		if err := mongoStore.EnsureIndexes(context.Background()); err != nil && cfg.Debug {
			log.Printf("[collector] index creation skipped: %v", err)
		}
	}()

	r2, err := store.NewR2(cfg)
	if err != nil {
		log.Printf("[collector] R2 disabled: %v", err)
	}
	if cfg.R2Enabled && r2 != nil {
		log.Printf("[collector] R2 enabled (bucket %s)", cfg.R2Bucket)
	}

	geoResolver := geo.NewResolver(cfg.GeoIPPath)

	buffer, err := store.NewBuffer(cfg.BufferDir, mongoStore, 15*time.Second, cfg.Debug)
	if err != nil {
		log.Fatalf("[collector] cannot create buffer dir %s: %v", cfg.BufferDir, err)
	}
	go buffer.Run(ctx)

	ingestor := collector.NewIngestor(cfg, mongoStore, r2, geoResolver, buffer)
	blacklist := collector.NewBlacklistCache(mongoStore)
	srv := httpapi.NewServer(cfg, ingestor, blacklist, mongoStore)

	httpServer := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("[collector] listening on %s", cfg.Addr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[collector] server error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Printf("[collector] shutting down")
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(shutCtx)
}
