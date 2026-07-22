// Command migrate creates the MongoDB indexes required by the v2 read APIs.
// It is idempotent and safe to re-run. Configuration comes from the same
// environment/.env as the collector.
package main

import (
	"context"
	"log"
	"time"

	"github.com/vibescan/vibescan-go/internal/config"
	"github.com/vibescan/vibescan-go/internal/store"
)

func main() {
	cfg := config.Load()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	mongoStore, err := store.Connect(ctx, cfg)
	if err != nil {
		log.Fatalf("[migrate] MongoDB connection failed: %v", err)
	}
	defer mongoStore.Disconnect(context.Background())

	log.Printf("[migrate] creating indexes on %s.%s …", cfg.MongoDB, cfg.ResultsCollection)
	if err := mongoStore.EnsureIndexes(ctx); err != nil {
		log.Fatalf("[migrate] index creation failed: %v", err)
	}
	if err := mongoStore.SeedBlacklist(ctx); err != nil {
		log.Printf("[migrate] blacklist seed skipped: %v", err)
	}
	log.Printf("[migrate] done")
}
