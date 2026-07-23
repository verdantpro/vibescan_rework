package enrich

import (
	"context"
	"log"
	"time"

	"github.com/vibescan/vibescan-go/internal/geo"
)

// WorkerStore is the store surface the background worker needs.
type WorkerStore interface {
	Available() bool
	RecentUnenrichedIPs(ctx context.Context, limit int, staleBefore time.Time) ([]string, error)
	DenormalizeEnrichment(ctx context.Context, ipInt int64, rec Record) error
}

// Worker keeps recently-captured hosts enriched using InternetDB only (free), so
// vuln/tag badges, search filters, and stats cover the whole census without
// spending Shodan query credits. Pacing comes from the Enricher's shared outbound
// limiter, so the loop is naturally throttled.
type Worker struct {
	enricher *Enricher
	store    WorkerStore
	ttl      time.Duration
	batch    int
	debug    bool
}

// NewWorker builds the background enrichment worker.
func NewWorker(e *Enricher, store WorkerStore, ttl time.Duration, batch int, debug bool) *Worker {
	if batch <= 0 {
		batch = 20
	}
	if ttl <= 0 {
		ttl = 168 * time.Hour
	}
	return &Worker{enricher: e, store: store, ttl: ttl, batch: batch, debug: debug}
}

// Run processes batches until ctx is cancelled, idling longer when the queue is
// empty.
func (w *Worker) Run(ctx context.Context) {
	timer := time.NewTimer(15 * time.Second) // let startup settle first
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		n := w.tick(ctx)
		next := 20 * time.Second
		if n == 0 {
			next = 90 * time.Second
		}
		timer.Reset(next)
	}
}

func (w *Worker) tick(ctx context.Context) int {
	if w.store == nil || !w.store.Available() {
		return 0
	}
	ips, err := w.store.RecentUnenrichedIPs(ctx, w.batch, time.Now().Add(-w.ttl))
	if err != nil {
		if w.debug {
			log.Printf("[enrich] worker queue error: %v", err)
		}
		return 0
	}
	done := 0
	for _, ip := range ips {
		select {
		case <-ctx.Done():
			return done
		default:
		}
		rec, err := w.enricher.Get(ctx, ip, false) // InternetDB only; throttled
		if err != nil {
			continue
		}
		if ipInt, ok := geo.IPStrToInt(ip); ok {
			_ = w.store.DenormalizeEnrichment(ctx, ipInt, rec)
			done++
		}
	}
	if w.debug && done > 0 {
		log.Printf("[enrich] worker enriched %d hosts", done)
	}
	return done
}
