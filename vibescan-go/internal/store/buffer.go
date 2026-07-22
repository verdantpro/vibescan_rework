package store

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"time"

	"go.mongodb.org/mongo-driver/bson"
)

// Buffer durably spools upserts to disk when MongoDB writes fail, and flushes
// them back once the database recovers. It mirrors the resilience behavior of
// server.py's buffered-results queue, using BSON files to preserve BSON types
// (dates, etc.) exactly.
type Buffer struct {
	dir      string
	mongo    *Mongo
	interval time.Duration
	debug    bool
}

type bufferFile struct {
	Ops []UpsertOp `bson:"ops"`
}

// NewBuffer creates the spool directory and returns a Buffer.
func NewBuffer(dir string, m *Mongo, interval time.Duration, debug bool) (*Buffer, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &Buffer{dir: dir, mongo: m, interval: interval, debug: debug}, nil
}

// Persist writes ops to a new atomically-created BSON spool file.
func (b *Buffer) Persist(ops []UpsertOp) error {
	if len(ops) == 0 {
		return nil
	}
	data, err := bson.Marshal(bufferFile{Ops: ops})
	if err != nil {
		return err
	}
	name := fmt.Sprintf("%d_%d.bson", time.Now().UnixMilli(), os.Getpid())
	path := filepath.Join(b.dir, name)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Run flushes spooled files back to MongoDB on an interval until ctx is done.
func (b *Buffer) Run(ctx context.Context) {
	ticker := time.NewTicker(b.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			b.flushOnce(ctx)
		}
	}
}

func (b *Buffer) flushOnce(ctx context.Context) {
	if !b.mongo.Available() {
		return
	}
	files := b.listFiles()
	if len(files) == 0 {
		return
	}
	path := files[0]

	data, err := os.ReadFile(path)
	if err != nil {
		_ = os.Rename(path, path+".bad")
		return
	}
	var bf bufferFile
	if err := bson.Unmarshal(data, &bf); err != nil {
		_ = os.Rename(path, path+".bad")
		return
	}
	if len(bf.Ops) == 0 {
		_ = os.Remove(path)
		return
	}

	failed, err := b.mongo.BulkUpsert(ctx, bf.Ops)
	if err == nil {
		_ = os.Remove(path)
		if b.debug {
			log.Printf("[buffer] flushed %d ops from %s", len(bf.Ops), filepath.Base(path))
		}
		return
	}

	// Keep only the ops that failed; drop the rest.
	if len(failed) > 0 {
		remaining := make([]UpsertOp, 0, len(failed))
		for i, op := range bf.Ops {
			if failed[i] {
				remaining = append(remaining, op)
			}
		}
		if newData, mErr := bson.Marshal(bufferFile{Ops: remaining}); mErr == nil {
			tmp := path + ".tmp"
			if os.WriteFile(tmp, newData, 0o644) == nil {
				_ = os.Rename(tmp, path)
			}
		}
	}
	if b.debug {
		log.Printf("[buffer] partial flush from %s: %d ops kept", filepath.Base(path), len(failed))
	}
}

func (b *Buffer) listFiles() []string {
	entries, err := os.ReadDir(b.dir)
	if err != nil {
		return nil
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".bson" {
			files = append(files, filepath.Join(b.dir, e.Name()))
		}
	}
	sort.Strings(files)
	return files
}
