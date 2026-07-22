package store

import (
	"context"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// EnsureIndexes creates the indexes the v2 read paths rely on. It mirrors the
// relevant subset of vibescan_v2/tools/apply_indexes.py (results collection
// only; votes/users indexes belong to deferred features). Index creation is
// idempotent, so this is safe to call on every startup.
func (m *Mongo) EnsureIndexes(ctx context.Context) error {
	if m == nil || m.results == nil {
		return mongo.ErrClientDisconnected
	}
	models := []mongo.IndexModel{
		// Gallery/feed sort and stats time-window scans.
		{Keys: bson.D{{Key: "updated_at", Value: -1}}, Options: options.Index().SetName("idx_updated_at")},
		{Keys: bson.D{{Key: "received_at", Value: -1}}, Options: options.Index().SetName("idx_received_at")},
		// Service detail lookups and ingest upsert filter.
		{Keys: bson.D{{Key: "ip", Value: 1}, {Key: "port", Value: 1}}, Options: options.Index().SetName("idx_ip_port")},
		// Deterministic gallery pagination sort key.
		{
			Keys:    bson.D{{Key: "updated_at", Value: 1}, {Key: "received_at", Value: 1}, {Key: "_id", Value: 1}},
			Options: options.Index().SetName("idx_updated_received_id"),
		},
		// Random landing-capture sampling filter.
		{
			Keys: bson.D{
				{Key: "landing_image.secured", Value: 1},
				{Key: "landing_image.http_status", Value: 1},
				{Key: "updated_at", Value: -1},
			},
			Options: options.Index().SetName("idx_landing_pool"),
		},
		// DOM-structure neighbor lookups (sparse: most docs may lack it).
		{Keys: bson.D{{Key: "dom_hash", Value: 1}}, Options: options.Index().SetName("idx_dom_hash").SetSparse(true)},
	}
	_, err := m.results.Indexes().CreateMany(ctx, models)
	return err
}
