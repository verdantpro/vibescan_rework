package store

import (
	"context"
	"strings"

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
		// Anchored ip_str prefix search (IP-like queries in /api/v2/search).
		{Keys: bson.D{{Key: "ip_str", Value: 1}}, Options: options.Index().SetName("idx_ip_str")},
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
	if _, err := m.results.Indexes().CreateMany(ctx, models); err != nil {
		return err
	}

	// Free-text search index, created on its own so a pre-existing text index
	// with different fields (e.g. from the legacy Python app) can't block the
	// core indexes above. MongoDB permits only one text index per collection.
	textIdx := mongo.IndexModel{
		Keys: bson.D{
			{Key: "banner", Value: "text"},
			{Key: "whois", Value: "text"},
			{Key: "cert_cn", Value: "text"},
			{Key: "fulltext", Value: "text"},
		},
		Options: options.Index().
			SetName("idx_text_search").
			SetWeights(bson.D{
				{Key: "banner", Value: 10},
				{Key: "cert_cn", Value: 8},
				{Key: "whois", Value: 5},
				{Key: "fulltext", Value: 1},
			}),
	}
	if _, err := m.results.Indexes().CreateOne(ctx, textIdx); err != nil && !isTextIndexConflict(err) {
		return err
	}
	return nil
}

// isTextIndexConflict reports whether err is MongoDB refusing a second/renamed
// text index (code 85 IndexOptionsConflict / 86 IndexKeySpecsConflict, or the
// "already exists with a different name" text). Such a collection already has a
// usable text index, so search still works and startup should not fail.
func isTextIndexConflict(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "text index") ||
		strings.Contains(msg, "indexoptionsconflict") ||
		strings.Contains(msg, "indexkeyspecsconflict") ||
		strings.Contains(msg, "already exists")
}
