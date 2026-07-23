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
	return m.ensureTextIndex(ctx)
}

// textIndexWeights defines the single free-text search index the /api/v2/search
// endpoint relies on. Weights bias matches toward short identifying fields
// (product banner, cert CN, geo city/country) over bulk page text. Geo fields
// live in the geoip subdocument, so a query like "shanghai" or "china" — which
// comes from GeoIP, not the banner — matches here.
var textIndexWeights = bson.D{
	{Key: "banner", Value: 10},
	{Key: "geoip.city", Value: 9},
	{Key: "cert_cn", Value: 8},
	{Key: "geoip.country", Value: 6},
	{Key: "geoip.country_iso", Value: 6},
	{Key: "geoip.region", Value: 5},
	{Key: "whois", Value: 5},
	{Key: "rdns", Value: 4},
	{Key: "fulltext", Value: 1},
}

func textIndexModel() mongo.IndexModel {
	keys := bson.D{}
	for _, w := range textIndexWeights {
		keys = append(keys, bson.E{Key: w.Key, Value: "text"})
	}
	return mongo.IndexModel{
		Keys:    keys,
		Options: options.Index().SetName("idx_text_search").SetWeights(textIndexWeights),
	}
}

// ensureTextIndex creates (or updates) the collection's single text index.
// MongoDB allows only one text index per collection and rejects a differing spec
// under the same name, so when the field set/weights change (e.g. adding geo
// fields) we drop the existing text index and recreate it — but only then, so a
// normal startup never rebuilds it.
func (m *Mongo) ensureTextIndex(ctx context.Context) error {
	cur, err := m.results.Indexes().List(ctx)
	if err != nil {
		return err
	}
	var existing []bson.M
	if err := cur.All(ctx, &existing); err != nil {
		return err
	}

	desired := map[string]int{}
	for _, w := range textIndexWeights {
		desired[w.Key] = w.Value.(int)
	}

	for _, idx := range existing {
		weights, ok := idx["weights"].(bson.M) // only a text index has "weights"
		if !ok {
			continue
		}
		if textWeightsEqual(weights, desired) {
			return nil // already current — don't rebuild
		}
		// A text index exists but with a different field set/weights; drop it so
		// we can recreate (only one text index is permitted per collection).
		if name, _ := idx["name"].(string); name != "" {
			if _, err := m.results.Indexes().DropOne(ctx, name); err != nil {
				return err
			}
		}
		break
	}
	_, err = m.results.Indexes().CreateOne(ctx, textIndexModel())
	return err
}

func textWeightsEqual(got bson.M, want map[string]int) bool {
	if len(got) != len(want) {
		return false
	}
	for k, v := range want {
		gv, ok := got[k]
		if !ok || toInt(gv) != v {
			return false
		}
	}
	return true
}

// toInt normalizes the numeric types the driver may decode index weights into.
func toInt(v any) int {
	switch n := v.(type) {
	case int32:
		return int(n)
	case int64:
		return int(n)
	case int:
		return n
	case float64:
		return int(n)
	default:
		return -1
	}
}
