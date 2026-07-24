package store

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/vibescan/vibescan-go/internal/enrich"
)

// enrichmentDoc is the durable cache row: the enrichment record plus the integer
// IP key it's stored under.
type enrichmentDoc struct {
	IPInt         int64 `bson:"ip_int"`
	enrich.Record `bson:",inline"`
}

// ReadEnrichment implements enrich.Cache.
func (m *Mongo) ReadEnrichment(ctx context.Context, ipInt int64) (enrich.Record, bool, error) {
	if m == nil || m.enrichment == nil {
		return enrich.Record{}, false, nil
	}
	var doc enrichmentDoc
	err := m.enrichment.FindOne(ctx, bson.M{"ip_int": ipInt}).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		return enrich.Record{}, false, nil
	}
	if err != nil {
		return enrich.Record{}, false, err
	}
	return doc.Record, true, nil
}

// UpsertEnrichment implements enrich.Cache.
func (m *Mongo) UpsertEnrichment(ctx context.Context, ipInt int64, rec enrich.Record) error {
	if m == nil || m.enrichment == nil {
		return nil
	}
	_, err := m.enrichment.UpdateOne(ctx,
		bson.M{"ip_int": ipInt},
		bson.M{"$set": enrichmentDoc{IPInt: ipInt, Record: rec}},
		options.Update().SetUpsert(true),
	)
	return err
}

// RecentUnenrichedIPs returns up to limit recent captured IP strings whose result
// docs carry no fresh `enriched_at` (missing or older than staleBefore), newest
// first — the worker's queue.
func (m *Mongo) RecentUnenrichedIPs(ctx context.Context, limit int, staleBefore time.Time) ([]string, error) {
	if m == nil || m.results == nil {
		return nil, nil
	}
	pipeline := mongo.Pipeline{
		bson.D{{Key: "$match", Value: bson.D{{Key: "$or", Value: bson.A{
			bson.D{{Key: "enriched_at", Value: bson.D{{Key: "$exists", Value: false}}}},
			bson.D{{Key: "enriched_at", Value: bson.D{{Key: "$lt", Value: staleBefore}}}},
		}}}}},
		bson.D{{Key: "$sort", Value: bson.D{{Key: "updated_at", Value: -1}}}},
		bson.D{{Key: "$group", Value: bson.D{
			{Key: "_id", Value: "$ip"},
			{Key: "ip_str", Value: bson.D{{Key: "$first", Value: "$ip_str"}}},
			{Key: "updated_at", Value: bson.D{{Key: "$first", Value: "$updated_at"}}},
		}}},
		bson.D{{Key: "$sort", Value: bson.D{{Key: "updated_at", Value: -1}}}},
		bson.D{{Key: "$limit", Value: limit}},
	}
	cur, err := m.results.Aggregate(ctx, pipeline, options.Aggregate().SetAllowDiskUse(true))
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)
	var rows []struct {
		IPStr string `bson:"ip_str"`
	}
	if err := cur.All(ctx, &rows); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		if r.IPStr != "" {
			out = append(out, r.IPStr)
		}
	}
	return out, nil
}

// DenormalizeEnrichment writes a light enrichment summary onto every result doc
// for an IP so tiles/search can use it without a join. Always stamps enriched_at
// (even for an empty record) so the worker doesn't retry it before the TTL.
func (m *Mongo) DenormalizeEnrichment(ctx context.Context, ipInt int64, rec enrich.Record) error {
	if m == nil || m.results == nil {
		return nil
	}
	tags := rec.Tags
	if tags == nil {
		tags = []string{}
	}
	ports := rec.Ports
	if ports == nil {
		ports = []int{}
	}
	sources := rec.Sources
	if sources == nil {
		sources = []string{}
	}
	_, err := m.results.UpdateMany(ctx,
		bson.M{"ip": ipInt},
		bson.M{"$set": bson.M{
			"vuln_count":     len(rec.Vulns),
			"shodan_tags":    tags,
			"extra_ports":    ports,
			"verdict":        rec.Verdict, // "" for keyless/worker; set on the deep path
			"enrich_sources": sources,     // which feeds contributed (internetdb, shodan, …)
			"enriched_at":    time.Now().UTC(),
		}},
	)
	return err
}
