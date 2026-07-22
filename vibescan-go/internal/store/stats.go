package store

import (
	"context"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/vibescan/vibescan-go/internal/geo"
)

// Stats is the aggregate snapshot returned by the /api/v2/stats endpoint. All
// figures are computed over the requested time window (see StatsAggregate).
type Stats struct {
	TimeRangeHours      int            `json:"time_range_hours"`
	Totals              StatsTotals    `json:"totals"`
	ServicesByPort      map[string]int `json:"services_by_port"`
	StatusCodeCounts    map[string]int `json:"status_code_counts"`
	SecureCaptureCounts map[string]int `json:"secure_capture_counts"`
	TopBanners          map[string]int `json:"top_banners"`
	SubmissionsByClient map[string]int `json:"submissions_by_client"`
	SubmissionsOverTime map[string]int `json:"submissions_over_time"`
}

// StatsTotals holds the headline counts.
type StatsTotals struct {
	Hosts    int `json:"hosts"`
	Services int `json:"services"`
}

// facetResult decodes the single $facet document produced by the pipeline.
type facetResult struct {
	Ports   []kv         `bson:"ports"`
	Status  []statusRow  `bson:"status"`
	Secure  []securedRow `bson:"secure"`
	Banners []kv         `bson:"banners"`
	Hosts   []countOnly  `bson:"hosts"`
	Clients []kvStr      `bson:"clients"`
	Times   []timeRow    `bson:"times"`
	Total   []countOnly  `bson:"total"`
}

type kv struct {
	ID    string `bson:"_id"`
	Count int    `bson:"count"`
}
type kvStr struct {
	ID    string `bson:"_id"`
	Count int    `bson:"count"`
}
type statusRow struct {
	Class string `bson:"_id"` // "200" | "3xx" | "4xx" | "5xx" | "other"
	Count int    `bson:"count"`
}
type securedRow struct {
	Secured bool `bson:"_id"`
	Count   int  `bson:"count"`
}
type countOnly struct {
	Count int `bson:"count"`
}
type timeRow struct {
	Bucket time.Time `bson:"_id"`
	Count  int       `bson:"count"`
}

type statsCache struct {
	mu   sync.Mutex
	at   time.Time
	data map[int]Stats
}

var statsMemo = &statsCache{data: map[int]Stats{}}

const statsTTL = 60 * time.Second

// StatsAggregate computes windowed stats over the last timeRangeHours hours in a
// single $facet pass, with a short in-process cache. The shapes mirror the
// Python /stats composite (services_by_port, status_code_counts, etc.).
func (m *Mongo) StatsAggregate(ctx context.Context, timeRangeHours, maxTimeMS int) (Stats, error) {
	statsMemo.mu.Lock()
	if cached, ok := statsMemo.data[timeRangeHours]; ok && time.Since(statsMemo.at) < statsTTL {
		statsMemo.mu.Unlock()
		return cached, nil
	}
	statsMemo.mu.Unlock()

	cutoff := time.Now().UTC().Add(-time.Duration(timeRangeHours) * time.Hour)
	match := bson.D{{Key: "updated_at", Value: bson.D{{Key: "$gte", Value: cutoff}}}}

	// Bucket submissions by 5 minutes for the 1h view, else hourly.
	timeUnit, binSize := "hour", 1
	if timeRangeHours <= 1 {
		timeUnit, binSize = "minute", 5
	}

	// Banner cleaning mirrors stats.py: split on "extrainfo:", strip "product: ",
	// trim, drop empties.
	bannerClean := bson.A{
		bson.D{{Key: "$match", Value: bson.D{{Key: "banner", Value: bson.D{{Key: "$type", Value: "string"}, {Key: "$ne", Value: ""}}}}}},
		bson.D{{Key: "$project", Value: bson.D{{Key: "b", Value: bson.D{{Key: "$arrayElemAt", Value: bson.A{
			bson.D{{Key: "$split", Value: bson.A{"$banner", "extrainfo:"}}}, 0,
		}}}}}}},
		bson.D{{Key: "$project", Value: bson.D{{Key: "b", Value: bson.D{{Key: "$cond", Value: bson.D{
			{Key: "if", Value: bson.D{{Key: "$eq", Value: bson.A{bson.D{{Key: "$indexOfCP", Value: bson.A{"$b", "product: "}}}, 0}}}},
			{Key: "then", Value: bson.D{{Key: "$substrCP", Value: bson.A{"$b", 9, bson.D{{Key: "$strLenCP", Value: "$b"}}}}}},
			{Key: "else", Value: "$b"},
		}}}}}}},
		bson.D{{Key: "$project", Value: bson.D{{Key: "b", Value: bson.D{{Key: "$trim", Value: bson.D{{Key: "input", Value: "$b"}}}}}}}},
		bson.D{{Key: "$match", Value: bson.D{{Key: "b", Value: bson.D{{Key: "$ne", Value: ""}}}}}},
		bson.D{{Key: "$group", Value: bson.D{{Key: "_id", Value: "$b"}, {Key: "count", Value: bson.D{{Key: "$sum", Value: 1}}}}}},
		bson.D{{Key: "$sort", Value: bson.D{{Key: "count", Value: -1}}}},
		bson.D{{Key: "$limit", Value: 25}},
	}

	statusExpr := bson.D{{Key: "$switch", Value: bson.D{
		{Key: "branches", Value: bson.A{
			bson.D{{Key: "case", Value: bson.D{{Key: "$eq", Value: bson.A{"$http_status", 200}}}}, {Key: "then", Value: "200"}},
			bson.D{{Key: "case", Value: bson.D{{Key: "$and", Value: bson.A{
				bson.D{{Key: "$gte", Value: bson.A{"$http_status", 300}}}, bson.D{{Key: "$lt", Value: bson.A{"$http_status", 400}}},
			}}}}, {Key: "then", Value: "3xx"}},
			bson.D{{Key: "case", Value: bson.D{{Key: "$and", Value: bson.A{
				bson.D{{Key: "$gte", Value: bson.A{"$http_status", 400}}}, bson.D{{Key: "$lt", Value: bson.A{"$http_status", 500}}},
			}}}}, {Key: "then", Value: "4xx"}},
			bson.D{{Key: "case", Value: bson.D{{Key: "$and", Value: bson.A{
				bson.D{{Key: "$gte", Value: bson.A{"$http_status", 500}}}, bson.D{{Key: "$lt", Value: bson.A{"$http_status", 600}}},
			}}}}, {Key: "then", Value: "5xx"}},
		}},
		{Key: "default", Value: "other"},
	}}}

	facet := bson.D{
		{Key: "ports", Value: bson.A{
			bson.D{{Key: "$match", Value: bson.D{{Key: "port", Value: bson.D{{Key: "$exists", Value: true}}}}}},
			bson.D{{Key: "$group", Value: bson.D{{Key: "_id", Value: bson.D{{Key: "$toString", Value: "$port"}}}, {Key: "count", Value: bson.D{{Key: "$sum", Value: 1}}}}}},
			bson.D{{Key: "$sort", Value: bson.D{{Key: "count", Value: -1}}}},
			bson.D{{Key: "$limit", Value: 100}},
		}},
		{Key: "status", Value: bson.A{
			bson.D{{Key: "$match", Value: bson.D{{Key: "http_status", Value: bson.D{{Key: "$type", Value: "number"}}}}}},
			bson.D{{Key: "$group", Value: bson.D{{Key: "_id", Value: statusExpr}, {Key: "count", Value: bson.D{{Key: "$sum", Value: 1}}}}}},
		}},
		{Key: "secure", Value: bson.A{
			bson.D{{Key: "$group", Value: bson.D{{Key: "_id", Value: bson.D{{Key: "$eq", Value: bson.A{"$secured", true}}}}, {Key: "count", Value: bson.D{{Key: "$sum", Value: 1}}}}}},
		}},
		{Key: "banners", Value: bannerClean},
		{Key: "hosts", Value: bson.A{
			bson.D{{Key: "$group", Value: bson.D{{Key: "_id", Value: "$ip"}}}},
			bson.D{{Key: "$count", Value: "count"}},
		}},
		{Key: "clients", Value: bson.A{
			bson.D{{Key: "$match", Value: bson.D{
				{Key: "anon", Value: bson.D{{Key: "$ne", Value: true}}},
				{Key: "submitted_by", Value: bson.D{{Key: "$ne", Value: "0.0.0.0"}}},
			}}},
			bson.D{{Key: "$group", Value: bson.D{{Key: "_id", Value: "$submitted_by"}, {Key: "count", Value: bson.D{{Key: "$sum", Value: 1}}}}}},
			bson.D{{Key: "$sort", Value: bson.D{{Key: "count", Value: -1}}}},
			bson.D{{Key: "$limit", Value: 50}},
		}},
		{Key: "times", Value: bson.A{
			bson.D{{Key: "$group", Value: bson.D{
				{Key: "_id", Value: bson.D{{Key: "$dateTrunc", Value: bson.D{
					{Key: "date", Value: "$updated_at"}, {Key: "unit", Value: timeUnit}, {Key: "binSize", Value: binSize},
				}}}},
				{Key: "count", Value: bson.D{{Key: "$sum", Value: 1}}},
			}}},
			bson.D{{Key: "$sort", Value: bson.D{{Key: "_id", Value: 1}}}},
		}},
		{Key: "total", Value: bson.A{
			bson.D{{Key: "$count", Value: "count"}},
		}},
	}

	pipeline := mongo.Pipeline{
		bson.D{{Key: "$match", Value: match}},
		bson.D{{Key: "$facet", Value: facet}},
	}

	opts := options.Aggregate().SetAllowDiskUse(true)
	if maxTimeMS > 0 {
		opts.SetMaxTime(time.Duration(maxTimeMS) * time.Millisecond)
	}
	cur, err := m.results.Aggregate(ctx, pipeline, opts)
	if err != nil {
		return Stats{}, err
	}
	defer cur.Close(ctx)

	var rows []facetResult
	if err := cur.All(ctx, &rows); err != nil {
		return Stats{}, err
	}

	out := Stats{
		TimeRangeHours:      timeRangeHours,
		ServicesByPort:      map[string]int{},
		StatusCodeCounts:    map[string]int{"200": 0, "3xx": 0, "4xx": 0, "5xx": 0},
		SecureCaptureCounts: map[string]int{"secured": 0, "insecure": 0},
		TopBanners:          map[string]int{},
		SubmissionsByClient: map[string]int{},
		SubmissionsOverTime: map[string]int{},
	}
	if len(rows) == 1 {
		f := rows[0]
		for _, p := range f.Ports {
			out.ServicesByPort[p.ID] = p.Count
		}
		for _, s := range f.Status {
			if _, ok := out.StatusCodeCounts[s.Class]; ok {
				out.StatusCodeCounts[s.Class] += s.Count
			}
		}
		for _, s := range f.Banners {
			out.TopBanners[s.ID] = s.Count
		}
		for _, s := range f.Secure {
			if s.Secured {
				out.SecureCaptureCounts["secured"] += s.Count
			} else {
				out.SecureCaptureCounts["insecure"] += s.Count
			}
		}
		for _, c := range f.Clients {
			key := geo.AnonymizeIP(c.ID)
			if c.ID == "" {
				key = "unknown"
			}
			out.SubmissionsByClient[key] += c.Count
		}
		for _, t := range f.Times {
			out.SubmissionsOverTime[formatBucket(t.Bucket, timeRangeHours)] = t.Count
		}
		if len(f.Hosts) == 1 {
			out.Totals.Hosts = f.Hosts[0].Count
		}
		if len(f.Total) == 1 {
			out.Totals.Services = f.Total[0].Count
		}
	}

	statsMemo.mu.Lock()
	statsMemo.data[timeRangeHours] = out
	statsMemo.at = time.Now()
	statsMemo.mu.Unlock()

	return out, nil
}

func formatBucket(t time.Time, timeRangeHours int) string {
	if timeRangeHours <= 1 {
		return t.UTC().Format("2006-01-02 15:04")
	}
	return t.UTC().Format("2006-01-02 15:00")
}
