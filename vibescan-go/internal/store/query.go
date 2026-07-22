package store

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/vibescan/vibescan-go/internal/geo"
)

// ServiceDoc is the read-side view of a results document. Fulltext is omitted
// from list queries via projection; HasFulltext is populated instead.
type ServiceDoc struct {
	ID              primitive.ObjectID `bson:"_id"`
	IP              int64              `bson:"ip"`
	IPStr           string             `bson:"ip_str"`
	Port            int                `bson:"port"`
	Banner          string             `bson:"banner"`
	Capture         string             `bson:"capture"`
	CaptureHash     string             `bson:"capture_hash"`
	CaptureExt      string             `bson:"capture_ext"`
	HTTPStatus      *int               `bson:"http_status"`
	Secured         bool               `bson:"secured"`
	Whois           string             `bson:"whois"`
	Fulltext        string             `bson:"fulltext"`
	HasFulltext     bool               `bson:"has_fulltext"`
	ScreenshotPhash string             `bson:"screenshot_phash"`
	DomHash         string             `bson:"dom_hash"`
	CertCN          string             `bson:"cert_cn"`
	FaviconHash     string             `bson:"favicon_hash"`
	SubmittedBy     string             `bson:"submitted_by"`
	Anon            bool               `bson:"anon"`
	UpdatedAt       time.Time          `bson:"updated_at"`
	ReceivedAt      time.Time          `bson:"received_at"`
	Timestamp       time.Time          `bson:"timestamp"`
	GeoIP           *geo.GeoIP         `bson:"geoip"`
	LandingImage    *LandingImage      `bson:"landing_image"`
}

// LandingImage mirrors the embedded landing_image sub-document.
type LandingImage struct {
	Port        string `bson:"port" json:"port"`
	CaptureHash string `bson:"capture_hash" json:"capture_hash"`
	CaptureExt  string `bson:"capture_ext" json:"capture_ext"`
	HTTPStatus  int    `bson:"http_status" json:"http_status"`
	Secured     bool   `bson:"secured" json:"secured"`
	Product     string `bson:"product" json:"product"`
}

// ListOpts are shared list/search parameters.
type ListOpts struct {
	Limit       int
	Offset      int
	MaxTimeMS   int
	Query       string // free-text (regex) filter; empty means no text filter
	Port        *int
	Secured     *bool
	StatusCode  *int // exact HTTP status match
	Product     string
	ScreensOnly bool
}

// hasCaptureMatch is the aggregation match ensuring a real (non-error) capture,
// mirroring the gallery query in gallery.py.
var hasCaptureMatch = bson.D{
	{Key: "capture", Value: bson.D{{Key: "$type", Value: "string"}, {Key: "$ne", Value: ""}}},
	{Key: "$expr", Value: bson.D{{Key: "$ne", Value: bson.A{
		bson.D{{Key: "$substrCP", Value: bson.A{bson.D{{Key: "$toLower", Value: "$capture"}}, 0, 16}}},
		"screenshot_error",
	}}}},
}

// listPipeline builds a match/sort/paginate pipeline that excludes the heavy
// fulltext field while surfacing has_fulltext.
func listPipeline(match bson.D, offset, limit int) mongo.Pipeline {
	return mongo.Pipeline{
		bson.D{{Key: "$match", Value: match}},
		bson.D{{Key: "$sort", Value: bson.D{
			{Key: "updated_at", Value: -1},
			{Key: "received_at", Value: -1},
			{Key: "_id", Value: -1},
		}}},
		bson.D{{Key: "$skip", Value: offset}},
		bson.D{{Key: "$limit", Value: limit}},
		bson.D{{Key: "$addFields", Value: bson.D{{Key: "has_fulltext", Value: bson.D{
			{Key: "$gt", Value: bson.A{
				bson.D{{Key: "$strLenCP", Value: bson.D{{Key: "$ifNull", Value: bson.A{"$fulltext", ""}}}}},
				0,
			}},
		}}}}},
		bson.D{{Key: "$project", Value: bson.D{{Key: "fulltext", Value: 0}}}},
	}
}

func (m *Mongo) aggregateDocs(ctx context.Context, pipeline mongo.Pipeline, maxTimeMS int) ([]ServiceDoc, error) {
	opts := options.Aggregate().SetAllowDiskUse(true)
	if maxTimeMS > 0 {
		opts.SetMaxTime(time.Duration(maxTimeMS) * time.Millisecond)
	}
	cur, err := m.results.Aggregate(ctx, pipeline, opts)
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)
	var docs []ServiceDoc
	if err := cur.All(ctx, &docs); err != nil {
		return nil, err
	}
	return docs, nil
}

// Gallery returns the most recent captured services.
func (m *Mongo) Gallery(ctx context.Context, o ListOpts) ([]ServiceDoc, error) {
	match := bson.D{}
	if o.ScreensOnly {
		match = hasCaptureMatch
	}
	return m.aggregateDocs(ctx, listPipeline(match, o.Offset, o.Limit), o.MaxTimeMS)
}

// Search returns services matching a free-text query and/or filters.
func (m *Mongo) Search(ctx context.Context, o ListOpts) ([]ServiceDoc, error) {
	and := bson.A{}
	if o.Query != "" {
		rx := bson.D{{Key: "$regex", Value: o.Query}, {Key: "$options", Value: "i"}}
		and = append(and, bson.D{{Key: "$or", Value: bson.A{
			bson.D{{Key: "banner", Value: rx}},
			bson.D{{Key: "whois", Value: rx}},
			bson.D{{Key: "ip_str", Value: rx}},
			bson.D{{Key: "cert_cn", Value: rx}},
			bson.D{{Key: "fulltext", Value: rx}},
		}}})
	}
	if o.Product != "" {
		and = append(and, bson.D{{Key: "banner", Value: bson.D{
			{Key: "$regex", Value: o.Product}, {Key: "$options", Value: "i"},
		}}})
	}
	if o.Port != nil {
		and = append(and, bson.D{{Key: "port", Value: *o.Port}})
	}
	if o.Secured != nil {
		and = append(and, bson.D{{Key: "secured", Value: *o.Secured}})
	}
	if o.StatusCode != nil {
		and = append(and, bson.D{{Key: "http_status", Value: *o.StatusCode}})
	}
	if o.ScreensOnly {
		and = append(and, bson.D(hasCaptureMatch))
	}

	match := bson.D{}
	if len(and) > 0 {
		match = bson.D{{Key: "$and", Value: and}}
	}
	return m.aggregateDocs(ctx, listPipeline(match, o.Offset, o.Limit), o.MaxTimeMS)
}

// ServiceDetail returns a single service document (including fulltext).
func (m *Mongo) ServiceDetail(ctx context.Context, ipInt int64, port int) (*ServiceDoc, error) {
	var doc ServiceDoc
	err := m.results.FindOne(ctx, bson.M{"ip": ipInt, "port": port}).Decode(&doc)
	if err != nil {
		return nil, err
	}
	doc.HasFulltext = doc.Fulltext != ""
	return &doc, nil
}

// RandomLanding samples one random capture for the live viewport.
// Preference order (same idea as the Python landing pool, with a practical fallback):
//  1. Classic "landing page": insecure HTTP 200 with landing_image set
//  2. Any service that has a real screenshot (HTTPS hits, non-200 pages, early deploys)
func (m *Mongo) RandomLanding(ctx context.Context) (*ServiceDoc, error) {
	prefer := bson.D{
		{Key: "landing_image.secured", Value: false},
		{Key: "landing_image.http_status", Value: 200},
		{Key: "landing_image.capture_hash", Value: bson.D{{Key: "$type", Value: "string"}, {Key: "$ne", Value: ""}}},
	}
	doc, err := m.sampleOne(ctx, prefer)
	if err != nil || doc != nil {
		return doc, err
	}
	// Fallback: any row with a non-empty capture_hash (uploaded or base64 capture).
	return m.sampleOne(ctx, bson.D{
		{Key: "capture_hash", Value: bson.D{{Key: "$type", Value: "string"}, {Key: "$ne", Value: ""}}},
		{Key: "capture", Value: bson.D{{Key: "$type", Value: "string"}, {Key: "$ne", Value: ""}}},
	})
}

func (m *Mongo) sampleOne(ctx context.Context, match bson.D) (*ServiceDoc, error) {
	pipeline := mongo.Pipeline{
		bson.D{{Key: "$match", Value: match}},
		bson.D{{Key: "$sample", Value: bson.D{{Key: "size", Value: 1}}}},
		bson.D{{Key: "$project", Value: bson.D{{Key: "fulltext", Value: 0}}}},
	}
	docs, err := m.aggregateDocs(ctx, pipeline, 0)
	if err != nil {
		return nil, err
	}
	if len(docs) == 0 {
		return nil, nil
	}
	return &docs[0], nil
}

// LoadCapture returns the raw capture value for a service (used by the image
// endpoint to serve base64 captures stored in MongoDB).
func (m *Mongo) LoadCapture(ctx context.Context, ipInt int64, port int) (string, string, error) {
	var doc struct {
		Capture    string `bson:"capture"`
		CaptureExt string `bson:"capture_ext"`
	}
	err := m.results.FindOne(ctx, bson.M{"ip": ipInt, "port": port},
		options.FindOne().SetProjection(bson.M{"capture": 1, "capture_ext": 1}),
	).Decode(&doc)
	if err != nil {
		return "", "", err
	}
	return doc.Capture, doc.CaptureExt, nil
}
