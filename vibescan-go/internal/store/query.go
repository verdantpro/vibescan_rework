package store

import (
	"context"
	"regexp"
	"strings"
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
	// Denormalized enrichment summary (written by the enrichment worker/on-demand).
	VulnCount  int      `bson:"vuln_count"`
	ShodanTags []string `bson:"shodan_tags"`
	ExtraPorts []int    `bson:"extra_ports"`
	Verdict    string   `bson:"verdict"`
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
	// Recent selects the pure-recency gallery ("Latest signals"): screenshots
	// only, newest first, any status, no per-/24 dedup or 200-first ranking.
	Recent bool
	// Enrichment filters (from the denormalized summary).
	HasVulns *bool
	Tag      string
	Verdict  string // clean|suspicious|malicious
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
		hasFulltextStage(),
		bson.D{{Key: "$project", Value: bson.D{{Key: "fulltext", Value: 0}}}},
	}
}

func hasFulltextStage() bson.D {
	return bson.D{{Key: "$addFields", Value: bson.D{{Key: "has_fulltext", Value: bson.D{
		{Key: "$gt", Value: bson.A{
			bson.D{{Key: "$strLenCP", Value: bson.D{{Key: "$ifNull", Value: bson.A{"$fulltext", ""}}}}},
			0,
		}},
	}}}}}
}

// galleryPipeline ranks feed tiles for human browsing:
//  1. Prefer HTTP 200
//  2. Prefer non-blank / non-placeholder screenshots (via pHash heuristics)
//  3. At most one service per IPv4 /24 (reduces proxy-farm spam)
//  4. Then recency
func galleryPipeline(offset, limit int) mongo.Pipeline {
	blankPhash := bson.A{
		"",
		"0000000000000000",
		"8080000000000000",
		"8080000000004000",
		"0000400000000000",
	}
	return mongo.Pipeline{
		bson.D{{Key: "$match", Value: hasCaptureMatch}},
		bson.D{{Key: "$addFields", Value: bson.D{
			{Key: "rank_status", Value: bson.D{{Key: "$cond", Value: bson.A{
				bson.D{{Key: "$eq", Value: bson.A{"$http_status", 200}}},
				0, 1,
			}}}},
			{Key: "rank_phash", Value: bson.D{{Key: "$cond", Value: bson.A{
				bson.D{{Key: "$in", Value: bson.A{
					bson.D{{Key: "$ifNull", Value: bson.A{"$screenshot_phash", ""}}},
					blankPhash,
				}}},
				1, 0,
			}}}},
			// IPv4 /24 bucket: high 24 bits of the 32-bit address integer.
			{Key: "net24", Value: bson.D{{Key: "$floor", Value: bson.D{
				{Key: "$divide", Value: bson.A{"$ip", 256}},
			}}}},
		}}},
		// Best candidate per /24 first (status, phash, then newest).
		bson.D{{Key: "$sort", Value: bson.D{
			{Key: "rank_status", Value: 1},
			{Key: "rank_phash", Value: 1},
			{Key: "updated_at", Value: -1},
		}}},
		bson.D{{Key: "$group", Value: bson.D{
			{Key: "_id", Value: "$net24"},
			{Key: "doc", Value: bson.D{{Key: "$first", Value: "$$ROOT"}}},
		}}},
		bson.D{{Key: "$replaceRoot", Value: bson.D{{Key: "newRoot", Value: "$doc"}}}},
		bson.D{{Key: "$sort", Value: bson.D{
			{Key: "rank_status", Value: 1},
			{Key: "rank_phash", Value: 1},
			{Key: "updated_at", Value: -1},
		}}},
		bson.D{{Key: "$skip", Value: offset}},
		bson.D{{Key: "$limit", Value: limit}},
		hasFulltextStage(),
		bson.D{{Key: "$project", Value: bson.D{
			{Key: "fulltext", Value: 0},
			{Key: "rank_status", Value: 0},
			{Key: "rank_phash", Value: 0},
			{Key: "net24", Value: 0},
		}}},
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

// Gallery returns captured services for the feed/console.
//
//   - Recent:      screenshots only, strict newest-first, any status, no dedup
//     (the "Latest signals" rail — new agent finds appear immediately).
//   - ScreensOnly: ranked gallery — prefer HTTP 200, non-blank screenshots, and
//     one host per /24 (the curated feed).
//   - otherwise:   plain recency list over all docs (unused by the UI).
func (m *Mongo) Gallery(ctx context.Context, o ListOpts) ([]ServiceDoc, error) {
	if o.Recent {
		return m.aggregateDocs(ctx, listPipeline(bson.D(hasCaptureMatch), o.Offset, o.Limit), o.MaxTimeMS)
	}
	if !o.ScreensOnly {
		return m.aggregateDocs(ctx, listPipeline(bson.D{}, o.Offset, o.Limit), o.MaxTimeMS)
	}
	return m.aggregateDocs(ctx, galleryPipeline(o.Offset, o.Limit), o.MaxTimeMS)
}

// maxQueryLen bounds the free-text query so a pathological input can't blow up
// the index scan. 128 chars is far more than any real banner/product term.
const maxQueryLen = 128

// Search returns services matching a free-text query and/or filters.
//
// Free-text matching uses a MongoDB $text index (banner/whois/cert_cn/fulltext),
// except IP-like queries (containing a dot), which route to an anchored, escaped
// ip_str prefix match — $text tokenizes on "." so it can't match dotted IPs, and
// an anchored literal regex is both index-friendly and ReDoS-proof.
func (m *Mongo) Search(ctx context.Context, o ListOpts) ([]ServiceDoc, error) {
	// $text must sit at the top level of the match document (it cannot be nested
	// in $and/$or), so filters are merged as sibling keys — an implicit AND.
	match := bson.D{}
	add := func(key string, val any) { match = append(match, bson.E{Key: key, Value: val}) }

	q := strings.TrimSpace(o.Query)
	if len(q) > maxQueryLen {
		q = q[:maxQueryLen]
	}
	if q != "" {
		if isIPLike(q) {
			add("ip_str", bson.D{{Key: "$regex", Value: "^" + regexp.QuoteMeta(q)}})
		} else {
			add("$text", bson.D{{Key: "$search", Value: q}})
		}
	}
	if o.Product != "" {
		p := o.Product
		if len(p) > maxQueryLen {
			p = p[:maxQueryLen]
		}
		// Escaped literal substring; anchoring isn't wanted here (product may be
		// mid-banner), but QuoteMeta keeps it ReDoS-proof.
		add("banner", bson.D{{Key: "$regex", Value: regexp.QuoteMeta(p)}, {Key: "$options", Value: "i"}})
	}
	if o.Port != nil {
		add("port", *o.Port)
	}
	if o.Secured != nil {
		add("secured", *o.Secured)
	}
	if o.StatusCode != nil {
		add("http_status", *o.StatusCode)
	}
	if o.HasVulns != nil {
		if *o.HasVulns {
			add("vuln_count", bson.D{{Key: "$gt", Value: 0}})
		} else {
			add("vuln_count", bson.D{{Key: "$in", Value: bson.A{0, nil}}})
		}
	}
	if o.Tag != "" {
		add("shodan_tags", o.Tag)
	}
	if o.Verdict != "" {
		add("verdict", o.Verdict)
	}
	if o.ScreensOnly {
		match = append(match, hasCaptureMatch...)
	}

	return m.aggregateDocs(ctx, listPipeline(match, o.Offset, o.Limit), o.MaxTimeMS)
}

// isIPLike reports whether q looks like an IPv4 address or a leading fragment of
// one (digits and dots, at least one dot) so it can be matched as an ip_str
// prefix rather than tokenized by the text index.
func isIPLike(q string) bool {
	dot := false
	for _, r := range q {
		switch {
		case r == '.':
			dot = true
		case r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return dot
}

// ServiceDetail returns a single service document. When brief is true the heavy
// fulltext field is projected out (HasFulltext is still reported) — used by the
// live console, which renders telemetry but never the page source.
func (m *Mongo) ServiceDetail(ctx context.Context, ipInt int64, port int, brief bool) (*ServiceDoc, error) {
	opts := options.FindOne()
	if brief {
		// Drop the heavy field entirely; the brief caller (console) doesn't use
		// fulltext or has_fulltext, so no extra round-trip to recompute the flag.
		opts.SetProjection(bson.M{"fulltext": 0})
	}
	var doc ServiceDoc
	err := m.results.FindOne(ctx, bson.M{"ip": ipInt, "port": port}, opts).Decode(&doc)
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
