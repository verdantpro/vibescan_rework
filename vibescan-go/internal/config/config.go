// Package config loads collector configuration from the environment,
// mirroring the environment variables used by the Python VibeScan server.
package config

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// DefaultSharedKey is the fallback HMAC key when VIBESCAN_SHARED_KEY is unset.
// It must match common/transport.py:DEFAULT_SHARED_KEY so legacy agents that
// rely on the default key continue to submit successfully.
const DefaultSharedKey = "vibescan-default-key"

// DefaultPublicURL matches common/transport.py:DEFAULT_PUBLIC_URL.
const DefaultPublicURL = "http://localhost:8080"

// Config holds all collector settings.
type Config struct {
	Addr  string
	Debug bool

	SharedKey string
	PublicURL string

	MongoURI             string
	MongoDB              string
	ResultsCollection    string
	BlacklistCollection  string
	EnrichmentCollection string

	GeoIPPath string
	BufferDir string

	// R2 object storage (optional).
	R2Enabled         bool
	R2FallbackToMongo bool
	R2Bucket          string
	R2Endpoint        string
	R2AccessKey       string
	R2SecretKey       string
	R2PublicURL       string
	R2Region          string

	IngestBatchSize     int
	R2UploadConcurrency int

	// Read-API tuning.
	AggMaxTimeMS int
	MaxGallery   int

	// Per-IP rate limit for the public /api/v2 read endpoints. RPS <= 0 disables
	// limiting; Burst is the bucket capacity (short spikes allowed).
	ReadRateRPS   float64
	ReadRateBurst float64

	// Host enrichment (Shodan InternetDB, free/keyless; the paid Shodan Host API
	// is used only on-demand when a key is set). Key stays server-side.
	EnrichEnabled       bool
	ShodanAPIKey        string
	EnrichTTLHours      int     // durable cache freshness window
	EnrichWorkerEnabled bool    // background worker enriches recent hosts (InternetDB only)
	EnrichWorkerRPS     float64 // shared outbound rate to Shodan/InternetDB
	EnrichWorkerBatch   int     // hosts enriched per worker tick

	// Threat-intel enrichment (ported from scope-recon). Each key is optional; a
	// missing key skips that source. ip-api + RIPEstat are keyless. Keyed sources
	// run on-demand only (Signal view) to protect free quotas.
	VirusTotalKey  string
	AbuseIPDBKey   string
	GreyNoiseKey   string
	OTXKey         string
	ThreatFoxKey   string
	IPQSKey        string
	PulsediveKey   string
	IPInfoToken    string
	ThreatTTLHours int // reputation cache freshness (shorter than Shodan's)
}

// trueValues mirrors common/transport.py:_TRUE_VALUES.
var trueValues = map[string]bool{"1": true, "true": true, "yes": true, "on": true}

// LoadDotenv loads KEY=VALUE lines from a .env file into the process
// environment without overriding already-set variables, matching
// common/transport.py:load_dotenv.
func LoadDotenv(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		k, v, _ := strings.Cut(line, "=")
		k = strings.TrimSpace(k)
		k = strings.TrimPrefix(k, "export ")
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		v = strings.Trim(v, "'")
		v = strings.Trim(v, "\"")
		if k == "" {
			continue
		}
		if _, ok := os.LookupEnv(k); !ok {
			_ = os.Setenv(k, v)
		}
	}
}

func envStr(name, def string) string {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	return v
}

func envBool(name string, def bool) bool {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	return trueValues[strings.ToLower(v)]
}

func envInt(name string, def int) int {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func envFloat(name string, def float64) float64 {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return def
	}
	return f
}

// envStrAny returns the first non-empty of the named vars, else def. Used so the
// object-storage settings accept both S3_* (AWS) and R2_* (Cloudflare) names.
func envStrAny(def string, names ...string) string {
	for _, n := range names {
		if v := strings.TrimSpace(os.Getenv(n)); v != "" {
			return v
		}
	}
	return def
}

func envBoolAny(def bool, names ...string) bool {
	for _, n := range names {
		if v := strings.TrimSpace(os.Getenv(n)); v != "" {
			return trueValues[strings.ToLower(v)]
		}
	}
	return def
}

// Load reads the .env file (if present) and builds a Config from the
// environment, applying the same defaults as the Python server.
func Load() *Config {
	LoadDotenv(".env")

	c := &Config{
		Addr:      ":" + envStr("PORT", "8000"),
		Debug:     envBool("VIBESCAN_DEBUG", false),
		SharedKey: envStr("VIBESCAN_SHARED_KEY", DefaultSharedKey),
		PublicURL: envStr("VIBESCAN_PUBLIC_URL", DefaultPublicURL),

		MongoURI:             envStr("MONGO_URI", "mongodb://localhost:27017"),
		MongoDB:              envStr("MONGO_DB", "vibescan"),
		ResultsCollection:    envStr("MONGO_COLLECTION", "results"),
		BlacklistCollection:  envStr("MONGO_COLLECTION_BLACKLIST", "cidr_blacklist"),
		EnrichmentCollection: envStr("MONGO_COLLECTION_ENRICHMENT", "enrichment"),

		GeoIPPath: envStr("GEOLITE2_CITY_MMDB", "./GeoLite2-City.mmdb"),
		BufferDir: envStr("VIBESCAN_BUFFER_DIR", "cache/server_buffer"),

		// Object storage accepts S3_* (AWS) or R2_* (Cloudflare) names.
		R2Enabled:         envBoolAny(false, "S3_ENABLED", "R2_ENABLED"),
		R2FallbackToMongo: envBoolAny(true, "S3_FALLBACK_TO_MONGO", "R2_FALLBACK_TO_MONGO"),
		R2Bucket:          envStrAny("", "S3_BUCKET_NAME", "R2_BUCKET_NAME"),
		R2Endpoint:        envStrAny("", "S3_ENDPOINT_URL", "R2_ENDPOINT_URL"),
		R2AccessKey:       envStrAny("", "S3_ACCESS_KEY_ID", "R2_ACCESS_KEY_ID"),
		R2SecretKey:       envStrAny("", "S3_SECRET_ACCESS_KEY", "R2_SECRET_ACCESS_KEY"),
		R2PublicURL:       strings.TrimRight(envStrAny("", "S3_PUBLIC_URL", "R2_PUBLIC_URL"), "/"),
		// Region for SigV4. Empty = current behavior (R2/MinIO auto-discovery);
		// AWS S3 needs the real region, e.g. us-east-1.
		R2Region: envStrAny("", "S3_REGION", "R2_REGION"),

		IngestBatchSize: envInt("VIBESCAN_INGEST_BATCH_SIZE", 10),
		AggMaxTimeMS:    envInt("MONGO_AGG_MAX_TIME_MS", 7000),
		MaxGallery:      500,

		ReadRateRPS:   envFloat("VIBESCAN_READ_RATE_RPS", 10),
		ReadRateBurst: envFloat("VIBESCAN_READ_RATE_BURST", 20),

		EnrichEnabled:       envBool("VIBESCAN_ENRICH_ENABLED", true),
		ShodanAPIKey:        envStr("SHODAN_API_KEY", ""),
		EnrichTTLHours:      envInt("VIBESCAN_ENRICH_TTL_HOURS", 168),
		EnrichWorkerEnabled: envBool("VIBESCAN_ENRICH_WORKER", true),
		EnrichWorkerRPS:     envFloat("VIBESCAN_ENRICH_RPS", 1),
		EnrichWorkerBatch:   envInt("VIBESCAN_ENRICH_BATCH", 20),

		VirusTotalKey:  envStr("VIRUSTOTAL_API_KEY", ""),
		AbuseIPDBKey:   envStr("ABUSEIPDB_API_KEY", ""),
		GreyNoiseKey:   envStr("GREYNOISE_API_KEY", ""),
		OTXKey:         envStr("OTX_API_KEY", ""),
		ThreatFoxKey:   envStr("THREATFOX_API_KEY", ""),
		IPQSKey:        envStr("IPQS_API_KEY", ""),
		PulsediveKey:   envStr("PULSEDIVE_API_KEY", ""),
		IPInfoToken:    envStr("IPINFO_TOKEN", ""),
		ThreatTTLHours: envInt("VIBESCAN_THREAT_TTL_HOURS", 24),
	}

	// Clamp ingest batch size to the same 1..50 window as the Python server.
	if c.IngestBatchSize < 1 {
		c.IngestBatchSize = 1
	}
	if c.IngestBatchSize > 50 {
		c.IngestBatchSize = 50
	}

	// R2 upload concurrency: default min(4, batch), overridable, capped at batch.
	def := c.IngestBatchSize
	if def > 4 {
		def = 4
	}
	if def < 1 {
		def = 1
	}
	c.R2UploadConcurrency = envInt("VIBESCAN_R2_UPLOAD_CONCURRENCY", def)
	if c.R2UploadConcurrency < 1 {
		c.R2UploadConcurrency = 1
	}
	if c.R2UploadConcurrency > c.IngestBatchSize {
		c.R2UploadConcurrency = c.IngestBatchSize
	}

	// R2 requires all connection fields; disable if incompletely configured.
	if c.R2Enabled {
		if c.R2Bucket == "" || c.R2Endpoint == "" || c.R2AccessKey == "" ||
			c.R2SecretKey == "" || c.R2PublicURL == "" {
			c.R2Enabled = false
		}
	}

	return c
}
