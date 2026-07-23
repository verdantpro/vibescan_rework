package enrich

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxBody = 1 << 20 // 1 MiB cap on any enrichment response

// internetDB queries Shodan's free, keyless InternetDB. A 404 means "no data on
// file" — returned as an empty record tagged with the source so it caches as a
// negative result rather than being refetched every time.
func (e *Enricher) internetDB(ctx context.Context, ip string) (Record, bool) {
	if err := e.lim.wait(ctx); err != nil {
		return Record{}, false
	}
	body, status, ok := e.fetch(ctx, "https://internetdb.shodan.io/"+url.PathEscape(ip), nil)
	if !ok {
		return Record{}, false
	}
	if status == http.StatusNotFound {
		return Record{Sources: []string{"internetdb"}}, true // negative cache
	}
	if status != http.StatusOK {
		return Record{}, false
	}
	return parseInternetDB(body)
}

func parseInternetDB(body []byte) (Record, bool) {
	var d struct {
		Ports     []int    `json:"ports"`
		Hostnames []string `json:"hostnames"`
		CPEs      []string `json:"cpes"`
		Vulns     []string `json:"vulns"`
		Tags      []string `json:"tags"`
	}
	if json.Unmarshal(body, &d) != nil {
		return Record{}, false
	}
	return Record{
		Ports:     d.Ports,
		Hostnames: d.Hostnames,
		CPEs:      d.CPEs,
		Vulns:     d.Vulns,
		Tags:      d.Tags,
		Sources:   []string{"internetdb"},
	}, true
}

// shodanHost queries the paid Shodan Host API for richer ownership/product data.
// Called only on the on-demand path when a key is configured.
func (e *Enricher) shodanHost(ctx context.Context, ip string) (Record, bool) {
	if e.key == "" {
		return Record{}, false
	}
	if err := e.lim.wait(ctx); err != nil {
		return Record{}, false
	}
	q := url.Values{"key": {e.key}, "minify": {"false"}}
	u := "https://api.shodan.io/shodan/host/" + url.PathEscape(ip) + "?" + q.Encode()
	body, status, ok := e.fetch(ctx, u, map[string]string{})
	if !ok || status != http.StatusOK {
		return Record{}, false // 401/403 (bad key), 404 (no data), 429 (rate) all → skip
	}
	return parseShodanHost(body)
}

func parseShodanHost(body []byte) (Record, bool) {
	var d struct {
		Org         string   `json:"org"`
		ISP         string   `json:"isp"`
		ASN         string   `json:"asn"`
		CountryName string   `json:"country_name"`
		City        string   `json:"city"`
		Hostnames   []string `json:"hostnames"`
		Tags        []string `json:"tags"`
		Vulns       []string `json:"vulns"`
		Ports       []int    `json:"ports"`
		LastUpdate  string   `json:"last_update"`
		Data        []struct {
			Port    int    `json:"port"`
			Product string `json:"product"`
			Version string `json:"version"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &d) != nil {
		return Record{}, false
	}

	rec := Record{
		Org:       strings.TrimSpace(d.Org),
		ISP:       strings.TrimSpace(d.ISP),
		ASN:       strings.TrimSpace(d.ASN),
		Country:   strings.TrimSpace(d.CountryName),
		City:      strings.TrimSpace(d.City),
		Hostnames: d.Hostnames,
		Tags:      d.Tags,
		Vulns:     d.Vulns,
		Ports:     d.Ports,
		Sources:   []string{"shodan"},
	}
	for _, s := range d.Data {
		p := strings.TrimSpace(s.Product)
		if p == "" {
			continue
		}
		if s.Version != "" {
			p += " " + strings.TrimSpace(s.Version)
		}
		rec.Products = append(rec.Products, p)
		if s.Port != 0 {
			rec.Ports = append(rec.Ports, s.Port)
		}
	}
	if t := parseShodanTime(d.LastUpdate); !t.IsZero() {
		rec.LastSeen = t
	}
	return rec, true
}

// fetch performs a bounded GET and returns the body + status. ok is false only on
// transport failure (the caller decides what a non-2xx status means).
func (e *Enricher) fetch(ctx context.Context, u string, extra map[string]string) ([]byte, int, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, false
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, 0, false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, resp.StatusCode, false
	}
	return body, resp.StatusCode, true
}

// parseShodanTime parses Shodan's last_update ("2021-05-30T12:34:56.789012").
func parseShodanTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.999999", "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}
