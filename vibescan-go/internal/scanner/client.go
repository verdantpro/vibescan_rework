package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/vibescan/vibescan-go/internal/transport"
)

// Client talks to the collector: fetching the CIDR blacklist and submitting
// signed results over the legacy v1 protocol.
type Client struct {
	baseURL   string
	sharedKey string
	http      *http.Client
}

// NewClient builds a collector client. baseURL is e.g. https://host (no path).
func NewClient(baseURL, sharedKey string) *Client {
	return &Client{
		baseURL:   baseURL,
		sharedKey: sharedKey,
		http:      &http.Client{Timeout: 20 * time.Second},
	}
}

// FetchBlacklist returns the enabled CIDRs and their TTL seconds from
// GET /api/v1/blacklist, mirroring client_agent.py:_fetch_blacklist.
func (c *Client) FetchBlacklist(ctx context.Context) (cidrs []string, ttl time.Duration, err error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/blacklist", nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("blacklist HTTP %d", resp.StatusCode)
	}
	var body struct {
		CIDRs      []string `json:"cidrs"`
		TTLSeconds int      `json:"ttl_seconds"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, 0, err
	}
	ttlSec := body.TTLSeconds
	if ttlSec <= 0 {
		ttlSec = 3600
	}
	return body.CIDRs, time.Duration(ttlSec) * time.Second, nil
}

// Submit signs+compresses the payload and POSTs it to /api/v1/results, returning
// the collector's summary (stored/buffered/ips).
func (c *Client) Submit(ctx context.Context, payload any) (map[string]any, error) {
	env, err := transport.EncodeSubmission(payload, c.sharedKey)
	if err != nil {
		return nil, err
	}
	buf, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/results", bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("submit HTTP %d", resp.StatusCode)
	}
	var summary map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&summary)
	return summary, nil
}
