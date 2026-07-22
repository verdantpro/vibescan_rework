package transport

import (
	"encoding/json"
	"testing"
)

// EncodeSubmission → DecodeSubmission must round-trip, and a wrong key must fail
// verification — proving the agent-side envelope is collector-compatible.
func TestEncodeDecodeRoundTrip(t *testing.T) {
	payload := map[string]any{
		"version":      1,
		"generated_at": "2026-07-22T00:00:00+00:00",
		"results": []map[string]any{
			{"ip": "8.8.8.8", "services": map[string]any{"80": map[string]any{"banner": "nginx"}}},
		},
	}
	env, err := EncodeSubmission(payload, "secret")
	if err != nil {
		t.Fatalf("EncodeSubmission: %v", err)
	}
	if env.Compression != "gzip" || env.CompressedPayload == "" || env.Signature == "" {
		t.Fatalf("bad envelope: %+v", env)
	}

	raw, err := DecodeSubmission(env, "secret")
	if err != nil {
		t.Fatalf("DecodeSubmission: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("payload not JSON: %v", err)
	}
	if got["generated_at"] != "2026-07-22T00:00:00+00:00" {
		t.Errorf("generated_at round-trip mismatch: %v", got["generated_at"])
	}

	if _, err := DecodeSubmission(env, "wrong"); err == nil {
		t.Error("expected signature failure with wrong key")
	}
}
