package transport

import (
	"encoding/json"
	"testing"
)

// Golden envelope produced by vibescan_v2/common/transport.py:encode_submission
// with secret "testkey". The Go decoder must accept it, proving HMAC + gzip +
// base64 compatibility with the legacy v1 agent protocol.
const (
	goldenPayload    = `H4sIAAAAAAAC/6tWSk/NSy1KLElNiU8sUbJSMjIwMtM1MNc1MgwxMLACI20wqaSjVJRaXJpTUqxkFV2tlFkAVGyoZ6RnrGcClCpOLSrLTE4FylUrWRiAyKTEPKDBQEUVSrW1tbG1ADCyyNxqAAAA`
	goldenSignature  = `eb2c4a7eb78fae47a21143e064dc0767a2ebf8f1527215a8516274c485010ca5`
	goldenSecret     = `testkey`
	goldenGeneratedA = `2026-07-21T00:00:00+00:00`
)

func TestDecodeSubmissionGolden(t *testing.T) {
	env := Envelope{
		CompressedPayload: goldenPayload,
		Signature:         goldenSignature,
		Compression:       "gzip",
	}
	raw, err := DecodeSubmission(env, goldenSecret)
	if err != nil {
		t.Fatalf("DecodeSubmission failed: %v", err)
	}

	var p struct {
		GeneratedAt string `json:"generated_at"`
		Results     []struct {
			IP       string                    `json:"ip"`
			Services map[string]map[string]any `json:"services"`
		} `json:"results"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("payload not valid JSON: %v", err)
	}
	if p.GeneratedAt != goldenGeneratedA {
		t.Errorf("generated_at = %q, want %q", p.GeneratedAt, goldenGeneratedA)
	}
	if len(p.Results) != 1 || p.Results[0].IP != "1.2.3.4" {
		t.Fatalf("unexpected results: %+v", p.Results)
	}
	if _, ok := p.Results[0].Services["80"]; !ok {
		t.Errorf("expected port 80 service, got %+v", p.Results[0].Services)
	}
}

func TestDecodeSubmissionBadSignature(t *testing.T) {
	env := Envelope{
		CompressedPayload: goldenPayload,
		Signature:         goldenSignature,
		Compression:       "gzip",
	}
	if _, err := DecodeSubmission(env, "wrongkey"); err == nil {
		t.Fatal("expected error for wrong secret, got nil")
	}
}

func TestDecodeSubmissionMissingFields(t *testing.T) {
	if _, err := DecodeSubmission(Envelope{Compression: "gzip"}, goldenSecret); err == nil {
		t.Fatal("expected error for missing fields, got nil")
	}
}
