package transport

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
)

// EncodeSubmission serializes payload to JSON, gzip-compresses it, signs the
// compressed bytes, and base64-encodes them — the exact envelope the collector
// expects, mirroring common/transport.py:encode_submission. It is the agent-side
// complement to DecodeSubmission.
func EncodeSubmission(payload any, secret string) (Envelope, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return Envelope{}, err
	}

	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(raw); err != nil {
		return Envelope{}, err
	}
	if err := zw.Close(); err != nil {
		return Envelope{}, err
	}
	compressed := buf.Bytes()

	return Envelope{
		CompressedPayload: base64.StdEncoding.EncodeToString(compressed),
		Signature:         signPayload(compressed, secret),
		Compression:       "gzip",
	}, nil
}
