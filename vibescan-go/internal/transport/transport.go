// Package transport decodes the signed, gzip-compressed, base64-encoded
// submission envelope produced by common/transport.py. It is byte-compatible
// with the legacy v1 agent protocol.
package transport

import (
	"bytes"
	"compress/gzip"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
)

// DefaultCompression matches common/transport.py:DEFAULT_COMPRESSION.
const DefaultCompression = "gzip"

// Envelope is the outer request body sent by agents.
type Envelope struct {
	CompressedPayload string `json:"compressed_payload"`
	Signature         string `json:"signature"`
	Compression       string `json:"compression"`
}

// signPayload returns the hex-encoded HMAC-SHA256 of data under secret,
// matching common/transport.py:sign_payload.
func signPayload(data []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

// verifySignature performs a constant-time comparison of the expected and
// provided hex signatures, matching common/transport.py:verify_signature.
func verifySignature(data []byte, signature, secret string) bool {
	expected := signPayload(data, secret)
	return subtle.ConstantTimeCompare([]byte(expected), []byte(signature)) == 1
}

// DecodeSubmission decodes, verifies, and inflates a submitted payload,
// returning the raw JSON bytes of the inner payload. It mirrors
// common/transport.py:decode_submission.
func DecodeSubmission(env Envelope, secret string) ([]byte, error) {
	compression := env.Compression
	if compression == "" {
		compression = DefaultCompression
	}
	if env.CompressedPayload == "" || env.Signature == "" {
		return nil, errors.New("missing compressed payload or signature")
	}

	compressed, err := base64.StdEncoding.DecodeString(env.CompressedPayload)
	if err != nil {
		return nil, err
	}

	if !verifySignature(compressed, env.Signature, secret) {
		return nil, errors.New("invalid signature")
	}

	if compression != "gzip" {
		return nil, errors.New("unsupported compression: " + compression)
	}
	zr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	return io.ReadAll(zr)
}
