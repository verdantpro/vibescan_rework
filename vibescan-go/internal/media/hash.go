// Package media reimplements the capture/DOM/pHash helpers from
// common/shared_utils.py and common/r2_storage.py, byte-for-byte compatible
// with the values stored by the Python collector.
package media

import (
	"crypto/sha1"
	"encoding/hex"
	"regexp"
	"strings"
)

// CaptureHashExt returns (hash, ext, ok) for a base64 capture string,
// mirroring common/r2_storage.py:compute_capture_hash_ext.
//
// The hash is the first 12 hex chars of SHA-1 over the base64 *string* bytes
// (not the decoded image). The extension is "jpg" when the base64 begins with
// the JPEG marker "/9j/", otherwise "png".
func CaptureHashExt(captureB64 string) (hash, ext string, ok bool) {
	if captureB64 == "" {
		return "", "", false
	}
	if strings.HasPrefix(strings.ToLower(captureB64), "screenshot_error") {
		return "", "", false
	}
	sum := sha1.Sum([]byte(captureB64))
	hash = hex.EncodeToString(sum[:])[:12]
	if strings.HasPrefix(captureB64, "/9j/") {
		ext = "jpg"
	} else {
		ext = "png"
	}
	return hash, ext, true
}

var (
	domCommentRE = regexp.MustCompile(`(?s)<!--.*?-->`)
	domScriptRE  = regexp.MustCompile(`(?is)<script\b[^>]*>.*?</script>`)
	domStyleRE   = regexp.MustCompile(`(?is)<style\b[^>]*>.*?</style>`)
	domTagRE     = regexp.MustCompile(`</?([a-zA-Z0-9:_-]+)(?:\s+[^>]*)?>`)
	phashChunkRE = regexp.MustCompile(`^[0-9a-f]{16}$`)
)

// DomStructureHash computes a stable hash of the HTML tag structure,
// mirroring common/shared_utils.py:compute_dom_structure_hash. Returns "" for
// empty or tagless input.
func DomStructureHash(fulltext string) string {
	text := strings.TrimSpace(fulltext)
	if text == "" {
		return ""
	}
	text = domCommentRE.ReplaceAllString(text, " ")
	text = domScriptRE.ReplaceAllString(text, " ")
	text = domStyleRE.ReplaceAllString(text, " ")

	matches := domTagRE.FindAllString(text, -1)
	if len(matches) == 0 {
		return ""
	}
	var b strings.Builder
	for _, m := range matches {
		b.WriteString(strings.ToLower(m))
	}
	sum := sha1.Sum([]byte(b.String()))
	return hex.EncodeToString(sum[:])[:16]
}

// SplitPhashChunks splits a 16-char hex pHash into four 4-char chunks,
// mirroring common/shared_utils.py:split_phash_chunks. Returns nil for invalid
// input.
func SplitPhashChunks(phashHex string) map[string]string {
	h := strings.ToLower(strings.TrimSpace(phashHex))
	if !phashChunkRE.MatchString(h) {
		return nil
	}
	return map[string]string{
		"phash_c0": h[0:4],
		"phash_c1": h[4:8],
		"phash_c2": h[8:12],
		"phash_c3": h[12:16],
	}
}

// ExtractProduct pulls a short display name from a service banner.
// Compatible with the Python extract_product inputs (product:/server: lines)
// but intentionally cleaner for UI: strips nmap "version:" / "extrainfo:"
// tails and returns a concise token (e.g. "nginx", "Squid", "Apache").
func ExtractProduct(banner string) string {
	banner = strings.TrimSpace(banner)
	if banner == "" {
		return ""
	}
	lines := strings.Split(banner, "\n")
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "product:") {
			return cleanProduct(strings.TrimSpace(line[len("product:"):]))
		}
		if strings.HasPrefix(lower, "server:") {
			return cleanProduct(strings.TrimSpace(line[len("server:"):]))
		}
	}
	first := strings.TrimRight(lines[0], "\r")
	return cleanProduct(first)
}

// cleanProduct normalizes nmap-ish product strings into a short label.
func cleanProduct(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	lower := strings.ToLower(s)
	for _, sep := range []string{" extrainfo:", " version:", " ("} {
		if i := strings.Index(lower, sep); i >= 0 {
			s = strings.TrimSpace(s[:i])
			lower = strings.ToLower(s)
		}
	}
	return firstToken(s)
}

// firstToken returns the leading token split on '/' then ' ', matching the
// Python `prod.split('/')[0].split(' ')[0].strip()` idiom.
func firstToken(s string) string {
	s = strings.SplitN(s, "/", 2)[0]
	s = strings.SplitN(s, " ", 2)[0]
	return strings.TrimSpace(s)
}
