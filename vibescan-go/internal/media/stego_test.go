package media

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"regexp"
	"testing"
)

func testPNG(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.RGBA{uint8(x * 7), uint8(y * 5), uint8((x + y) * 3), 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestStegoRoundTrip(t *testing.T) {
	src := testPNG(t, 64, 64)
	payload := "timestamp:2026-07-22T00:00:00|url:http://1.2.3.4:80|status:200|whois:TEST|banner:nginx"

	embedded, err := EmbedStego(src, payload)
	if err != nil {
		t.Fatalf("EmbedStego: %v", err)
	}
	if bytes.Equal(embedded, src) {
		t.Fatal("expected modified image (had capacity)")
	}
	if got := ExtractStego(embedded); got != payload {
		t.Errorf("ExtractStego = %q, want %q", got, payload)
	}
}

func TestStegoInsufficientSpace(t *testing.T) {
	src := testPNG(t, 4, 4) // 48 RGB bytes → room for ~2 payload bytes after the 32-bit header
	big := make([]byte, 100)
	for i := range big {
		big[i] = 'x'
	}
	out, _ := EmbedStego(src, string(big))
	if !bytes.Equal(out, src) {
		t.Error("expected original bytes when payload doesn't fit")
	}
}

func TestPerceptualHashDeterministic(t *testing.T) {
	img := testPNG(t, 120, 90)
	h1 := PerceptualHash(img)
	h2 := PerceptualHash(img)
	if h1 != h2 {
		t.Errorf("non-deterministic: %s vs %s", h1, h2)
	}
	if !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(h1) {
		t.Errorf("not a 16-char hex hash: %q", h1)
	}
	if PerceptualHash(nil) != "" {
		t.Error("expected empty hash for nil input")
	}
}
