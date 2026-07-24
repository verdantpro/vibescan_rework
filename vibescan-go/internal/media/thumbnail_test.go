package media

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"testing"
)

// makePNG builds a simple w×h test PNG.
func makePNG(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.RGBA{R: uint8(x % 256), G: uint8(y % 256), B: 128, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("encode png: %v", err)
	}
	return buf.Bytes()
}

func TestThumbnailDownscalesAndEncodesJPEG(t *testing.T) {
	src := makePNG(t, 1147, 720)
	out, err := Thumbnail(src, ThumbMaxWidth)
	if err != nil {
		t.Fatalf("Thumbnail: %v", err)
	}
	cfg, format, err := image.DecodeConfig(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("decode thumb: %v", err)
	}
	if format != "jpeg" {
		t.Errorf("format = %q, want jpeg", format)
	}
	if cfg.Width != ThumbMaxWidth {
		t.Errorf("width = %d, want %d", cfg.Width, ThumbMaxWidth)
	}
	// 1147x720 → 480 wide preserves aspect: 480*720/1147 ≈ 301.
	if cfg.Height < 290 || cfg.Height > 312 {
		t.Errorf("height = %d, want ~301 (aspect preserved)", cfg.Height)
	}
}

func TestThumbnailDoesNotUpscale(t *testing.T) {
	src := makePNG(t, 200, 120)
	out, err := Thumbnail(src, ThumbMaxWidth)
	if err != nil {
		t.Fatalf("Thumbnail: %v", err)
	}
	cfg, _, err := image.DecodeConfig(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("decode thumb: %v", err)
	}
	if cfg.Width != 200 || cfg.Height != 120 {
		t.Errorf("dims = %dx%d, want 200x120 (no upscale)", cfg.Width, cfg.Height)
	}
}

func TestThumbnailRejectsGarbage(t *testing.T) {
	if _, err := Thumbnail([]byte("not an image"), ThumbMaxWidth); err == nil {
		t.Error("expected error for undecodable input")
	}
}
