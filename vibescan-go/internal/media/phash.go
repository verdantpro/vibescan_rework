package media

import (
	"bytes"
	"fmt"
	"image"
	_ "image/jpeg" // register JPEG decoder
	_ "image/png"  // register PNG decoder

	xdraw "golang.org/x/image/draw"
)

// PerceptualHash computes the 16-char hex dHash of an image, mirroring
// common/shared_utils.py:compute_perceptual_hash: grayscale, resize to 9x8, then
// compare horizontally-adjacent pixels over 8 rows (64 bits).
//
// Note: Python uses a LANCZOS resize; Go uses CatmullRom (the closest
// high-quality kernel), so the hash can differ by a few bits from Python's for
// the same image. It is deterministic and internally consistent.
func PerceptualHash(imgBytes []byte) string {
	if len(imgBytes) == 0 {
		return ""
	}
	src, _, err := image.Decode(bytes.NewReader(imgBytes))
	if err != nil {
		return ""
	}

	// Grayscale first (matches PIL convert("L") before resize).
	b := src.Bounds()
	grayFull := image.NewGray(b)
	xdraw.Draw(grayFull, b, src, b.Min, xdraw.Src)

	small := image.NewGray(image.Rect(0, 0, 9, 8))
	xdraw.CatmullRom.Scale(small, small.Bounds(), grayFull, grayFull.Bounds(), xdraw.Over, nil)

	var value uint64
	for row := 0; row < 8; row++ {
		off := row * small.Stride
		for col := 0; col < 8; col++ {
			left := small.Pix[off+col]
			right := small.Pix[off+col+1]
			value <<= 1
			if left > right {
				value |= 1
			}
		}
	}
	return fmt.Sprintf("%016x", value)
}
