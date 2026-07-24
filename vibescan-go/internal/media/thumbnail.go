package media

import (
	"bytes"
	"image"
	"image/jpeg"
	_ "image/jpeg" // register JPEG decoder
	_ "image/png"  // register PNG decoder

	xdraw "golang.org/x/image/draw"
)

// ThumbMaxWidth is the target width for generated card thumbnails. Cards render
// at roughly 230–390px CSS width (up to ~2x DPR), so 480px keeps them crisp
// while cutting transfer by ~90% versus the full ~1147px PNG capture.
const ThumbMaxWidth = 480

// ThumbJPEGQuality trades a little fidelity for size; screenshots survive it well.
const ThumbJPEGQuality = 72

// Thumbnail decodes a PNG/JPEG capture, downscales it to at most maxWidth (never
// upscaling), and re-encodes it as JPEG. Aspect ratio is preserved. maxWidth <= 0
// falls back to ThumbMaxWidth. It returns the JPEG bytes, or an error if the
// source cannot be decoded.
func Thumbnail(imgBytes []byte, maxWidth int) ([]byte, error) {
	if maxWidth <= 0 {
		maxWidth = ThumbMaxWidth
	}
	src, _, err := image.Decode(bytes.NewReader(imgBytes))
	if err != nil {
		return nil, err
	}

	b := src.Bounds()
	sw, sh := b.Dx(), b.Dy()
	if sw <= 0 || sh <= 0 {
		return nil, image.ErrFormat
	}

	dw, dh := sw, sh
	if sw > maxWidth {
		dw = maxWidth
		dh = int(float64(sh) * float64(maxWidth) / float64(sw))
		if dh < 1 {
			dh = 1
		}
	}

	dst := image.NewRGBA(image.Rect(0, 0, dw, dh))
	xdraw.CatmullRom.Scale(dst, dst.Bounds(), src, b, xdraw.Over, nil)

	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, dst, &jpeg.Options{Quality: ThumbJPEGQuality}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
