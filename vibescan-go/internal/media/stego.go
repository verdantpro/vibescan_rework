package media

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"image"
	"image/png"
)

// EmbedStegoBase64 embeds payload into a base64 PNG capture and returns the
// re-encoded base64. On any failure it returns the input unchanged, so a capture
// is never lost to a stego error.
func EmbedStegoBase64(captureB64, payload string) string {
	raw, err := base64.StdEncoding.DecodeString(captureB64)
	if err != nil {
		return captureB64
	}
	out, err := EmbedStego(raw, payload)
	if err != nil {
		return captureB64
	}
	return base64.StdEncoding.EncodeToString(out)
}

// rgbBytes returns the image as a row-major R,G,B byte sequence (3 bytes/pixel),
// matching PIL's Image.convert("RGB").tobytes() ordering used by the stego codec.
func rgbBytes(img image.Image) ([]byte, int, int) {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	out := make([]byte, 0, w*h*3)
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			r, g, bl, _ := img.At(x, y).RGBA() // 16-bit
			out = append(out, byte(r>>8), byte(g>>8), byte(bl>>8))
		}
	}
	return out, w, h
}

// EmbedStego writes payload into the image's RGB LSBs and returns a lossless PNG,
// mirroring client_agent.py:_embed_metadata_stego. The bitstream is a 4-byte
// big-endian length prefix followed by the UTF-8 payload. On insufficient space
// or decode failure it returns the original bytes unchanged.
func EmbedStego(imgBytes []byte, payload string) ([]byte, error) {
	src, _, err := image.Decode(bytes.NewReader(imgBytes))
	if err != nil {
		return imgBytes, err
	}
	pix, w, h := rgbBytes(src)

	p := []byte(payload)
	bitstream := make([]byte, 4+len(p))
	binary.BigEndian.PutUint32(bitstream[:4], uint32(len(p)))
	copy(bitstream[4:], p)

	if len(bitstream)*8 > len(pix) {
		return imgBytes, nil // not enough capacity; leave image unmodified
	}

	bitIdx := 0
	for _, by := range bitstream {
		for pos := 7; pos >= 0; pos-- {
			bit := byte((by >> uint(pos)) & 1)
			pix[bitIdx] = (pix[bitIdx] & 0xFE) | bit
			bitIdx++
		}
	}

	// Reconstruct as RGBA (opaque) and encode lossless PNG; the RGB LSBs survive.
	out := image.NewRGBA(image.Rect(0, 0, w, h))
	for i := 0; i < w*h; i++ {
		out.Pix[i*4+0] = pix[i*3+0]
		out.Pix[i*4+1] = pix[i*3+1]
		out.Pix[i*4+2] = pix[i*3+2]
		out.Pix[i*4+3] = 255
	}
	var buf bytes.Buffer
	enc := png.Encoder{CompressionLevel: png.BestCompression}
	if err := enc.Encode(&buf, out); err != nil {
		return imgBytes, err
	}
	return buf.Bytes(), nil
}

// ExtractStego recovers a payload embedded by EmbedStego (and by the Python
// agent), mirroring common/shared_utils.py:extract_stego_payload. Returns "" when
// no valid payload is present.
func ExtractStego(imgBytes []byte) string {
	src, _, err := image.Decode(bytes.NewReader(imgBytes))
	if err != nil {
		return ""
	}
	pix, _, _ := rgbBytes(src)
	if len(pix) < 32 {
		return ""
	}

	var length uint32
	for i := 0; i < 32; i++ {
		length = (length << 1) | uint32(pix[i]&1)
	}
	totalBits := 32 + int(length)*8
	if length == 0 || totalBits > len(pix) {
		return ""
	}

	payload := make([]byte, length)
	for i := 0; i < int(length); i++ {
		var b byte
		for j := 0; j < 8; j++ {
			b = (b << 1) | (pix[32+i*8+j] & 1)
		}
		payload[i] = b
	}
	return string(payload)
}
