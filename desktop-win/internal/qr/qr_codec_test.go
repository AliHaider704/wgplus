package qr

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"testing"
)

func TestEncodeAndDecodeNormalAndInvertedQR(t *testing.T) {
	sample := "[Interface]\nPrivateKey = AAAA\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = BBBB\nEndpoint = 1.2.3.4:51820\n"
	pngBytes, err := EncodeConfToPNGBytes(sample)
	if err != nil {
		t.Fatalf("EncodeConfToPNGBytes failed: %v", err)
	}
	decoded, err := DecodeQRFromBytes(pngBytes)
	if err != nil || decoded != sample {
		t.Fatalf("normal QR round-trip failed: decoded=%q err=%v", decoded, err)
	}

	// Invert image colors to simulate a dark-mode QR screenshot
	img, err := png.Decode(bytes.NewReader(pngBytes))
	if err != nil {
		t.Fatalf("png.Decode failed: %v", err)
	}
	b := img.Bounds()
	inv := image.NewRGBA(b)
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			c := color.RGBAModel.Convert(img.At(x, y)).(color.RGBA)
			inv.SetRGBA(x, y, color.RGBA{R: 255 - c.R, G: 255 - c.G, B: 255 - c.B, A: 255})
		}
	}
	decodedInv, err := DecodeQRFromImage(inv)
	if err != nil || decodedInv != sample {
		t.Fatalf("inverted dark-mode QR decode failed: decoded=%q err=%v", decodedInv, err)
	}
}
