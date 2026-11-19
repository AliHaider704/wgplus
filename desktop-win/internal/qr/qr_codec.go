package qr

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"unsafe"

	"github.com/makiuchi-d/gozxing"
	qrreader "github.com/makiuchi-d/gozxing/qrcode"
	"github.com/skip2/go-qrcode"
	_ "golang.org/x/image/bmp"
	"golang.org/x/sys/windows"
)

const cfDIB = 8

var (
	modUser32          = windows.NewLazySystemDLL("user32.dll")
	modKernel32        = windows.NewLazySystemDLL("kernel32.dll")
	procOpenClipboard  = modUser32.NewProc("OpenClipboard")
	procCloseClipboard = modUser32.NewProc("CloseClipboard")
	procGetClipData    = modUser32.NewProc("GetClipboardData")
	procGlobalLock     = modKernel32.NewProc("GlobalLock")
	procGlobalUnlock   = modKernel32.NewProc("GlobalUnlock")
	procGlobalSize     = modKernel32.NewProc("GlobalSize")
	procRtlMoveMemory  = modKernel32.NewProc("RtlMoveMemory")
)

// EncodeConfToPNGBytes renders a pure #FFFFFF/#000000 ISO/IEC 18004 QR PNG image.
func EncodeConfToPNGBytes(confText string) ([]byte, error) {
	if confText == "" {
		return nil, errors.New("empty QR content")
	}
	return qrcode.Encode(confText, qrcode.Medium, 320)
}

// EncodeConfToPNGDataURL renders a base64 PNG data URL for embedding directly inside dark/light UI frames.
func EncodeConfToPNGDataURL(confText string) (string, error) {
	raw, err := EncodeConfToPNGBytes(confText)
	if err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(raw), nil
}

// DecodeQRFromImage decodes standard or dark-mode inverted QR codes from an image.Image.
func DecodeQRFromImage(img image.Image) (string, error) {
	if img == nil {
		return "", errors.New("nil image")
	}
	reader := qrreader.NewQRCodeReader()
	lum := gozxing.NewLuminanceSourceFromImage(img)

	hints := map[gozxing.DecodeHintType]interface{}{
		gozxing.DecodeHintType_TRY_HARDER: true,
	}

	if bmp, err := gozxing.NewBinaryBitmap(gozxing.NewHybridBinarizer(lum)); err == nil {
		if res, dErr := reader.Decode(bmp, hints); dErr == nil && res.GetText() != "" {
			return res.GetText(), nil
		}
	}
	if bmpInv, err := gozxing.NewBinaryBitmap(gozxing.NewHybridBinarizer(lum.Invert())); err == nil {
		if res, dErr := reader.Decode(bmpInv, hints); dErr == nil && res.GetText() != "" {
			return res.GetText(), nil
		}
	}
	return "", errors.New("no valid QR code detected in image")
}

// DecodeQRFromBytes decodes PNG, JPEG, GIF, or BMP image bytes into QR payload text.
func DecodeQRFromBytes(imgBytes []byte) (string, error) {
	if len(imgBytes) == 0 {
		return "", errors.New("empty image bytes")
	}
	img, _, err := image.Decode(bytes.NewReader(imgBytes))
	if err != nil {
		return "", fmt.Errorf("unsupported image format: %w", err)
	}
	return DecodeQRFromImage(img)
}

func wrapDibAsBmp(dib []byte) ([]byte, error) {
	if len(dib) < 40 {
		return nil, errors.New("clipboard DIB header too small")
	}
	biSize := binary.LittleEndian.Uint32(dib[0:4])
	if biSize < 12 || int(biSize) > len(dib) {
		return nil, errors.New("invalid DIB header size")
	}
	biBitCount := binary.LittleEndian.Uint16(dib[14:16])
	biCompression := binary.LittleEndian.Uint32(dib[16:20])
	biClrUsed := binary.LittleEndian.Uint32(dib[32:36])

	var colorTableEntries uint32
	if biClrUsed > 0 {
		colorTableEntries = biClrUsed
	} else if biBitCount <= 8 {
		colorTableEntries = 1 << biBitCount
	} else if biCompression == 3 && (biBitCount == 16 || biBitCount == 32) && biSize == 40 {
		colorTableEntries = 3
	}
	pixelOffset := 14 + biSize + colorTableEntries*4
	totalSize := uint32(14 + len(dib))

	out := make([]byte, totalSize)
	out[0] = 'B'
	out[1] = 'M'
	binary.LittleEndian.PutUint32(out[2:6], totalSize)
	binary.LittleEndian.PutUint32(out[10:14], pixelOffset)
	copy(out[14:], dib)
	return out, nil
}

// DecodeQRFromClipboardWindows reads an image (CF_DIB) from the Windows clipboard
// (e.g., after Ctrl+V from a Win+Shift+S snip) and decodes any embedded QR code.
func DecodeQRFromClipboardWindows() (string, error) {
	opened, _, _ := procOpenClipboard.Call(0)
	if opened == 0 {
		return "", errors.New("unable to open Windows clipboard")
	}

	hMem, _, _ := procGetClipData.Call(cfDIB)
	if hMem == 0 {
		procCloseClipboard.Call()
		return "", errors.New("no image found on clipboard")
	}

	sz, _, _ := procGlobalSize.Call(hMem)
	ptr, _, _ := procGlobalLock.Call(hMem)
	if ptr == 0 || sz == 0 {
		if ptr != 0 {
			procGlobalUnlock.Call(hMem)
		}
		procCloseClipboard.Call()
		return "", errors.New("failed locking clipboard image memory")
	}

	dibCopy := make([]byte, sz)
	procRtlMoveMemory.Call(uintptr(unsafe.Pointer(&dibCopy[0])), ptr, sz)
	procGlobalUnlock.Call(hMem)
	procCloseClipboard.Call()

	bmpBytes, err := wrapDibAsBmp(dibCopy)
	if err != nil {
		return "", err
	}
	return DecodeQRFromBytes(bmpBytes)
}
