package org.telegram.wgplus.module;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.net.Uri;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.BinaryBitmap;
import com.google.zxing.DecodeHintType;
import com.google.zxing.EncodeHintType;
import com.google.zxing.LuminanceSource;
import com.google.zxing.RGBLuminanceSource;
import com.google.zxing.Result;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.common.GlobalHistogramBinarizer;
import com.google.zxing.common.HybridBinarizer;
import com.google.zxing.qrcode.QRCodeReader;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.EnumMap;
import java.util.Map;

/**
 * Pure-Java ISO/IEC 18004 QR encoder and gallery-image decoder (zero CAMERA permission required).
 */
public final class WgQrCodec {

    private static final int COLOR_BLACK = 0xFF000000;
    private static final int COLOR_WHITE = 0xFFFFFFFF;

    private WgQrCodec() {
    }

    public static final class ArgbFrame {
        public final int width;
        public final int height;
        public final int[] pixels;

        public ArgbFrame(int width, int height, int[] pixels) {
            this.width = width;
            this.height = height;
            this.pixels = pixels;
        }
    }

    /**
     * Encodes configuration text into a crisp high-contrast black-on-white ARGB pixel matrix.
     */
    public static ArgbFrame encodeToArgbPixels(String payload, int dimensionPx) throws WgStrings.WgException {
        if (payload == null || payload.trim().isEmpty()) {
            throw new WgStrings.WgException(WgStrings.ErrorCode.INVALID_CONF);
        }
        int size = Math.max(240, Math.min(1024, dimensionPx));
        try {
            Map<EncodeHintType, Object> hints = new EnumMap<>(EncodeHintType.class);
            hints.put(EncodeHintType.CHARACTER_SET, StandardCharsets.UTF_8.name());
            hints.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.M);
            hints.put(EncodeHintType.MARGIN, 2);

            BitMatrix matrix = new QRCodeWriter().encode(payload, BarcodeFormat.QR_CODE, size, size, hints);
            int w = matrix.getWidth();
            int h = matrix.getHeight();
            int[] pixels = new int[w * h];
            for (int y = 0; y < h; y++) {
                int rowOffset = y * w;
                for (int x = 0; x < w; x++) {
                    pixels[rowOffset + x] = matrix.get(x, y) ? COLOR_BLACK : COLOR_WHITE;
                }
            }
            return new ArgbFrame(w, h, pixels);
        } catch (Throwable t) {
            throw new WgStrings.WgException(WgStrings.ErrorCode.QR_ENCODE_FAILED, t.getMessage(), t);
        }
    }

    public static Bitmap encodeToBitmap(String payload, int dimensionPx) throws WgStrings.WgException {
        ArgbFrame frame = encodeToArgbPixels(payload, dimensionPx);
        Bitmap bmp = Bitmap.createBitmap(frame.width, frame.height, Bitmap.Config.ARGB_8888);
        bmp.setPixels(frame.pixels, 0, frame.width, 0, 0, frame.width, frame.height);
        return bmp;
    }

    /**
     * Decodes a QR code from ARGB pixels, supporting both standard light-background and dark-mode inverted QR screenshots.
     */
    public static String decodeFromArgbPixels(int[] pixels, int width, int height) throws WgStrings.WgException {
        if (pixels == null || width <= 0 || height <= 0 || pixels.length < width * height) {
            throw new WgStrings.WgException(WgStrings.ErrorCode.QR_NOT_FOUND);
        }

        Map<DecodeHintType, Object> hints = new EnumMap<>(DecodeHintType.class);
        hints.put(DecodeHintType.CHARACTER_SET, StandardCharsets.UTF_8.name());
        hints.put(DecodeHintType.TRY_HARDER, Boolean.TRUE);
        hints.put(DecodeHintType.POSSIBLE_FORMATS, Collections.singletonList(BarcodeFormat.QR_CODE));

        RGBLuminanceSource rgbSource = new RGBLuminanceSource(width, height, pixels);
        LuminanceSource[] sources = new LuminanceSource[]{
                rgbSource,
                invertLuminanceCompat(rgbSource)
        };

        QRCodeReader reader = new QRCodeReader();
        for (LuminanceSource src : sources) {
            if (src == null) {
                continue;
            }
            BinaryBitmap[] candidates = new BinaryBitmap[]{
                    new BinaryBitmap(new HybridBinarizer(src)),
                    new BinaryBitmap(new GlobalHistogramBinarizer(src))
            };
            for (BinaryBitmap bin : candidates) {
                try {
                    reader.reset();
                    Result res = reader.decode(bin, hints);
                    if (res != null && res.getText() != null && !res.getText().trim().isEmpty()) {
                        return res.getText().trim();
                    }
                } catch (Throwable ignored) {
                }
            }
        }
        throw new WgStrings.WgException(WgStrings.ErrorCode.QR_NOT_FOUND);
    }

    private static LuminanceSource invertLuminanceCompat(final LuminanceSource delegate) {
        try {
            return delegate.invert();
        } catch (Throwable ignored) {
            final int w = delegate.getWidth();
            final int h = delegate.getHeight();
            return new LuminanceSource(w, h) {
                @Override
                public byte[] getRow(int y, byte[] row) {
                    byte[] r = delegate.getRow(y, row);
                    for (int i = 0; i < w; i++) {
                        r[i] = (byte) (255 - (r[i] & 0xFF));
                    }
                    return r;
                }

                @Override
                public byte[] getMatrix() {
                    byte[] m = delegate.getMatrix();
                    byte[] inv = new byte[w * h];
                    for (int i = 0; i < inv.length; i++) {
                        inv[i] = (byte) (255 - (m[i] & 0xFF));
                    }
                    return inv;
                }
            };
        }
    }

    public static String decodeFromImageUri(Context ctx, Uri uri) throws WgStrings.WgException {
        if (ctx == null || uri == null) {
            throw new WgStrings.WgException(WgStrings.ErrorCode.FILE_READ_FAILED);
        }
        byte[] rawBytes;
        try (InputStream in = ctx.getContentResolver().openInputStream(uri)) {
            if (in == null) {
                throw new WgStrings.WgException(WgStrings.ErrorCode.FILE_READ_FAILED);
            }
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buf = new byte[16384];
            int n;
            int total = 0;
            // Cap raw image read at 16 MB for safety
            while ((n = in.read(buf)) != -1) {
                total += n;
                if (total > 16 * 1024 * 1024) {
                    break;
                }
                baos.write(buf, 0, n);
            }
            rawBytes = baos.toByteArray();
        } catch (WgStrings.WgException we) {
            throw we;
        } catch (Throwable t) {
            throw new WgStrings.WgException(WgStrings.ErrorCode.FILE_READ_FAILED, t.getMessage(), t);
        }

        if (rawBytes.length == 0) {
            throw new WgStrings.WgException(WgStrings.ErrorCode.FILE_READ_FAILED);
        }

        BitmapFactory.Options bounds = new BitmapFactory.Options();
        bounds.inJustDecodeBounds = true;
        BitmapFactory.decodeByteArray(rawBytes, 0, rawBytes.length, bounds);
        if (bounds.outWidth <= 0 || bounds.outHeight <= 0) {
            throw new WgStrings.WgException(WgStrings.ErrorCode.QR_NOT_FOUND);
        }

        int sampleSize = 1;
        int maxDim = Math.max(bounds.outWidth, bounds.outHeight);
        while (maxDim / sampleSize > 1600) {
            sampleSize *= 2;
        }

        BitmapFactory.Options decodeOpts = new BitmapFactory.Options();
        decodeOpts.inSampleSize = sampleSize;
        decodeOpts.inPreferredConfig = Bitmap.Config.ARGB_8888;
        Bitmap bmp = BitmapFactory.decodeByteArray(rawBytes, 0, rawBytes.length, decodeOpts);
        if (bmp == null) {
            throw new WgStrings.WgException(WgStrings.ErrorCode.QR_NOT_FOUND);
        }
        try {
            int w = bmp.getWidth();
            int h = bmp.getHeight();
            int[] pixels = new int[w * h];
            bmp.getPixels(pixels, 0, w, 0, 0, w, h);
            return decodeFromArgbPixels(pixels, w, h);
        } finally {
            bmp.recycle();
        }
    }
}
