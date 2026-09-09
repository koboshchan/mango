// Client-side image resize/compress, run before anything ever leaves the
// browser (see crypto/aes.ts::aesEncryptBytes for the encryption step right
// after this). Always re-encodes to JPEG via <canvas>, which is also a
// deliberate sanitization step: the original file's bytes are never stored
// or transmitted, only a freshly rasterized copy, so anything hidden in a
// disguised non-image file can't survive the raster round-trip.
export const MAX_DIMENSION = 1024;
export const MAX_BYTES = 1_048_576;

const QUALITY_STEPS = [0.85, 0.7, 0.55, 0.4];

export interface PreparedImage {
  bytes: Uint8Array;
  width: number;
  height: number;
}

function drawScaled(bitmap: ImageBitmap, width: number, height: number): HTMLCanvasElement {
  const canvas = document.createElement('canvas');
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext('2d');
  if (!ctx) throw new Error('Canvas 2D context unavailable');
  ctx.drawImage(bitmap, 0, 0, width, height);
  return canvas;
}

function canvasToJpegBlob(canvas: HTMLCanvasElement, quality: number): Promise<Blob | null> {
  return new Promise((resolve) => canvas.toBlob(resolve, 'image/jpeg', quality));
}

/** Tries each quality step at a fixed size, returning the first blob that fits under MAX_BYTES, or null if none do. */
async function compressAtSize(bitmap: ImageBitmap, width: number, height: number): Promise<Blob | null> {
  const canvas = drawScaled(bitmap, width, height);
  for (const quality of QUALITY_STEPS) {
    const blob = await canvasToJpegBlob(canvas, quality);
    if (blob && blob.size <= MAX_BYTES) return blob;
  }
  return null;
}

/**
 * Resizes (never upscales) so both dimensions are <=1024px, then steps JPEG
 * quality down until the result is <=1MB. If even the lowest quality step
 * doesn't fit, halves the dimensions once and retries - if that still
 * doesn't fit, gives up with a clear error rather than looping forever.
 */
export async function prepareImage(file: File): Promise<PreparedImage> {
  if (!file.type.startsWith('image/')) {
    throw new Error('Not an image file');
  }

  const bitmap = await createImageBitmap(file);
  try {
    const scale = Math.min(1, MAX_DIMENSION / bitmap.width, MAX_DIMENSION / bitmap.height);
    let width = Math.max(1, Math.round(bitmap.width * scale));
    let height = Math.max(1, Math.round(bitmap.height * scale));

    let blob = await compressAtSize(bitmap, width, height);
    if (!blob) {
      // One fallback pass: halve dimensions and try the quality steps again.
      width = Math.max(1, Math.round(width / 2));
      height = Math.max(1, Math.round(height / 2));
      blob = await compressAtSize(bitmap, width, height);
    }
    if (!blob) {
      throw new Error('Image is too complex to compress under 1MB - try a smaller or simpler image.');
    }

    const bytes = new Uint8Array(await blob.arrayBuffer());
    return { bytes, width, height };
  } finally {
    bitmap.close();
  }
}
