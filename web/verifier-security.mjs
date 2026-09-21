import { classifyReference, shellQuote } from './lib/protocol.mjs';

export function buildNpxVerifyCommand(reference) {
  const parsed = classifyReference(reference);
  if (!['base_transaction_hash', 'arweave_transaction_id', 'legacy_cid'].includes(parsed.type) || parsed.errors.length) {
    return 'Enter a valid public reference to generate a command.';
  }
  return 'npx -y @confessionstxt/cli@latest verify -- ' + shellQuote(parsed.normalized);
}

// Inspect dimensions BEFORE decoding a hostile image or allocating a canvas.
export function inspectRasterImage(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let width, height, mime;
  if (bytes.length >= 33 && [137,80,78,71,13,10,26,10].every((b,i) => bytes[i] === b) &&
      view.getUint32(8) === 13 && view.getUint32(12) === 0x49484452) {
    width = view.getUint32(16); height = view.getUint32(20); mime = 'image/png';
  } else if (bytes[0] === 0xff && bytes[1] === 0xd8) {
    let i = 2;
    while (i + 3 < bytes.length) {
      if (bytes[i++] !== 0xff) break;
      while (bytes[i] === 0xff) i++;
      const marker = bytes[i++];
      if (marker === 0xda || marker === 0xd9) break;
      if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) continue;
      if (i + 2 > bytes.length) break;
      const length = view.getUint16(i);
      if (length < 2 || i + length > bytes.length) break;
      if ([0xc0,0xc1,0xc2].includes(marker) && length >= 8) {
        height = view.getUint16(i + 3); width = view.getUint16(i + 5); mime = 'image/jpeg'; break;
      }
      i += length;
    }
  }
  if (!width || !height || !mime) throw new Error('Preview supports standard JPEG and PNG images only. Download the original for local inspection.');
  if (width > 8192 || height > 8192 || width * height > 16_000_000) throw new Error('Image exceeds the 16 megapixel preview limit.');
  return { width, height, mime };
}
