// AES-256-GCM message encryption. The key is H1 = sha256(roomCode) - 32
// bytes, exactly an AES-256 key - and it never leaves this device (see
// store/vault.ts). A fresh random 12-byte IV is generated per message.
import { hexToBytes } from './hash.js';
import { bytesToB64, b64ToBytes } from './b64.js';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** Imports H1 (hex sha256 digest) as a non-extractable AES-256-GCM key. */
export async function importAesKey(h1Hex: string): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', hexToBytes(h1Hex) as BufferSource, { name: 'AES-GCM' }, false, [
    'encrypt',
    'decrypt',
  ]);
}

export interface EncBlob {
  iv: string; // base64, 12 bytes
  ct: string; // base64 ciphertext (includes the GCM auth tag)
}

export async function aesEncrypt(key: CryptoKey, plaintext: string): Promise<EncBlob> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoder.encode(plaintext));
  return { iv: bytesToB64(iv), ct: bytesToB64(ct) };
}

export async function aesDecrypt(key: CryptoKey, blob: EncBlob): Promise<string> {
  const iv = b64ToBytes(blob.iv);
  const ct = b64ToBytes(blob.ct);
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv as BufferSource }, key, ct as BufferSource);
  return decoder.decode(plaintext);
}

// Byte-oriented variants for image messages, which travel as raw bytes over
// REST (not JSON), not base64 - see net/rest.ts::uploadImage/fetchImage.
// The IV stays a small base64 string either way (12 bytes, cheap to carry
// in the message's JSON metadata); only the bulk ciphertext avoids the
// ~33% base64 bloat that the string-based aesEncrypt/aesDecrypt above pay
// for text messages, where it doesn't matter at that size.
export interface EncBytes {
  iv: string; // base64, 12 bytes
  ctBytes: Uint8Array;
}

export async function aesEncryptBytes(key: CryptoKey, plaintext: Uint8Array): Promise<EncBytes> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext as BufferSource);
  return { iv: bytesToB64(iv), ctBytes: new Uint8Array(ct) };
}

export async function aesDecryptBytes(key: CryptoKey, ivB64: string, ctBytes: Uint8Array): Promise<Uint8Array> {
  const iv = b64ToBytes(ivB64);
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv as BufferSource },
    key,
    ctBytes as BufferSource,
  );
  return new Uint8Array(plaintext);
}
