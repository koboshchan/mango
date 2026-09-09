// Encrypted image blob storage. The server only ever holds AES-GCM
// ciphertext bytes it cannot decrypt - see client/src/media/imagePrep.ts
// for the client-side resize/compress step and client/src/crypto/aes.ts for
// the byte-oriented encryption. Stored as real bytes (BSON Binary) in
// Mongo, not base64 text, per the same "server sees as little as possible"
// posture as every other collection in this app.
import { getDb } from './db.js';
import { sha256Hex } from './pow.js';
import { isDuplicateKeyError } from './mongoErrors.js';

// Hard cap enforced here in code, not just implied by the upload route's
// body-parser limit (which is given real margin so a functionally-valid
// compressed image is never rejected on a byte-counting technicality - see
// routes/api.ts). This is the actual 1MB rule.
export const MAX_IMAGE_BYTES = 1_048_576;

/**
 * Stores an encrypted image blob, keyed by the sha256 of its own bytes
 * (computed here, never trusted from the client) - this content-addressing
 * is what lets a MessageDoc's signed `ct` field double as the blob's
 * lookup key with no separate id to generate or trust (see messages.ts).
 * Re-uploading identical ciphertext is idempotent: a duplicate-key insert
 * just means the blob is already stored, which is the same outcome as if
 * this were the first upload, so it's treated as success rather than an
 * error - same pattern as rooms.ts::createRoom / auth.ts::registerUser.
 */
export async function storeImage(roomId: string, data: Buffer): Promise<string> {
  const id = sha256Hex(data);
  try {
    await getDb().images.insertOne({ _id: id, roomId, data, createdAt: new Date() });
  } catch (err) {
    if (!isDuplicateKeyError(err)) throw err;
  }
  return id;
}

export interface StoredImage {
  roomId: string;
  data: Buffer;
}

export async function getImage(imageId: string): Promise<StoredImage | null> {
  const doc = await getDb().images.findOne({ _id: imageId });
  if (!doc) return null;
  // The driver always hands binary fields back as a BSON Binary wrapper on
  // read, never as the plain Buffer that was inserted - passing that
  // wrapper straight to Express's res.send() silently JSON-stringifies it
  // (Binary#toJSON() returns a base64 string), which serializes the whole
  // response as quoted base64 text instead of the raw bytes it looks like
  // it should be. Unwrap explicitly so callers always get real bytes.
  const data = Buffer.isBuffer(doc.data) ? doc.data : Buffer.from((doc.data as unknown as { buffer: Buffer }).buffer);
  return { roomId: doc.roomId, data };
}

/** Whether an image with this id exists and belongs to `roomId` - used to bind an image message to the room it's allowed to appear in (see messages.ts). */
export async function imageExistsInRoom(imageId: string, roomId: string): Promise<boolean> {
  const doc = await getDb().images.findOne({ _id: imageId }, { projection: { roomId: 1 } });
  return doc !== null && doc.roomId === roomId;
}
