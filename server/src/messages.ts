// Message persistence and signature enforcement. The server stores and
// forwards only { iv, ct } - the AES-GCM ciphertext and its nonce (or, for
// an image message, a reference to a separately-stored ciphertext blob -
// see below). It can never decrypt these (it never has H1, the AES key).
// What it *can* and must do is verify the Ed25519 signature over the
// message before accepting it, using the sender's public key registered at
// signup; anything unsigned or with an invalid signature is rejected and
// never written to the DB.
//
// A valid signature proves authorship, not freshness: resubmitting an
// old, already-stored (roomId, sender, ts, iv, ct, sig) tuple verifies just
// as well the second time, since it's byte-identical to the first. To stop
// that replay, `_id` is derived deterministically from the signed content
// rather than a fresh random UUID, so an identical resubmission collides on
// insert (Mongo's unique _id index) instead of quietly becoming a second
// message. Two distinct legitimate messages would only collide if roomId,
// sender, ts (millisecond) AND the 12 random IV bytes all matched -
// astronomically unlikely.
//
// Image messages reuse this exact machinery for free: `ct` is the
// sha256(ciphertext) id of a blob stored separately (see images.ts), and
// since `ct` is part of the signed canonical string, a malicious server
// can't swap the referenced blob without invalidating the signature - no
// new crypto invariant needed. `kind` is folded into the canonical string
// too, so it can't be flipped post-signature either. This is the first
// place in this file that reads a second collection (images) - see the
// comment on that check below.
import { getDb, type MessageDoc } from './db.js';
import { getUserPublicKey } from './auth.js';
import { verifyEd25519 } from './sig.js';
import { sha256Hex } from './pow.js';
import { isDuplicateKeyError } from './mongoErrors.js';
import { imageExistsInRoom } from './images.js';

export interface IncomingMessage {
  roomId: string;
  sender: string;
  kind: 'text' | 'image';
  iv: string;
  ct: string;
  ts: number;
  sig: string;
  // Image-only, unsigned/cosmetic (see canonicalMessage) - a layout hint,
  // never trusted for anything security-relevant.
  width?: number;
  height?: number;
  sizeBytes?: number;
}

export class MessageRejected extends Error {}

// How far a claimed `ts` may drift from the server's own clock. Bounds how
// far in the future an attacker could usefully pre-sign a message, and
// stops a message from being back/post-dated to distort room ordering.
const TS_WINDOW_MS = 5 * 60 * 1000;

/** The exact byte string the client signs and the server re-derives to verify. Must match client/src/ui/chat.ts's two hand-copies of this string exactly. */
export function canonicalMessage(
  m: Pick<IncomingMessage, 'roomId' | 'sender' | 'ts' | 'iv' | 'ct' | 'kind'>,
): string {
  return `${m.roomId}|${m.sender}|${m.ts}|${m.iv}|${m.ct}|${m.kind}`;
}

function isValidShape(m: IncomingMessage): boolean {
  const base =
    typeof m.roomId === 'string' &&
    typeof m.sender === 'string' &&
    (m.kind === 'text' || m.kind === 'image') &&
    typeof m.iv === 'string' &&
    typeof m.ct === 'string' &&
    typeof m.ts === 'number' &&
    Number.isFinite(m.ts) &&
    typeof m.sig === 'string' &&
    m.sig.length > 0;
  if (!base) return false;
  if (m.kind === 'image') {
    return Number.isFinite(m.width) && Number.isFinite(m.height) && Number.isFinite(m.sizeBytes);
  }
  return true;
}

/**
 * Verifies signature and persists. Caller (ws/hub.ts) must already have
 * checked session validity, room membership, and proof-of-work before
 * calling this - this function only handles the signature/storage step.
 * Throws MessageRejected (never stores anything) if the signature is
 * missing, does not verify against the sender's registered public key, the
 * timestamp is out of window, or this exact message was already stored.
 */
export async function verifyAndPersistMessage(input: IncomingMessage): Promise<MessageDoc> {
  if (!isValidShape(input)) throw new MessageRejected('Malformed message');
  if (Math.abs(Date.now() - input.ts) > TS_WINDOW_MS) throw new MessageRejected('Timestamp too far from server time');

  const edPubB64 = await getUserPublicKey(input.sender);
  if (!edPubB64) throw new MessageRejected('Unknown sender');

  const data = canonicalMessage(input);
  const ok = await verifyEd25519(edPubB64, data, input.sig);
  if (!ok) throw new MessageRejected('Invalid or missing signature');

  if (input.kind === 'image') {
    // The signature above already proves the sender committed to this
    // exact `ct` (= the image blob's content-addressed id) at send time,
    // but says nothing about whether that blob was ever actually uploaded,
    // or uploaded for *this* room. Both must be checked explicitly - this
    // is the only place a message doc's validity depends on a second
    // collection, so it doesn't fall out of the signature check for free
    // the way ciphertext-swap tampering does.
    if (!(await imageExistsInRoom(input.ct, input.roomId))) {
      throw new MessageRejected('Referenced image not found');
    }
  }

  const doc: MessageDoc = {
    _id: sha256Hex(data),
    roomId: input.roomId,
    sender: input.sender,
    kind: input.kind,
    iv: input.iv,
    ct: input.ct,
    ts: input.ts,
    sig: input.sig,
    serverTs: Date.now(),
    ...(input.kind === 'image' ? { width: input.width, height: input.height, sizeBytes: input.sizeBytes } : {}),
  };

  try {
    await getDb().messages.insertOne(doc);
  } catch (err) {
    if (isDuplicateKeyError(err)) throw new MessageRejected('Duplicate message (replay)');
    throw err;
  }

  return doc;
}

export async function getHistory(
  roomId: string,
  before: number | undefined,
  limit: number,
): Promise<MessageDoc[]> {
  const query: Record<string, unknown> = { roomId };
  if (before !== undefined) query.serverTs = { $lt: before };

  const docs = await getDb()
    .messages.find(query)
    .sort({ serverTs: -1 })
    .limit(Math.min(Math.max(limit, 1), 200))
    .toArray();

  return docs.reverse(); // ascending, ready to render top-to-bottom
}
