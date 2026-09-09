// Proof-of-work anti-bot gate, stateless variant.
//
// A challenge is a self-describing, HMAC-authenticated string:
//   `${op}.${expiresAtMs}.${randomHex}.${hmacHex}`
// where hmacHex = HMAC-SHA256(secret, `${op}.${expiresAtMs}.${randomHex}`).
// Issuing a challenge therefore stores NOTHING server-side - the server can
// hand out an unlimited number of challenges for free without growing any
// in-memory state. (The previous Map-based design stored every issued
// challenge for 5 minutes regardless of whether it was ever solved: pulling
// 20,000 challenges took ~4s and zero cost of the caller's own, an
// unauthenticated memory-exhaustion vector against the anti-abuse mechanism
// itself.)
//
// The client still just counts up in hex, appending its guess as a string
// onto the whole opaque challenge, exactly as before - solving is unchanged
// and needs no protocol update, only a longer opaque string.
//
// Single-use enforcement (so a captured *valid* solution can't be replayed)
// only records challenges that were actually, successfully solved - i.e.
// memory use is bounded by real attacker CPU work, not by how many
// challenges they merely requested. That's what makes it self-limiting by
// construction rather than needing a separate cap.
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { POW_TTL_MS } from './config.js';

export type PowOp =
  | 'register'
  | 'createRoom'
  | 'login'
  | 'joinRoom'
  | 'sendMessage'
  | 'history'
  | 'userKey'
  | 'uploadImage'
  | 'image';

// Rough expected work at 16^d hashes. sendMessage/history/userKey are kept
// low so interactive actions don't feel throttled - a solved challenge is
// the only admission control on these endpoints; there is deliberately no
// separate volume/rate cap (see README threat model). uploadImage sits with
// register/createRoom since it's a heavier, deliberate one-shot action
// rather than a per-keystroke one; image (fetching a blob) is as cheap as
// history since it happens once per rendered image.
export const POW_DIFFICULTY: Record<PowOp, number> = {
  register: 5,
  createRoom: 5,
  login: 4,
  joinRoom: 4,
  sendMessage: 3,
  history: 2,
  userKey: 2,
  uploadImage: 4,
  image: 2,
};

// Generated fresh at boot, in memory only, never persisted. A restart
// invalidates every outstanding challenge - clients transparently
// re-request, same externally-visible behavior as before - and just as
// importantly resets the burned set consistently with it, so there's never
// a window where a challenge solved under a since-rotated secret could
// still be replayed.
const HMAC_SECRET = randomBytes(32);

export function sha256Hex(input: string | Buffer): string {
  return createHash('sha256').update(input).digest('hex');
}

function hmacFor(op: string, expiresAt: string, random: string): string {
  return createHmac('sha256', HMAC_SECRET).update(`${op}.${expiresAt}.${random}`).digest('hex');
}

export interface IssuedChallenge {
  challenge: string;
  difficulty: number;
  expiresAt: number;
}

export function issueChallenge(op: PowOp): IssuedChallenge {
  const expiresAt = Date.now() + POW_TTL_MS;
  const random = randomBytes(16).toString('hex');
  const hmac = hmacFor(op, String(expiresAt), random);
  return { challenge: `${op}.${expiresAt}.${random}.${hmac}`, difficulty: POW_DIFFICULTY[op], expiresAt };
}

export interface PowSubmission {
  challenge: string;
  nonce: string;
}

// Only ever holds challenges that were actually, successfully solved -
// bounded by real PoW work performed, not by how many were merely issued.
const burned = new Set<string>();

interface ParsedChallenge {
  op: string;
  expiresAt: number;
  random: string;
  hmac: string;
}

function parseChallenge(challenge: string): ParsedChallenge | null {
  const parts = challenge.split('.');
  if (parts.length !== 4) return null;
  const [op, expiresAtStr, random, hmac] = parts;
  const expiresAt = Number(expiresAtStr);
  if (!op || !random || !hmac || !Number.isFinite(expiresAt)) return null;
  return { op, expiresAt, random, hmac };
}

/**
 * Verifies a solved challenge for the given operation. Only a genuinely
 * valid solution is ever recorded (burned) for replay protection - an
 * invalid-nonce attempt leaves no trace, since the challenge itself carries
 * no server-side state until it's actually solved.
 */
export function verifyAndBurn(op: PowOp, submission: PowSubmission | undefined | null): boolean {
  if (!submission || !submission.challenge || !submission.nonce) return false;

  const parsed = parseChallenge(submission.challenge);
  if (!parsed) return false;

  // Reject anything tampered with or simply made up, before trusting any
  // of its fields (op, expiry) for the checks below.
  const expected = Buffer.from(hmacFor(parsed.op, String(parsed.expiresAt), parsed.random), 'hex');
  const actual = Buffer.from(parsed.hmac, 'hex');
  if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) return false;

  if (parsed.op !== op) return false;
  if (Date.now() > parsed.expiresAt) return false;

  const digest = sha256Hex(submission.challenge + submission.nonce);
  if (!digest.endsWith('0'.repeat(POW_DIFFICULTY[op]))) return false;

  if (burned.has(submission.challenge)) return false; // already spent
  burned.add(submission.challenge);
  return true;
}

// Periodic sweep: once a challenge's own embedded expiry has passed it
// could never be legitimately resubmitted anyway, so it's always safe to
// drop from the burned set at that point. Bounds its size to "however many
// challenges were actually solved within one TTL window."
const sweepInterval = setInterval(() => {
  const now = Date.now();
  for (const challenge of burned) {
    const parsed = parseChallenge(challenge);
    if (!parsed || now > parsed.expiresAt) burned.delete(challenge);
  }
}, POW_TTL_MS);
sweepInterval.unref();
