// Typed REST client. Wires up the bearer session token and proof-of-work
// automatically for every endpoint that needs one - see the REST surface
// table in the project plan / README for which endpoints require which.
import { fetchAndSolvePow, type PowSolution } from '../crypto/pow.js';
import { getSession } from '../store/vault.js';

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

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export type ProgressCb = (attempts: number, estimatedTotal: number) => void;

async function authHeader(): Promise<string | undefined> {
  const session = await getSession();
  return session ? `Bearer ${session.token}` : undefined;
}

async function rawFetch<T>(path: string, init: RequestInit): Promise<T> {
  const headers = new Headers(init.headers);
  const bearer = await authHeader();
  if (bearer) headers.set('authorization', bearer);
  if (init.body) headers.set('content-type', 'application/json');

  const res = await fetch(path, { ...init, headers });
  const isJson = res.headers.get('content-type')?.includes('application/json');
  const body = isJson ? await res.json() : undefined;

  if (!res.ok) {
    throw new ApiError(res.status, (body && body.error) || res.statusText);
  }
  return body as T;
}

/** POST with a PoW solution merged into the JSON body under `pow`. */
async function postWithPow<T>(
  path: string,
  op: PowOp,
  body: Record<string, unknown>,
  onProgress?: ProgressCb,
): Promise<T> {
  const pow = await fetchAndSolvePow(op, onProgress);
  return rawFetch<T>(path, { method: 'POST', body: JSON.stringify({ ...body, pow }) });
}

/** GET with a PoW solution appended as query params (GETs have no body). */
async function getWithPow<T>(
  path: string,
  op: PowOp,
  params: Record<string, string>,
  onProgress?: ProgressCb,
): Promise<T> {
  const pow = await fetchAndSolvePow(op, onProgress);
  const qs = new URLSearchParams({ ...params, challenge: pow.challenge, nonce: pow.nonce });
  return rawFetch<T>(`${path}?${qs.toString()}`, { method: 'GET' });
}

// --- Registration & login ---

export function register(
  username: string,
  phEnc: string,
  edPubB64: string,
  onProgress?: ProgressCb,
): Promise<{ ok: true }> {
  return postWithPow('/api/register', 'register', { username, phEnc, edPubB64 }, onProgress);
}

export function loginChallenge(username: string, onProgress?: ProgressCb): Promise<{ salt: string }> {
  return postWithPow('/api/login/challenge', 'login', { username }, onProgress);
}

export function login(
  username: string,
  salt: string,
  proof: string,
  onProgress?: ProgressCb,
): Promise<{ token: string; expiresAt: number; edPubB64: string }> {
  return postWithPow('/api/login', 'login', { username, salt, proof }, onProgress);
}

export function logout(): Promise<{ ok: true }> {
  return rawFetch('/api/logout', { method: 'POST' });
}

export function getUserKey(username: string, onProgress?: ProgressCb): Promise<{ edPubB64: string }> {
  return getWithPow(`/api/users/${encodeURIComponent(username)}/key`, 'userKey', {}, onProgress);
}

// --- Rooms ---

export interface EncBlob {
  iv: string;
  ct: string;
}

export function createRoom(
  roomIdEnc: string,
  nameEnc: EncBlob,
  onProgress?: ProgressCb,
): Promise<{ roomId: string }> {
  return postWithPow('/api/rooms/create', 'createRoom', { roomIdEnc, nameEnc }, onProgress);
}

export function joinRoom(
  roomIdEnc: string,
  onProgress?: ProgressCb,
): Promise<{ roomId: string; nameEnc: EncBlob }> {
  return postWithPow('/api/rooms/join', 'joinRoom', { roomIdEnc }, onProgress);
}

export function listRooms(): Promise<{ rooms: Array<{ roomId: string; nameEnc: EncBlob; joinedAt: string }> }> {
  return rawFetch('/api/rooms', { method: 'GET' });
}

export interface HistoryMessage {
  id: string;
  roomId: string;
  sender: string;
  kind: 'text' | 'image';
  iv: string;
  ct: string;
  width?: number;
  height?: number;
  sizeBytes?: number;
  ts: number;
  sig: string;
  serverTs: number;
}

export function getHistory(
  roomId: string,
  before?: number,
  limit = 50,
  onProgress?: ProgressCb,
): Promise<{ messages: HistoryMessage[] }> {
  const params: Record<string, string> = { limit: String(limit) };
  if (before !== undefined) params.before = String(before);
  return getWithPow(`/api/rooms/${encodeURIComponent(roomId)}/messages`, 'history', params, onProgress);
}

// --- Images ---
//
// Raw bytes in both directions, not JSON - these deliberately bypass
// rawFetch (which always sets Content-Type: application/json whenever a
// body is present, and always tries to parse the response as JSON) since
// neither is true here.

/** Uploads already-encrypted image bytes; returns the server-computed content-addressed id. */
export async function uploadImage(
  roomId: string,
  bytes: Uint8Array,
  onProgress?: ProgressCb,
): Promise<{ imageId: string }> {
  const pow = await fetchAndSolvePow('uploadImage', onProgress);
  const qs = new URLSearchParams({ challenge: pow.challenge, nonce: pow.nonce });
  const headers = new Headers({ 'content-type': 'application/octet-stream' });
  const bearer = await authHeader();
  if (bearer) headers.set('authorization', bearer);

  const res = await fetch(`/api/rooms/${encodeURIComponent(roomId)}/images?${qs.toString()}`, {
    method: 'POST',
    headers,
    body: bytes as BodyInit,
  });
  if (!res.ok) {
    const body = res.headers.get('content-type')?.includes('application/json') ? await res.json() : undefined;
    throw new ApiError(res.status, (body && body.error) || res.statusText);
  }
  return res.json() as Promise<{ imageId: string }>;
}

/** Fetches and returns an image's raw (still-encrypted) bytes. */
export async function fetchImage(imageId: string, onProgress?: ProgressCb): Promise<Uint8Array> {
  const pow = await fetchAndSolvePow('image', onProgress);
  const qs = new URLSearchParams({ challenge: pow.challenge, nonce: pow.nonce });
  const headers = new Headers();
  const bearer = await authHeader();
  if (bearer) headers.set('authorization', bearer);

  const res = await fetch(`/api/images/${encodeURIComponent(imageId)}?${qs.toString()}`, { headers });
  if (!res.ok) {
    const body = res.headers.get('content-type')?.includes('application/json') ? await res.json() : undefined;
    throw new ApiError(res.status, (body && body.error) || res.statusText);
  }
  return new Uint8Array(await res.arrayBuffer());
}

export type { PowSolution };
