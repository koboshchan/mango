// WebSocket hub: one live-message channel per authenticated connection,
// fanning out to every socket subscribed to a room. Every accept path is
// checked in order - session, membership, proof-of-work, signature - and
// the first failure short-circuits with an `error` frame; nothing partial
// is ever persisted or broadcast. See messages.ts for the signature step
// and pow.ts for the anti-bot step. A solved proof-of-work is the only
// admission control on sending - there is deliberately no separate
// per-user volume cap, so a client that keeps solving challenges (at
// sendMessage's difficulty) can keep sending. See README threat model.
import type { Server as HttpServer } from 'node:http';
import { WebSocketServer, type WebSocket } from 'ws';
import { resolveSession } from '../auth.js';
import { isMember } from '../rooms.js';
import { issueChallenge, verifyAndBurn, type PowSubmission } from '../pow.js';
import { verifyAndPersistMessage, MessageRejected } from '../messages.js';

interface ClientState {
  username: string;
  subscribed: Set<string>;
}

const clients = new Map<WebSocket, ClientState>();

function send(ws: WebSocket, frame: Record<string, unknown>): void {
  if (ws.readyState === ws.OPEN) ws.send(JSON.stringify(frame));
}

function sendError(ws: WebSocket, code: string, message: string): void {
  send(ws, { type: 'error', code, message });
}

function broadcastToRoom(roomId: string, frame: Record<string, unknown>): void {
  for (const [socket, state] of clients) {
    if (state.subscribed.has(roomId)) send(socket, frame);
  }
}

interface InboundFrame {
  type: string;
  token?: string;
  roomId?: string;
  kind?: 'text' | 'image';
  iv?: string;
  ct?: string;
  ts?: number;
  sig?: string;
  clientRef?: string;
  pow?: PowSubmission;
  // Image-only, unsigned/cosmetic - see messages.ts.
  width?: number;
  height?: number;
  sizeBytes?: number;
}

async function handleAuth(ws: WebSocket, frame: InboundFrame): Promise<void> {
  const username = await resolveSession(frame.token);
  if (!username) {
    sendError(ws, 'unauthorized', 'Invalid or expired session');
    ws.close();
    return;
  }
  clients.set(ws, { username, subscribed: new Set() });
  const powChallenge = issueChallenge('sendMessage');
  send(ws, { type: 'ws.ready', username, powChallenge });
}

async function handleSubscribe(ws: WebSocket, state: ClientState, frame: InboundFrame): Promise<void> {
  const roomId = frame.roomId;
  if (!roomId) return sendError(ws, 'bad_request', 'roomId required');

  const member = await isMember(state.username, roomId);
  if (!member) return sendError(ws, 'forbidden', 'Not a member of this room');

  state.subscribed.add(roomId);
  send(ws, { type: 'room.subscribed', roomId });
}

async function handleSend(ws: WebSocket, state: ClientState, frame: InboundFrame): Promise<void> {
  const { roomId, kind, iv, ct, ts, sig, clientRef, width, height, sizeBytes } = frame;
  if (!roomId || !kind || !iv || !ct || ts === undefined || !sig) {
    return sendError(ws, 'bad_request', 'Malformed message frame');
  }

  const member = await isMember(state.username, roomId);
  if (!member) return sendError(ws, 'forbidden', 'Not a member of this room');

  if (!verifyAndBurn('sendMessage', frame.pow)) {
    return sendError(ws, 'pow_failed', 'Proof of work missing, invalid, or already used');
  }

  try {
    const doc = await verifyAndPersistMessage({
      roomId,
      sender: state.username,
      kind,
      iv,
      ct,
      ts,
      sig,
      width,
      height,
      sizeBytes,
    });

    const nextPow = issueChallenge('sendMessage');
    send(ws, { type: 'msg.ack', clientRef, id: doc._id, serverTs: doc.serverTs, powChallenge: nextPow });

    broadcastToRoom(roomId, {
      type: 'msg.new',
      id: doc._id,
      roomId: doc.roomId,
      sender: doc.sender,
      kind: doc.kind,
      iv: doc.iv,
      ct: doc.ct,
      width: doc.width,
      height: doc.height,
      sizeBytes: doc.sizeBytes,
      ts: doc.ts,
      sig: doc.sig,
      serverTs: doc.serverTs,
    });
  } catch (err) {
    if (err instanceof MessageRejected) {
      // Covers bad/missing signatures, out-of-window timestamps, and
      // replay of an already-stored message (see messages.ts) - err.message
      // carries the specific reason, this code just marks "not accepted".
      sendError(ws, 'message_rejected', err.message);
    } else {
      sendError(ws, 'server_error', 'Failed to store message');
    }
  }
}

export function attachWsHub(server: HttpServer): void {
  const wss = new WebSocketServer({ server, path: '/ws' });

  wss.on('connection', (ws) => {
    ws.on('message', (raw) => {
      void (async () => {
        let frame: InboundFrame;
        try {
          frame = JSON.parse(raw.toString());
        } catch {
          return sendError(ws, 'bad_request', 'Malformed JSON frame');
        }

        if (frame.type === 'ws.auth') {
          return handleAuth(ws, frame);
        }

        const state = clients.get(ws);
        if (!state) {
          return sendError(ws, 'unauthorized', 'Send ws.auth first');
        }

        switch (frame.type) {
          case 'room.subscribe':
            return handleSubscribe(ws, state, frame);
          case 'msg.send':
            return handleSend(ws, state, frame);
          default:
            return sendError(ws, 'bad_request', `Unknown frame type: ${frame.type}`);
        }
      })();
    });

    ws.on('close', () => {
      clients.delete(ws);
    });
  });
}
