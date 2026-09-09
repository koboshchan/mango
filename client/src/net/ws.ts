// WebSocket client: auth handshake, room subscriptions, signed send/receive,
// and reconnect-with-resubscribe. Keeps a proof-of-work solution "pre-baked"
// for the next sendMessage so pressing enter never has to wait on a round
// trip or on hashing (difficulty for sendMessage is intentionally tiny -
// see server/src/pow.ts - so this resolves near-instantly anyway).
import { solvePow, type PowChallenge } from '../crypto/pow.js';

export interface InboundMsgNew {
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

export interface InboundAck {
  clientRef: string;
  id: string;
  serverTs: number;
  powChallenge: PowChallenge;
}

export interface InboundError {
  code: string;
  message: string;
}

type Listener<T> = (payload: T) => void;

export class ChatSocket {
  private ws: WebSocket | null = null;
  private token: string;
  private subscribedRooms = new Set<string>();
  private pendingPow: Promise<{ challenge: string; nonce: string }> | null = null;
  private reconnectAttempt = 0;
  private closedByUser = false;

  private onReady = new Set<Listener<{ username: string }>>();
  private onSubscribed = new Set<Listener<{ roomId: string }>>();
  private onMessage = new Set<Listener<InboundMsgNew>>();
  private onAck = new Set<Listener<InboundAck>>();
  private onErrorCb = new Set<Listener<InboundError>>();
  private onDisconnected = new Set<Listener<void>>();

  constructor(token: string) {
    this.token = token;
  }

  onReadyEvent(cb: Listener<{ username: string }>): void {
    this.onReady.add(cb);
  }
  onSubscribedEvent(cb: Listener<{ roomId: string }>): void {
    this.onSubscribed.add(cb);
  }
  onMessageEvent(cb: Listener<InboundMsgNew>): void {
    this.onMessage.add(cb);
  }
  onAckEvent(cb: Listener<InboundAck>): void {
    this.onAck.add(cb);
  }
  onErrorEvent(cb: Listener<InboundError>): void {
    this.onErrorCb.add(cb);
  }
  onDisconnectedEvent(cb: Listener<void>): void {
    this.onDisconnected.add(cb);
  }

  connect(): void {
    this.closedByUser = false;
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    this.ws = new WebSocket(`${proto}//${location.host}/ws`);

    this.ws.onopen = () => {
      this.reconnectAttempt = 0;
      this.send({ type: 'ws.auth', token: this.token });
    };

    this.ws.onmessage = (ev) => {
      let frame: Record<string, unknown>;
      try {
        frame = JSON.parse(ev.data as string);
      } catch {
        return;
      }
      this.handleFrame(frame);
    };

    this.ws.onclose = () => {
      for (const cb of this.onDisconnected) cb();
      if (!this.closedByUser) this.scheduleReconnect();
    };
  }

  close(): void {
    this.closedByUser = true;
    this.ws?.close();
  }

  private scheduleReconnect(): void {
    const delay = Math.min(1000 * 2 ** this.reconnectAttempt, 15000);
    this.reconnectAttempt++;
    setTimeout(() => {
      if (this.closedByUser) return;
      this.connect();
    }, delay);
  }

  private handleFrame(frame: Record<string, unknown>): void {
    switch (frame.type) {
      case 'ws.ready': {
        this.primePow(frame.powChallenge as PowChallenge);
        for (const cb of this.onReady) cb({ username: frame.username as string });
        // Re-subscribe to whatever rooms we were watching before a reconnect.
        for (const roomId of this.subscribedRooms) this.send({ type: 'room.subscribe', roomId });
        break;
      }
      case 'room.subscribed':
        for (const cb of this.onSubscribed) cb({ roomId: frame.roomId as string });
        break;
      case 'msg.new':
        for (const cb of this.onMessage) cb(frame as unknown as InboundMsgNew);
        break;
      case 'msg.ack':
        this.primePow(frame.powChallenge as PowChallenge);
        for (const cb of this.onAck) cb(frame as unknown as InboundAck);
        break;
      case 'error':
        for (const cb of this.onErrorCb) cb(frame as unknown as InboundError);
        break;
    }
  }

  private primePow(challenge: PowChallenge | undefined): void {
    if (!challenge) return;
    this.pendingPow = solvePow(challenge.challenge, challenge.difficulty);
  }

  private send(frame: Record<string, unknown>): void {
    this.ws?.send(JSON.stringify(frame));
  }

  subscribeRoom(roomId: string): void {
    this.subscribedRooms.add(roomId);
    this.send({ type: 'room.subscribe', roomId });
  }

  async sendMessage(input: {
    roomId: string;
    kind: 'text' | 'image';
    iv: string;
    ct: string;
    width?: number;
    height?: number;
    sizeBytes?: number;
    ts: number;
    sig: string;
    clientRef: string;
  }): Promise<void> {
    if (!this.pendingPow) throw new Error('Not authenticated yet - no PoW challenge available');
    const pow = await this.pendingPow;
    this.pendingPow = null; // consumed; primed again by the server's ack/ready
    this.send({ ...input, type: 'msg.send', pow });
  }
}
