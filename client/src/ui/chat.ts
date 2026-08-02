// Chat screen: renders history + live messages for the open room, sends
// signed+encrypted messages, and shows the local Ed25519 identity
// fingerprint (for out-of-band comparison - see README threat model). The
// identity itself is derived from the account password (crypto/identity.ts)
// so there's no export/import step to move between devices.
//
// Rendering pipeline per message, strictly in this order:
//   1. Resolve the sender's Ed25519 public key (REST + trust-on-first-use
//      pin, see store/vault.ts::checkAndPinPeer). A pin mismatch is treated
//      as untrusted - the message is never decrypted, only flagged.
//   2. Verify the signature over the exact canonical string the server
//      checked (roomId|sender|ts|iv|ct). Anything that fails is rendered as
//      a visibly invalid row and never decrypted.
//   3. Only then AES-GCM-decrypt with the local room key (H1) and render
//      via textContent - never innerHTML, which is what made the original
//      index.html vulnerable to a stored-XSS via message text.
//
// Message data vs. DOM are deliberately decoupled: `allMessages` holds
// every message fetched for the currently open room (ascending by
// serverTs), each resolved (verified + decrypted) at most once and cached
// on the entry itself. The DOM only ever holds a contiguous window
// [windowStart, windowEnd) of that array, capped at MAX_RENDERED rows -
// scrolling toward either edge grows the window (from memory if already
// loaded, from the network only when paging past what's been fetched so
// far), and growing past the cap trims from whichever edge is furthest
// from the viewport. This keeps a long-lived room from turning into an
// ever-growing DOM while still letting the user page back through history.
import { aesEncrypt, aesDecrypt, importAesKey, type EncBlob } from '../crypto/aes.js';
import { signMessage, verifyMessage, fingerprint, fingerprintFromRawB64 } from '../crypto/identity.js';
import * as api from '../net/rest.js';
import type { InboundMsgNew, InboundError } from '../net/ws.js';
import { checkAndPinPeer, listRoomsLocal, type StoredRoom } from '../store/vault.js';
import { showRoomsScreen } from './screens.js';
import { state } from '../state.js';

function el<T extends HTMLElement>(id: string): T {
  return document.getElementById(id) as T;
}

// How many messages a single history fetch pulls, the hard cap on rendered
// DOM rows, the count trimming settles at once that cap is exceeded, and
// how close to an edge (px) triggers loading the next page in that
// direction.
const FETCH_LIMIT = 100;
const MAX_RENDERED = 500;
const TRIM_TO = 400;
const SCROLL_TRIGGER_PX = 150;

interface LoadedMessage {
  id: string;
  roomId: string;
  sender: string;
  iv: string;
  ct: string;
  ts: number;
  sig: string;
  serverTs: number;
  /** Verified/decrypted exactly once, then cached here for as long as the message stays in memory. */
  resolved?: { valid: boolean; text: string };
}

function toLoadedMessage(m: api.HistoryMessage | InboundMsgNew): LoadedMessage {
  return { id: m.id, roomId: m.roomId, sender: m.sender, iv: m.iv, ct: m.ct, ts: m.ts, sig: m.sig, serverTs: m.serverTs };
}

export interface ChatController {
  openRoom: (room: StoredRoom) => Promise<void>;
  handleIncomingMessage: (m: InboundMsgNew) => void;
  handleWsError: (err: InboundError) => void;
}

export function wireChatScreen(): ChatController {
  const chatHeaderTitle = el<HTMLElement>('chat-header-title');
  const messagesBox = el<HTMLElement>('messages-box');
  const messageInput = el<HTMLInputElement>('message-input');
  const backBtn = el<HTMLElement>('back-to-rooms');
  const channelList = el<HTMLElement>('channel-list');
  const userDisplay = el<HTMLElement>('logged-user-display');
  const logoutBtn = el<HTMLButtonElement>('chat-logout-btn');
  const fpEl = el<HTMLElement>('identity-fingerprint');
  const sidebar = el<HTMLElement>('chat-sidebar');
  const sidebarBackdrop = el<HTMLElement>('sidebar-backdrop');
  const menuToggleBtn = el<HTMLButtonElement>('menu-toggle-btn');

  // Off-canvas sidebar drawer, only actually visible below the 768px
  // breakpoint (see index.html's @media block) - on desktop the sidebar is
  // always a static column and these classes are simply inert.
  function openDrawer(): void {
    sidebar.classList.add('open');
    sidebarBackdrop.classList.add('open');
  }
  function closeDrawer(): void {
    sidebar.classList.remove('open');
    sidebarBackdrop.classList.remove('open');
  }
  menuToggleBtn.addEventListener('click', openDrawer);
  sidebarBackdrop.addEventListener('click', closeDrawer);

  let currentAesKey: CryptoKey | null = null;

  // Per-room message state, reset on every openRoom() call - see the file
  // header for the data/DOM split this implements.
  let allMessages: LoadedMessage[] = [];
  let knownIds = new Set<string>();
  let windowStart = 0; // inclusive index into allMessages currently rendered
  let windowEnd = 0; // exclusive index into allMessages currently rendered
  let historyExhausted = false; // true once a page came back shorter than FETCH_LIMIT
  let loadingOlder = false;
  let loadingNewer = false;

  async function refreshIdentityPanel(): Promise<void> {
    if (!state.identity) return;
    fpEl.textContent = await fingerprint(state.identity.publicKey);
  }

  async function renderChannelList(activeRoomId: string): Promise<void> {
    const rooms = state.username ? await listRoomsLocal(state.username) : [];
    channelList.innerHTML = '';
    for (const room of rooms) {
      const div = document.createElement('div');
      div.className = 'channel' + (room.roomId === activeRoomId ? ' active' : '');
      div.textContent = room.name; // textContent, not innerHTML
      div.addEventListener('click', () => {
        void openRoom(room);
      });
      channelList.appendChild(div);
    }
  }

  async function getSignerKey(username: string): Promise<{ edPubB64: string; mismatch: boolean }> {
    const cached = state.peerKeys.get(username);
    if (cached) return cached;

    const { edPubB64 } = await api.getUserKey(username);
    const fp = await fingerprintFromRawB64(edPubB64);
    const pin = await checkAndPinPeer(username, edPubB64, fp);

    const info = { edPubB64, fingerprint: fp, mismatch: pin.status === 'mismatch' };
    state.peerKeys.set(username, info);

    if (pin.status === 'mismatch') {
      // Deliberately does not overwrite the pin automatically - see
      // store/vault.ts::checkAndPinPeer. Surface it and let messages from
      // this sender render as untrusted until a human resolves it.
      console.warn(
        `SECURITY WARNING: ${username}'s signing key changed since it was first seen. ` +
          `Pinned fingerprint: ${pin.pinned.fingerprint}, new fingerprint: ${fp}. ` +
          'Messages from them are shown as unverified.',
      );
    }
    return info;
  }

  /** Verifies + decrypts a message exactly once; later calls return the cached result. */
  async function resolveMessage(m: LoadedMessage): Promise<{ valid: boolean; text: string }> {
    if (m.resolved) return m.resolved;

    const canonical = `${m.roomId}|${m.sender}|${m.ts}|${m.iv}|${m.ct}`;
    const keyInfo = await getSignerKey(m.sender);
    const valid = !keyInfo.mismatch && (await verifyMessage(keyInfo.edPubB64, canonical, m.sig));

    let text: string;
    if (!valid) {
      text = keyInfo.mismatch
        ? "[hidden: sender's signing key changed and is not yet re-verified]"
        : '[rejected: invalid signature]';
    } else if (currentAesKey) {
      try {
        const plaintext = await aesDecrypt(currentAesKey, { iv: m.iv, ct: m.ct } as EncBlob);
        const parsed = JSON.parse(plaintext) as { text: string; ts: number };
        text = parsed.text;
      } catch {
        text = '[failed to decrypt - wrong room key?]';
      }
    } else {
      text = '';
    }

    m.resolved = { valid, text };
    return m.resolved;
  }

  function buildMessageRow(m: LoadedMessage, resolved: { valid: boolean; text: string }): HTMLElement {
    const row = document.createElement('div');
    row.className = 'message' + (resolved.valid ? '' : ' invalid-sig');
    row.dataset.id = m.id;

    const userEl = document.createElement('div');
    userEl.className = 'message-user';
    userEl.textContent = m.sender; // textContent, not innerHTML - see file header

    const textEl = document.createElement('div');
    textEl.className = 'message-text';
    textEl.textContent = resolved.text; // textContent, not innerHTML - see file header

    row.appendChild(userEl);
    row.appendChild(textEl);
    return row;
  }

  /** Resolves the signer key once per distinct sender in the batch, before resolving messages in parallel - avoids one PoW-gated REST call per message on a cold room. */
  async function warmSignerKeys(msgs: LoadedMessage[]): Promise<void> {
    const senders = new Set(msgs.map((m) => m.sender));
    await Promise.all([...senders].map((s) => getSignerKey(s)));
  }

  async function buildFragment(msgs: LoadedMessage[]): Promise<DocumentFragment> {
    await warmSignerKeys(msgs);
    const resolvedList = await Promise.all(msgs.map((m) => resolveMessage(m)));
    const frag = document.createDocumentFragment();
    msgs.forEach((m, i) => frag.appendChild(buildMessageRow(m, resolvedList[i]!)));
    return frag;
  }

  /** Trims rendered rows back down to TRIM_TO once MAX_RENDERED is exceeded, discarding from whichever edge is furthest from the edge that was just grown. */
  function trimWindow(grewAt: 'top' | 'bottom'): void {
    const rendered = windowEnd - windowStart;
    if (rendered <= MAX_RENDERED) return;
    const excess = rendered - TRIM_TO;

    if (grewAt === 'top') {
      // Just prepended at the top - the viewport is up there, so discard
      // from the bottom. Those rows are below the viewport; no scroll
      // compensation needed.
      for (let i = 0; i < excess; i++) messagesBox.lastChild?.remove();
      windowEnd -= excess;
    } else {
      // Just appended at the bottom - discard from the top. Those rows are
      // above the viewport, so removing them shrinks scrollHeight above the
      // current scroll position; compensate scrollTop to hold the view.
      const oldScrollHeight = messagesBox.scrollHeight;
      for (let i = 0; i < excess; i++) messagesBox.firstChild?.remove();
      windowStart += excess;
      messagesBox.scrollTop -= oldScrollHeight - messagesBox.scrollHeight;
    }
  }

  /** Prepends a batch at the top of the DOM, keeping the visible content anchored (no visual jump). */
  async function prependWithAnchor(msgs: LoadedMessage[]): Promise<void> {
    if (msgs.length === 0) return;
    const frag = await buildFragment(msgs);
    const oldScrollHeight = messagesBox.scrollHeight;
    const oldScrollTop = messagesBox.scrollTop;
    messagesBox.insertBefore(frag, messagesBox.firstChild);
    messagesBox.scrollTop = oldScrollTop + (messagesBox.scrollHeight - oldScrollHeight);
  }

  /** Grows the rendered window toward older history: from memory if already fetched, otherwise pages the server with `before`. */
  async function loadOlder(): Promise<void> {
    if (loadingOlder || !state.currentRoom) return;
    loadingOlder = true;
    try {
      let toPrepend: LoadedMessage[];

      if (windowStart > 0) {
        const newStart = Math.max(0, windowStart - FETCH_LIMIT);
        toPrepend = allMessages.slice(newStart, windowStart);
        windowStart = newStart;
      } else {
        if (historyExhausted) return;
        const oldest = allMessages[0];
        const before = oldest ? oldest.serverTs : undefined;
        const { messages } = await api.getHistory(state.currentRoom.roomId, before, FETCH_LIMIT);
        if (messages.length < FETCH_LIMIT) historyExhausted = true;

        const fresh = messages.map(toLoadedMessage).filter((m) => !knownIds.has(m.id));
        if (fresh.length === 0) return;
        for (const m of fresh) knownIds.add(m.id);

        allMessages = [...fresh, ...allMessages];
        windowEnd += fresh.length;
        windowStart = 0;
        toPrepend = fresh;
      }

      await prependWithAnchor(toPrepend);
      trimWindow('top');
    } finally {
      loadingOlder = false;
    }
  }

  /** Grows the rendered window toward newer history - always from memory, since anything newer than what's loaded arrives live via the socket and is appended directly (see handleIncomingMessage). */
  function loadNewer(): void {
    if (loadingNewer || windowEnd >= allMessages.length) return;
    loadingNewer = true;
    const newEnd = Math.min(allMessages.length, windowEnd + FETCH_LIMIT);
    const toAppend = allMessages.slice(windowEnd, newEnd);
    windowEnd = newEnd;

    void (async () => {
      try {
        const frag = await buildFragment(toAppend);
        messagesBox.appendChild(frag);
        trimWindow('bottom');
      } finally {
        loadingNewer = false;
      }
    })();
  }

  messagesBox.addEventListener('scroll', () => {
    if (messagesBox.scrollTop < SCROLL_TRIGGER_PX) void loadOlder();
    const distanceFromBottom = messagesBox.scrollHeight - messagesBox.scrollTop - messagesBox.clientHeight;
    if (distanceFromBottom < SCROLL_TRIGGER_PX) loadNewer();
  });

  async function openRoom(room: StoredRoom): Promise<void> {
    state.currentRoom = room;
    currentAesKey = await importAesKey(room.h1);
    chatHeaderTitle.textContent = `# ${room.name}`;
    messagesBox.innerHTML = '';
    userDisplay.textContent = state.username ?? '';
    closeDrawer(); // picking a room (from the drawer or the channel list) should reveal the chat
    // The identity panel lives in this screen's sidebar; state.identity is
    // only populated once login/registration completes (see
    // ui/auth.ts and main.ts), which happens after this controller was
    // wired up - refresh here rather than only once at wire time.
    void refreshIdentityPanel();

    allMessages = [];
    knownIds = new Set();
    windowStart = 0;
    windowEnd = 0;
    historyExhausted = false;
    loadingOlder = false;
    loadingNewer = false;

    await renderChannelList(room.roomId);
    state.socket?.subscribeRoom(room.roomId);

    try {
      const { messages } = await api.getHistory(room.roomId, undefined, FETCH_LIMIT);
      if (messages.length < FETCH_LIMIT) historyExhausted = true;

      for (const m of messages.map(toLoadedMessage)) {
        if (knownIds.has(m.id)) continue;
        knownIds.add(m.id);
        allMessages.push(m);
      }
      windowStart = 0;
      windowEnd = allMessages.length;

      const frag = await buildFragment(allMessages);
      messagesBox.appendChild(frag);
      messagesBox.scrollTop = messagesBox.scrollHeight;
    } catch (err) {
      console.error('Failed to load history', err);
    }
  }

  function handleIncomingMessage(m: InboundMsgNew): void {
    if (!state.currentRoom || m.roomId !== state.currentRoom.roomId) return;
    if (knownIds.has(m.id)) return; // guards resubscribe/reconnect redelivery
    knownIds.add(m.id);

    const wasAtNewestEnd = windowEnd === allMessages.length;
    const nearBottom =
      messagesBox.scrollHeight - messagesBox.scrollTop - messagesBox.clientHeight < SCROLL_TRIGGER_PX;

    const loaded = toLoadedMessage(m);
    allMessages.push(loaded);
    if (!wasAtNewestEnd) return; // user has scrolled away from "now" - keep the data, leave the DOM alone

    windowEnd = allMessages.length;
    void (async () => {
      const frag = await buildFragment([loaded]);
      messagesBox.appendChild(frag);
      trimWindow('bottom');
      if (nearBottom) messagesBox.scrollTop = messagesBox.scrollHeight;
    })();
  }

  function handleWsError(err: InboundError): void {
    console.error(`WS error [${err.code}]: ${err.message}`);
    // Most error codes (bad_request, forbidden, unauthorized, pow_failed,
    // server_error) reflect a client bug rather than something the user did
    // - console logging is enough. message_rejected is the one a real
    // person can actually hit (e.g. a stale/duplicate send), so surface it
    // directly instead of failing silently. There is deliberately no
    // separate rate limit - a solved proof-of-work is the only admission
    // control on sending (see README threat model).
    if (err.code === 'message_rejected') {
      alert(`Message not sent: ${err.message}`);
    }
  }

  messageInput.addEventListener('keypress', (ev) => {
    if (ev.key === 'Enter') void handleSend();
  });

  async function handleSend(): Promise<void> {
    const text = messageInput.value.trim();
    if (!text || !state.currentRoom || !currentAesKey || !state.identity || !state.username) return;

    const ts = Date.now();
    const { iv, ct } = await aesEncrypt(currentAesKey, JSON.stringify({ text, ts }));
    const canonical = `${state.currentRoom.roomId}|${state.username}|${ts}|${iv}|${ct}`;
    const sig = await signMessage(state.identity.privateKey, canonical);
    const clientRef = crypto.randomUUID();

    messageInput.value = '';
    try {
      await state.socket?.sendMessage({ roomId: state.currentRoom.roomId, iv, ct, ts, sig, clientRef });
    } catch (err) {
      console.error('Failed to send message', err);
    }
  }

  backBtn.addEventListener('click', () => {
    state.currentRoom = null;
    closeDrawer(); // reset for the next time this screen is shown
    showRoomsScreen();
    window.dispatchEvent(new CustomEvent('mango:refresh-rooms'));
  });

  logoutBtn.addEventListener('click', () => {
    window.dispatchEvent(new CustomEvent('mango:logout'));
  });

  return { openRoom, handleIncomingMessage, handleWsError };
}
