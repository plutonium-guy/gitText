/**
 * gitText — share text via URL, Supabase fallback, encrypted, signed, multi-file.
 * Heavy lifting in Rust/WASM; JS = wiring + DOM.
 */
'use strict';

const ENCODER = new TextEncoder();
const DECODER = new TextDecoder();
const DB_CONFIG = { name: 'gt', ver: 1, store: 'd' };
const URL_LIMIT = 32000;
const SUPABASE_THRESHOLD = 6000;     // payload size > this → push to Supabase
const TOKEN_SIZE = 9;
const LANGS = ['Plain','JavaScript','JSON','HTML','CSS','Python','Markdown','Rust'];
const EXT = ['txt','js','json','html','css','py','md','rs'];
const SUPABASE_URL = 'https://aszsbjmhnnecvokbezaa.supabase.co';
const SUPABASE_KEY = 'sb_publishable_QxCN7rqj58WYyZxywRE9Mw_I4fcGsdM';
const TOKEN_CLASSES = { 1:'kw', 2:'str', 3:'num', 4:'cmt', 5:'op', 6:'punc', 7:'fn', 8:'type', 10:'tag', 11:'attr', 12:'prop' };
const PREFS_KEY = 'gt:prefs';

let wasm, memory, memView, db, supabase, sessionKey, syncInterval;
let currentLang = 0, storageMode = 'url', password = null, docId = null;
let readOnly = false;
let saveTimeout, highlightTimeout, snapTimeout;
let files = null;        // multi-file mode: [{name, body}] or null
let activeFile = 0;
let searchState = { matches: [], idx: -1, query: '', flags: 0 };
let prefs = { theme: 'phosphor', wrap: false, indent: 2 };

const dom = {};
const getEl = id => document.getElementById(id);
[
  'editor','editor-wrapper','highlight-layer','line-numbers','loading',
  'copy-btn','clear-btn','encrypt-btn','qr-btn','docs-btn','download-btn','lang-btn','session-btn',
  'palette-btn','more-btn',
  'stats','status-dot','status-text','url-size','toast',
  'modal','modal-content','modal-close','modal-title',
  'password-form','password-input','password-confirm','password-submit',
  'qr-canvas','docs-list','storage-mode','tab-strip','preview-pane','search-bar'
].forEach(id => { const el = getEl(id); if (el) dom[id.replace(/-/g, '_')] = el; });

// ----- helpers ---------------------------------------------------------------
const genKey = () => {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const limit = 256 - (256 % chars.length);
  const result = [];
  while (result.length < 16) {
    const arr = new Uint8Array(32);
    crypto.getRandomValues(arr);
    for (const b of arr) if (b < limit && result.length < 16) result.push(chars[b % chars.length]);
  }
  return result.join('');
};
const secureCompare = (a, b) => {
  const len = Math.max(a.length, b.length);
  let r = a.length ^ b.length;
  for (let i = 0; i < len; i++) r |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return r === 0;
};
const escapeHtml = (() => { const d = document.createElement('div'); return s => { d.textContent = s; return d.innerHTML; }; })();
const loadPrefs = () => { try { Object.assign(prefs, JSON.parse(localStorage.getItem(PREFS_KEY) || '{}')); } catch {} };
const savePrefs = () => { try { localStorage.setItem(PREFS_KEY, JSON.stringify(prefs)); } catch {} };

// ----- wasm bridge -----------------------------------------------------------
const updateMemView = () => { memView = new Uint8Array(memory.buffer); };
const toW = bytes => {
  const ptr = wasm.alloc(bytes.length);
  if (!ptr && bytes.length) throw new Error('alloc');
  if (memView.buffer !== memory.buffer) updateMemView();
  memView.set(bytes, ptr);
  return { ptr, len: bytes.length };
};
const fromW = packed => {
  const p = Number(packed >> 32n), l = Number(packed & 0xFFFFFFFFn);
  if (!p || !l) return null;
  if (memView.buffer !== memory.buffer) updateMemView();
  return memView.subarray(p, p + l);
};
const resetHeap = () => wasm.reset_heap();
const args = obj => [obj.ptr, obj.len];

// brotli/deflate native compression
const HAS_BR = (() => { try { new CompressionStream('br'); return true; } catch { return false; } })();
const CS_ALGO = HAS_BR ? 'br' : 'deflate-raw';
const TAG_BR = 0x42, TAG_DF = 0x44;
const TAG_OUT = HAS_BR ? TAG_BR : TAG_DF;
const compressBytes = async bytes => {
  if (!bytes || !bytes.length) return null;
  const cs = new CompressionStream(CS_ALGO);
  const buf = await new Response(new Blob([bytes]).stream().pipeThrough(cs)).arrayBuffer();
  const u8 = new Uint8Array(buf);
  const out = new Uint8Array(u8.length + 1);
  out[0] = TAG_OUT;
  out.set(u8, 1);
  return out;
};
const decompressBytes = async bytes => {
  if (!bytes || bytes.length < 2) return null;
  const algo = bytes[0] === TAG_BR ? 'br' : bytes[0] === TAG_DF ? 'deflate-raw' : null;
  if (!algo) return null;
  try {
    const ds = new DecompressionStream(algo);
    const body = bytes.subarray(1);
    const buf = await new Response(new Blob([body]).stream().pipeThrough(ds)).arrayBuffer();
    return new Uint8Array(buf);
  } catch { return null; }
};

const W = {
  compress: compressBytes,
  decompress: decompressBytes,
  b64enc: data => { resetHeap(); const r = fromW(wasm.base64url_encode(...args(toW(data)))); return r ? DECODER.decode(r) : ''; },
  b64dec: str => { resetHeap(); return fromW(wasm.base64url_decode(...args(toW(ENCODER.encode(str)))))?.slice(); },
  // v2 envelope: argon2id + AES-CTR; payload self-tagged with 0x02 + salt + nonce
  encryptV2: (data, pw) => {
    resetHeap();
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const r = wasm.aes_v2_encrypt(
      ...args(toW(data)),
      ...args(toW(ENCODER.encode(pw))),
      toW(salt).ptr,
      toW(nonce).ptr
    );
    return fromW(r)?.slice();
  },
  decryptV2: (data, pw) => {
    resetHeap();
    const r = wasm.aes_v2_decrypt(...args(toW(data)), ...args(toW(ENCODER.encode(pw))));
    return fromW(r)?.slice();
  },
  // legacy v1 — try when v2 fails on stored payloads
  encryptV1: (data, pw) => {
    resetHeap();
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const r = wasm.aes_ctr_encrypt(
      ...args(toW(data)),
      ...args(toW(ENCODER.encode(pw))),
      toW(nonce).ptr
    );
    return fromW(r)?.slice();
  },
  decryptAuto: (data, pw) => {
    if (data && data[0] === 0x02) return W.decryptV2(data, pw);
    resetHeap();
    const r = wasm.aes_ctr_decrypt(...args(toW(data)), ...args(toW(ENCODER.encode(pw))));
    return fromW(r)?.slice();
  },
  hash: data => { resetHeap(); const r = fromW(wasm.hash_data(...args(toW(data)))); return r ? DECODER.decode(r) : null; },
  detectLang: text => { resetHeap(); return wasm.detect_language(...args(toW(ENCODER.encode(text.slice(0, 2000))))); },
  tokenize: (text, langId) => {
    if (!text || !langId) return [];
    resetHeap();
    const td = fromW(wasm.tokenize(...args(toW(ENCODER.encode(text))), langId));
    if (!td) return [];
    const dv = new DataView(td.buffer, td.byteOffset, td.byteLength);
    const out = [];
    for (let i = 0; i + TOKEN_SIZE <= td.length; i += TOKEN_SIZE) {
      out.push({ s: dv.getUint32(i, true), l: dv.getUint32(i + 4, true), t: td[i + 8] });
    }
    return out;
  },
  search: (text, pat, flags) => {
    if (!text || !pat) return [];
    resetHeap();
    const r = fromW(wasm.search_all(...args(toW(ENCODER.encode(text))), ...args(toW(ENCODER.encode(pat))), flags));
    if (!r) return [];
    const dv = new DataView(r.buffer, r.byteOffset, r.byteLength);
    const out = [];
    for (let i = 0; i + 8 <= r.length; i += 8) {
      out.push({ s: dv.getUint32(i, true), l: dv.getUint32(i + 4, true) });
    }
    return out;
  },
  mdRender: text => {
    if (!text) return '';
    resetHeap();
    const r = fromW(wasm.md_render(...args(toW(ENCODER.encode(text)))));
    return r ? DECODER.decode(r) : '';
  },
  diff: (a, b) => {
    resetHeap();
    const r = fromW(wasm.diff_lines(...args(toW(ENCODER.encode(a))), ...args(toW(ENCODER.encode(b)))));
    if (!r) return [];
    const dv = new DataView(r.buffer, r.byteOffset, r.byteLength);
    const n = dv.getUint32(0, true);
    const out = [];
    for (let i = 0; i < n; i++) {
      const off = 4 + i * 9;
      out.push({ op: r[off], ai: dv.getUint32(off + 1, true), bi: dv.getUint32(off + 5, true) });
    }
    return out;
  },
  formatJSON: (text, indent) => {
    resetHeap();
    const r = fromW(wasm.format_json(...args(toW(ENCODER.encode(text))), indent));
    return r ? DECODER.decode(r) : null;
  },
  formatMD: text => {
    resetHeap();
    const r = fromW(wasm.format_markdown(...args(toW(ENCODER.encode(text)))));
    return r ? DECODER.decode(r) : null;
  },
  ed25519KeyFromSeed: seed => {
    resetHeap();
    const r = fromW(wasm.ed25519_keypair_from_seed(toW(seed).ptr));
    if (!r) return null;
    return { sk: r.slice(0, 64), pk: r.slice(64) };
  },
  ed25519Sign: (msg, sk) => {
    resetHeap();
    const r = fromW(wasm.ed25519_sign(...args(toW(msg)), toW(sk).ptr));
    return r?.slice();
  },
  ed25519Verify: (msg, sig, pk) => {
    resetHeap();
    return wasm.ed25519_verify(...args(toW(msg)), toW(sig).ptr, toW(pk).ptr) === 1;
  },
  snapshotPush: (text, note) => {
    resetHeap();
    return wasm.snapshot_push(...args(toW(ENCODER.encode(text))), ...args(toW(ENCODER.encode(note))), BigInt(Date.now()));
  },
  snapshotList: () => {
    resetHeap();
    const r = fromW(wasm.snapshot_list());
    if (!r) return [];
    const dv = new DataView(r.buffer, r.byteOffset, r.byteLength);
    const n = dv.getUint32(0, true);
    const out = [];
    let off = 4;
    for (let i = 0; i < n; i++) {
      const tsLo = dv.getUint32(off, true), tsHi = dv.getUint32(off + 4, true);
      const ts = tsHi * 0x100000000 + tsLo;
      const nl = dv.getUint32(off + 8, true);
      const dl = dv.getUint32(off + 12, true);
      const note = DECODER.decode(r.subarray(off + 16, off + 16 + nl));
      out.push({ idx: i, ts, note, size: dl });
      off += 16 + nl;
    }
    return out;
  },
  snapshotRestore: idx => {
    resetHeap();
    const r = fromW(wasm.snapshot_restore(idx));
    return r ? DECODER.decode(r) : null;
  },
  snapshotClear: () => wasm.snapshot_clear(),
  packFiles: arr => {
    // Build [n:u32]([nl:u16][name][bl:u32][body])*
    let total = 4;
    for (const f of arr) total += 2 + ENCODER.encode(f.name).length + 4 + ENCODER.encode(f.body).length;
    const buf = new Uint8Array(total);
    const dv = new DataView(buf.buffer);
    let off = 0;
    dv.setUint32(off, arr.length, true); off += 4;
    for (const f of arr) {
      const nb = ENCODER.encode(f.name);
      const bb = ENCODER.encode(f.body);
      dv.setUint16(off, nb.length, true); off += 2;
      buf.set(nb, off); off += nb.length;
      dv.setUint32(off, bb.length, true); off += 4;
      buf.set(bb, off); off += bb.length;
    }
    return buf;
  },
  unpackFiles: bytes => {
    if (!bytes || bytes.length < 4) return null;
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const n = dv.getUint32(0, true);
    if (n > 256) return null;
    const out = [];
    let off = 4;
    try {
      for (let i = 0; i < n; i++) {
        const nl = dv.getUint16(off, true); off += 2;
        const name = DECODER.decode(bytes.subarray(off, off + nl)); off += nl;
        const bl = dv.getUint32(off, true); off += 4;
        const body = DECODER.decode(bytes.subarray(off, off + bl)); off += bl;
        out.push({ name, body });
      }
    } catch { return null; }
    return out;
  },
  renderPNG: (text, langId, scale) => {
    const toks = langId ? W.tokenize(text, langId) : [];
    // Re-encode tokens to wasm-side raw format
    const tokenBytes = new Uint8Array(toks.length * TOKEN_SIZE);
    const tdv = new DataView(tokenBytes.buffer);
    toks.forEach((t, i) => {
      tdv.setUint32(i * TOKEN_SIZE, t.s, true);
      tdv.setUint32(i * TOKEN_SIZE + 4, t.l, true);
      tokenBytes[i * TOKEN_SIZE + 8] = t.t;
    });
    resetHeap();
    const r = fromW(wasm.render_png(
      ...args(toW(ENCODER.encode(text))),
      ...args(toW(tokenBytes)),
      scale
    ));
    return r?.slice();
  },
  qrGen: url => {
    if (!window.qrcode) return null;
    try {
      const qr = window.qrcode(0, 'L');
      qr.addData(url);
      qr.make();
      const sz = qr.getModuleCount();
      const data = new Uint8Array(sz * sz);
      for (let y = 0; y < sz; y++) for (let x = 0; x < sz; x++) data[y * sz + x] = qr.isDark(y, x) ? 1 : 0;
      return { data, sz };
    } catch { return null; }
  }
};

// ----- IndexedDB -------------------------------------------------------------
const idb = {
  init: () => new Promise((res, rej) => {
    const req = indexedDB.open(DB_CONFIG.name, DB_CONFIG.ver);
    req.onerror = () => rej(req.error);
    req.onsuccess = () => res(req.result);
    req.onupgradeneeded = e => {
      const d = e.target.result;
      if (!d.objectStoreNames.contains(DB_CONFIG.store)) {
        const s = d.createObjectStore(DB_CONFIG.store, { keyPath: 'id' });
        s.createIndex('c', 'created', { unique: false });
      }
    };
  }),
  save: (text, pw) => new Promise(async (res, rej) => {
    if (!db) return res(null);
    try {
      let data = ENCODER.encode(text);
      if (pw) data = W.encryptV2(data, pw);
      const compressed = await W.compress(data);
      if (!compressed) return res(null);
      const id = W.hash(compressed);
      if (!id) return res(null);
      const doc = { id, title: text.split('\n')[0].slice(0, 50) || 'Untitled', data: compressed, enc: !!pw, size: text.length, created: Date.now() };
      const tx = db.transaction(DB_CONFIG.store, 'readwrite');
      const r = tx.objectStore(DB_CONFIG.store).put(doc);
      r.onsuccess = () => res(id);
      r.onerror = () => rej(r.error);
    } catch (e) { rej(e); }
  }),
  load: (id, pw) => new Promise((res, rej) => {
    if (!db) return res(null);
    const tx = db.transaction(DB_CONFIG.store, 'readonly');
    const r = tx.objectStore(DB_CONFIG.store).get(id);
    r.onsuccess = async () => {
      try {
        const doc = r.result;
        if (!doc) return res(null);
        let data = await W.decompress(doc.data);
        if (!data) return res(null);
        if (doc.enc) {
          if (!pw) return res({ needPw: true, doc });
          data = W.decryptAuto(data, pw);
          if (!data) return res({ badPw: true });
        }
        res({ text: DECODER.decode(data), doc });
      } catch (e) { rej(e); }
    };
    r.onerror = () => rej(r.error);
  }),
  all: () => new Promise((res, rej) => {
    if (!db) return res([]);
    const tx = db.transaction(DB_CONFIG.store, 'readonly');
    const r = tx.objectStore(DB_CONFIG.store).index('c').openCursor(null, 'prev');
    const docs = [];
    r.onsuccess = e => {
      const c = e.target.result;
      if (c) { docs.push({ id: c.value.id, title: c.value.title, size: c.value.size, enc: c.value.enc, created: c.value.created }); c.continue(); } else res(docs);
    };
    r.onerror = () => rej(r.error);
  }),
  del: id => new Promise((res, rej) => {
    if (!db) return res(false);
    const tx = db.transaction(DB_CONFIG.store, 'readwrite');
    const r = tx.objectStore(DB_CONFIG.store).delete(id);
    r.onsuccess = () => res(true);
    r.onerror = () => rej(r.error);
  })
};

// ----- url codec -------------------------------------------------------------
// URL fragment forms:
//   #<encoded>           plain
//   #e<encoded>          encrypted v1 (legacy)
//   #v<encoded>          encrypted v2 (argon2id)
//   #r:<encoded>         read-only plain
//   #m:<encoded>         multi-file pack
//   #d:<id>              local IDB doc
//   #k:<key>             supabase short key
const urlEnc = async (text, pw) => {
  let data = ENCODER.encode(text);
  let prefix = '';
  if (pw) {
    data = W.encryptV2(data, pw);
    prefix = 'v';
  }
  const c = await W.compress(data);
  if (!c) return '';
  return prefix + W.b64enc(c);
};
const urlDec = async (str, pw) => {
  let isEnc = false, ver = 1, ro = false;
  if (str.startsWith('r:')) { ro = true; str = str.slice(2); }
  if (str[0] === 'v') { isEnc = true; ver = 2; str = str.slice(1); }
  else if (str[0] === 'e') { isEnc = true; ver = 1; str = str.slice(1); }
  const raw = W.b64dec(str);
  if (!raw) return null;
  let data = await W.decompress(raw);
  if (!data) return null;
  if (isEnc) {
    if (!pw) return { needPw: true, ver };
    data = ver === 2 ? W.decryptV2(data, pw) : W.decryptAuto(data, pw);
    if (!data) return { badPw: true };
  }
  return { text: DECODER.decode(data), readOnly: ro };
};

// ----- supabase session ------------------------------------------------------
const session = {
  create: async (pw, expiresHours = 12) => {
    if (!supabase) return ui.toast('Supabase not ready');
    const key = genKey();
    const text = getText();
    if (!text) return ui.toast('Nothing to share');
    try {
      let data = ENCODER.encode(text);
      if (pw) data = W.encryptV2(data, pw);
      const compressed = await W.compress(data);
      if (!compressed) return ui.toast('compress failed');
      const expires_at = new Date(Date.now() + expiresHours * 3600 * 1000).toISOString();
      const { error } = await supabase.from('sessions').upsert({
        k: key, d: W.b64enc(compressed), e: !!pw, u: new Date().toISOString(), expires_at
      });
      if (error) throw error;
      sessionKey = key;
      if (pw) password = pw;
      const url = new URL(location.href);
      url.searchParams.set('s', key);
      history.replaceState(null, '', url);
      session.startSync();
      ui.updateSession(true);
      ui.toast(`Session: ${key} (${expiresHours}h)`);
    } catch (e) { console.error(e); ui.toast('Session create failed'); }
  },
  upload: async (text, pw) => {
    if (!supabase) return null;
    const key = genKey();
    let data = ENCODER.encode(text);
    if (pw) data = W.encryptV2(data, pw);
    const compressed = await W.compress(data);
    if (!compressed) return null;
    try {
      const { error } = await supabase.from('sessions').upsert({
        k: key, d: W.b64enc(compressed), e: !!pw, u: new Date().toISOString()
      });
      if (error) throw error;
      return key;
    } catch (e) { console.error(e); return null; }
  },
  join: async (key, pw) => {
    if (!supabase) return ui.toast('Supabase not ready');
    try {
      const { data, error } = await supabase.from('sessions').select('d,e').eq('k', key).single();
      if (error || !data) return ui.toast('Session not found');
      const raw = W.b64dec(data.d);
      if (!raw) return ui.toast('Decode failed');
      let decrypted = await W.decompress(raw);
      if (!decrypted) return ui.toast('Decompress failed');
      if (data.e) {
        if (!pw) return ui.showSessionPw(key);
        decrypted = W.decryptAuto(decrypted, pw);
        if (!decrypted) return ui.toast('Wrong password');
      }
      setText(DECODER.decode(decrypted));
      sessionKey = key;
      if (pw) password = pw;
      const url = new URL(location.href);
      url.searchParams.set('s', key);
      history.replaceState(null, '', url);
      ui.updateAll();
      session.startSync();
      ui.updateSession(true);
      ui.toast(`Joined: ${key}`);
    } catch (e) { console.error(e); ui.toast('Join failed'); }
  },
  syncUp: async () => {
    if (!sessionKey || !supabase) return;
    const text = getText();
    if (!text) return;
    try {
      let data = ENCODER.encode(text);
      if (password) data = W.encryptV2(data, password);
      const c = await W.compress(data);
      if (!c) return;
      await supabase.from('sessions').upsert({ k: sessionKey, d: W.b64enc(c), e: !!password, u: new Date().toISOString() });
      ui.setStatus('saved');
    } catch (e) { console.error(e); }
  },
  syncDown: async () => {
    if (!sessionKey || !supabase) return;
    try {
      const { data } = await supabase.from('sessions').select('d,e').eq('k', sessionKey).single();
      if (!data) return;
      const raw = W.b64dec(data.d);
      if (!raw) return;
      let decrypted = await W.decompress(raw);
      if (!decrypted) return;
      if (data.e) {
        if (!password) return;
        decrypted = W.decryptAuto(decrypted, password);
        if (!decrypted) return;
      }
      const text = DECODER.decode(decrypted);
      if (text !== getText()) { setText(text); ui.updateAll(); ui.toast('Session updated'); }
    } catch (e) { console.error(e); }
  },
  startSync: () => {
    if (syncInterval) clearTimeout(syncInterval);
    let backoff = 5000;
    const tick = async () => {
      try { await session.syncDown(); backoff = 5000; }
      catch { backoff = Math.min(backoff * 2, 60000); }
      if (syncInterval) syncInterval = setTimeout(tick, backoff);
    };
    syncInterval = setTimeout(tick, backoff);
  },
  stop: () => {
    if (syncInterval) clearTimeout(syncInterval);
    syncInterval = null;
    sessionKey = null;
    password = null;
    ui.updateSession(false);
    const url = new URL(location.href);
    url.searchParams.delete('s');
    history.replaceState(null, '', url);
  }
};

// ----- multi-file abstraction ------------------------------------------------
const getText = () => files ? files[activeFile].body : dom.editor.value;
const setText = t => {
  if (files) { files[activeFile].body = t; dom.editor.value = t; ui.renderTabs(); }
  else dom.editor.value = t;
};
const switchFile = i => {
  if (!files || i < 0 || i >= files.length) return;
  files[activeFile].body = dom.editor.value;
  activeFile = i;
  dom.editor.value = files[activeFile].body;
  ui.renderTabs();
  ui.updateAll();
};
const addFile = (name = 'untitled.txt') => {
  files = files || [{ name: 'main.txt', body: dom.editor.value }];
  files.push({ name, body: '' });
  activeFile = files.length - 1;
  dom.editor.value = '';
  ui.renderTabs();
  ui.updateAll();
};
const closeFile = i => {
  if (!files || files.length <= 1) { files = null; activeFile = 0; ui.renderTabs(); return; }
  files.splice(i, 1);
  if (activeFile >= files.length) activeFile = files.length - 1;
  dom.editor.value = files[activeFile].body;
  ui.renderTabs();
  ui.updateAll();
};

// ----- ui --------------------------------------------------------------------
const ui = {
  toast: msg => {
    dom.toast.textContent = msg;
    dom.toast.classList.add('show');
    setTimeout(() => dom.toast.classList.remove('show'), 2200);
  },
  setStatus: s => {
    dom.status_dot.classList.toggle('saving', s === 'saving');
    dom.status_text.textContent = s === 'saving' ? 'SAVING' : s === 'saved' ? (password ? 'ENCRYPTED' : 'SAVED') : 'READY';
  },
  closeModal: () => {
    dom.modal.classList.remove('show');
    dom.qr_canvas.style.display = 'none';
    dom.password_form.style.display = 'block';
    dom.docs_list.style.display = 'none';
    dom.docs_list.innerHTML = '';
  },
  updateStats: () => {
    const text = getText();
    const chars = text.length;
    const bytes = ENCODER.encode(text).length;
    const lines = text.split('\n').length;
    dom.stats.textContent = `${lines}L | ${chars}C | ${ui.fmtBytes(bytes)}`;
  },
  fmtBytes: b => b < 1024 ? `${b}B` : b < 1048576 ? `${(b/1024).toFixed(1)}K` : `${(b/1048576).toFixed(2)}M`,
  updateLines: () => {
    const n = dom.editor.value.split('\n').length;
    dom.line_numbers.textContent = Array.from({length: n}, (_,i) => i + 1).join('\n');
  },
  syncScroll: () => {
    const st = dom.editor.scrollTop;
    dom.line_numbers.scrollTop = st;
    dom.highlight_layer.scrollTop = st;
    dom.highlight_layer.scrollLeft = dom.editor.scrollLeft;
  },
  updateTitle: () => {
    const first = getText().split('\n')[0].trim().slice(0, 60);
    document.title = first ? `${first} — git/text` : 'git/text';
  },
  updateAll: () => {
    ui.updateStats();
    ui.updateLines();
    ui.highlight();
    ui.updateTitle();
    if (prefs.preview && currentLang === 6) ui.renderPreview();
  },
  applyTheme: () => {
    document.documentElement.dataset.theme = prefs.theme;
    document.documentElement.dataset.wrap = prefs.wrap ? '1' : '0';
  },
  updateSession: on => {
    if (dom.session_btn) { dom.session_btn.textContent = on ? 'LEAVE' : 'SESSION'; dom.session_btn.classList.toggle('active', on); }
    dom.storage_mode.textContent = on ? '[CLOUD]' : (storageMode === 'local' ? '[LOCAL]' : storageMode === 'sb' ? '[SBKEY]' : '[URL]');
  },
  getExt: () => EXT[currentLang] || 'txt',
  highlight: () => {
    if (!dom.highlight_layer) return;
    const text = dom.editor.value;
    if (!text) return dom.highlight_layer.innerHTML = '<br>';
    if (!currentLang) {
      currentLang = W.detectLang(text);
      dom.lang_btn.textContent = LANGS[currentLang];
    }
    if (!currentLang) return dom.highlight_layer.textContent = text;
    const toks = W.tokenize(text, currentLang);
    const matches = searchState.matches;
    let html = '', last = 0;
    const pushSeg = (a, b, base = '') => {
      if (a >= b) return;
      const seg = text.slice(a, b);
      // overlay matches
      const segMatches = matches.filter(m => m.s < b && m.s + m.l > a);
      if (!segMatches.length) { html += base ? `<span class="${base}">${escapeHtml(seg)}</span>` : escapeHtml(seg); return; }
      let p = a;
      for (const m of segMatches) {
        const ms = Math.max(m.s, a), me = Math.min(m.s + m.l, b);
        if (p < ms) { const pre = text.slice(p, ms); html += base ? `<span class="${base}">${escapeHtml(pre)}</span>` : escapeHtml(pre); }
        const hit = text.slice(ms, me);
        html += `<span class="tok-match">${escapeHtml(hit)}</span>`;
        p = me;
      }
      if (p < b) { const tail = text.slice(p, b); html += base ? `<span class="${base}">${escapeHtml(tail)}</span>` : escapeHtml(tail); }
    };
    if (!toks.length) { pushSeg(0, text.length); dom.highlight_layer.innerHTML = html || '<br>'; return; }
    for (const tk of toks) {
      if (tk.s > last) pushSeg(last, tk.s);
      const cls = TOKEN_CLASSES[tk.t];
      pushSeg(tk.s, tk.s + tk.l, cls ? `tok-${cls}` : '');
      last = tk.s + tk.l;
    }
    if (last < text.length) pushSeg(last, text.length);
    dom.highlight_layer.innerHTML = html || '<br>';
  },
  scheduleHighlight: () => {
    if (highlightTimeout) cancelAnimationFrame(highlightTimeout);
    highlightTimeout = requestAnimationFrame(ui.highlight);
  },
  renderTabs: () => {
    if (!dom.tab_strip) return;
    if (!files) { dom.tab_strip.style.display = 'none'; dom.tab_strip.innerHTML = ''; return; }
    dom.tab_strip.style.display = 'flex';
    dom.tab_strip.innerHTML = files.map((f, i) =>
      `<div class="tab${i === activeFile ? ' active' : ''}" data-i="${i}"><span class="tab-name">${escapeHtml(f.name)}</span><span class="tab-close" data-i="${i}">×</span></div>`
    ).join('') + `<button class="tab-add" id="tab-add">+ FILE</button>`;
    dom.tab_strip.querySelectorAll('.tab').forEach(el => el.onclick = e => {
      if (e.target.classList.contains('tab-close')) return;
      switchFile(parseInt(el.dataset.i));
    });
    dom.tab_strip.querySelectorAll('.tab-close').forEach(el => el.onclick = e => {
      e.stopPropagation();
      closeFile(parseInt(el.dataset.i));
    });
    const addBtn = getEl('tab-add');
    if (addBtn) addBtn.onclick = () => {
      const name = prompt('New file name', `file${files.length}.txt`);
      if (name) addFile(name);
    };
  },
  renderPreview: () => {
    if (!dom.preview_pane) return;
    const text = getText();
    const html = W.mdRender(text);
    dom.preview_pane.innerHTML = html;
  },
  togglePreview: () => {
    prefs.preview = !prefs.preview;
    savePrefs();
    document.body.classList.toggle('preview-on', prefs.preview);
    if (prefs.preview) ui.renderPreview();
  },
  showPassword: (mode, id = null) => {
    const isDec = mode.includes('decrypt');
    dom.modal_title.textContent = isDec ? 'decrypt' : 'encrypt';
    dom.password_form.style.display = 'flex';
    dom.docs_list.style.display = 'none';
    dom.qr_canvas.style.display = 'none';
    dom.modal.classList.add('show');
    dom.password_input.value = '';
    dom.password_confirm.style.display = isDec ? 'none' : 'block';
    dom.password_confirm.value = '';
    dom.password_submit.textContent = isDec ? 'Decrypt' : 'Encrypt';
    dom.password_submit.onclick = async () => {
      const pw = dom.password_input.value;
      if (!pw) return;
      if (isDec) {
        if (mode === 'decrypt-local' && id) {
          const r = await idb.load(id, pw);
          if (r?.badPw) return ui.toast('Wrong password');
          if (r?.text) { password = pw; setText(r.text); dom.encrypt_btn.textContent = 'ENCRYPTED'; dom.encrypt_btn.classList.add('active'); ui.updateAll(); ui.closeModal(); }
        } else {
          const t = await urlDec(location.hash.slice(1), pw);
          if (t?.badPw) return ui.toast('Wrong password');
          if (t && t.text) { password = pw; setText(t.text); dom.encrypt_btn.textContent = 'ENCRYPTED'; dom.encrypt_btn.classList.add('active'); ui.updateAll(); ui.closeModal(); }
        }
      } else {
        if (!secureCompare(pw, dom.password_confirm.value)) return ui.toast('Passwords do not match');
        password = pw;
        dom.encrypt_btn.textContent = 'ENCRYPTED';
        dom.encrypt_btn.classList.add('active');
        if (mode === 'sess-enc-create') session.create(pw);
        else doc.save();
        ui.closeModal();
        ui.toast('Encrypted (argon2id)');
      }
    };
  },
  showSessionPw: key => {
    dom.modal_title.textContent = 'session password';
    dom.password_form.style.display = 'flex';
    dom.docs_list.style.display = 'none';
    dom.qr_canvas.style.display = 'none';
    dom.modal.classList.add('show');
    dom.password_input.value = '';
    dom.password_confirm.style.display = 'none';
    dom.password_submit.textContent = 'Join';
    dom.password_submit.onclick = () => { session.join(key, dom.password_input.value); ui.closeModal(); };
  },
  showSessionDlg: () => {
    if (sessionKey) { session.stop(); ui.toast('Left session'); return; }
    dom.modal_title.textContent = 'session';
    dom.password_form.style.display = 'none';
    dom.docs_list.style.display = 'block';
    dom.docs_list.innerHTML = `
      <div class="download-options">
        <div style="margin-bottom:0.6rem">
          <label style="display:block;font-size:0.65rem;color:var(--text-dim);text-transform:uppercase;letter-spacing:0.15em;margin-bottom:0.3rem">expiry</label>
          <select id="sx" style="width:100%;padding:0.55rem;background:var(--ink);border:1px solid var(--rule);color:var(--text-bright);font-family:var(--mono);font-size:0.8rem">
            <option value="1">1 hour</option><option value="12" selected>12 hours</option>
            <option value="24">24 hours</option><option value="168">7 days</option>
          </select>
        </div>
        <button class="download-option" id="sc"><span class="download-icon">[NEW]</span><span>create</span></button>
        <button class="download-option" id="se"><span class="download-icon">[ENC]</span><span>encrypted</span></button>
        <div style="margin-top:1rem;padding-top:1rem;border-top:1px dashed var(--rule)">
          <input id="ski" placeholder="enter_key" style="width:100%;padding:0.6rem;background:var(--ink);border:1px solid var(--rule);color:var(--text-bright);margin-bottom:0.5rem;font-family:var(--mono);font-size:0.85rem">
          <button class="download-option" id="sj" style="width:100%"><span class="download-icon">[JOIN]</span><span>join</span></button>
        </div>
      </div>`;
    dom.modal.classList.add('show');
    const exp = () => parseInt(getEl('sx').value, 10) || 12;
    getEl('sc').onclick = () => { ui.closeModal(); session.create(null, exp()); };
    getEl('se').onclick = () => { const e = exp(); ui.closeModal(); ui.showPassword('sess-enc-create'); session._pendingExpiry = e; };
    getEl('sj').onclick = () => { const k = getEl('ski').value.trim(); if (k) { ui.closeModal(); session.join(k); } };
  },
  showDocs: async () => {
    dom.modal_title.textContent = 'documents';
    dom.password_form.style.display = 'none';
    dom.docs_list.style.display = 'block';
    dom.docs_list.innerHTML = '<div class="loading-docs">…</div>';
    dom.modal.classList.add('show');
    try {
      const docs = await idb.all();
      if (!docs.length) return dom.docs_list.innerHTML = '<div class="no-docs">no documents</div>';
      dom.docs_list.innerHTML = docs.map(d => `
        <div class="doc-item" data-id="${escapeHtml(d.id)}">
          <div class="doc-info">
            <span class="doc-title">${escapeHtml(d.title)}</span>
            <span class="doc-meta">${ui.fmtBytes(d.size)} · ${d.enc ? '[ENC]' : 'plain'}</span>
          </div>
          <div class="doc-actions">
            <button class="doc-load" data-id="${escapeHtml(d.id)}">open</button>
            <button class="doc-delete" data-id="${escapeHtml(d.id)}">del</button>
          </div>
        </div>`).join('');
      dom.docs_list.querySelectorAll('.doc-load').forEach(b => b.onclick = () => {
        ui.closeModal();
        history.pushState(null, '', location.pathname + '#d:' + b.dataset.id);
        doc.load();
      });
      dom.docs_list.querySelectorAll('.doc-delete').forEach(b => b.onclick = async () => {
        if (confirm('Delete?')) {
          await idb.del(b.dataset.id);
          b.closest('.doc-item').remove();
          if (docId === b.dataset.id) doc.clear();
          ui.toast('Deleted');
        }
      });
    } catch (e) { dom.docs_list.innerHTML = '<div class="error">error</div>'; }
  },
  showDL: () => {
    dom.modal_title.textContent = 'download';
    dom.password_form.style.display = 'none';
    dom.docs_list.style.display = 'block';
    dom.docs_list.innerHTML = `
      <div class="download-options">
        <button class="download-option" data-f="txt"><span class="download-icon">[TXT]</span><span>.${ui.getExt()}</span></button>
        <button class="download-option" data-f="gtz"><span class="download-icon">[GTZ]</span><span>.gtz</span></button>
        <button class="download-option" data-f="png"><span class="download-icon">[PNG]</span><span>.png screenshot</span></button>
      </div>`;
    dom.docs_list.querySelectorAll('.download-option').forEach(b => b.onclick = async () => {
      const text = getText();
      if (!text) return ui.toast('Empty');
      const a = document.createElement('a');
      const ts = new Date().toISOString().slice(0, 10).replace(/-/g, '');
      if (b.dataset.f === 'gtz') {
        const c = await W.compress(ENCODER.encode(text));
        if (!c) return ui.toast('Failed');
        a.href = URL.createObjectURL(new Blob([c]));
        a.download = `gt_${ts}.gtz`;
      } else if (b.dataset.f === 'png') {
        const png = W.renderPNG(text, currentLang, 2);
        if (!png) return ui.toast('PNG failed');
        a.href = URL.createObjectURL(new Blob([png], { type: 'image/png' }));
        a.download = `gt_${ts}.png`;
      } else {
        a.href = URL.createObjectURL(new Blob([text]));
        a.download = `gt_${ts}.${ui.getExt()}`;
      }
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 1000);
      ui.closeModal();
      ui.toast('Downloaded');
    });
    dom.modal.classList.add('show');
  },
  showQR: () => {
    const url = location.href;
    if (url.length > 2900) return ui.toast('URL too long — use SESSION');
    const q = W.qrGen(url);
    if (!q) return ui.toast('QR failed');
    dom.qr_canvas.style.display = 'block';
    dom.qr_canvas.width = dom.qr_canvas.height = (q.sz + 8) * 6;
    const ctx = dom.qr_canvas.getContext('2d');
    ctx.fillStyle = '#07090a';
    ctx.fillRect(0, 0, dom.qr_canvas.width, dom.qr_canvas.height);
    ctx.fillStyle = '#b6ff66';
    for (let y = 0; y < q.sz; y++) for (let x = 0; x < q.sz; x++) if (q.data[y * q.sz + x]) ctx.fillRect((x + 4) * 6, (y + 4) * 6, 6, 6);
    dom.modal_title.textContent = 'qr code';
    dom.password_form.style.display = 'none';
    dom.docs_list.style.display = 'none';
    dom.modal.classList.add('show');
  },
  showSnapshots: () => {
    const list = W.snapshotList();
    dom.modal_title.textContent = `snapshots (${list.length})`;
    dom.password_form.style.display = 'none';
    dom.docs_list.style.display = 'block';
    dom.modal.classList.add('show');
    if (!list.length) { dom.docs_list.innerHTML = '<div class="no-docs">no snapshots yet</div>'; return; }
    dom.docs_list.innerHTML = list.slice().reverse().map(s => `
      <div class="doc-item" data-i="${s.idx}">
        <div class="doc-info">
          <span class="doc-title">${escapeHtml(s.note || '(auto)')}</span>
          <span class="doc-meta">${new Date(s.ts).toLocaleString()} · ${ui.fmtBytes(s.size)}</span>
        </div>
        <div class="doc-actions">
          <button class="snap-restore" data-i="${s.idx}">restore</button>
        </div>
      </div>`).join('') + `<button class="download-option" id="snap-clear" style="margin-top:1rem"><span class="download-icon">[CLR]</span><span>clear all</span></button>`;
    dom.docs_list.querySelectorAll('.snap-restore').forEach(b => b.onclick = () => {
      const t = W.snapshotRestore(parseInt(b.dataset.i));
      if (t == null) return;
      if (!confirm('Replace current document?')) return;
      setText(t); ui.updateAll(); ui.closeModal(); ui.toast('Restored');
    });
    const cl = getEl('snap-clear');
    if (cl) cl.onclick = () => { W.snapshotClear(); ui.showSnapshots(); };
  },
  showDiff: () => {
    dom.modal_title.textContent = 'diff';
    dom.password_form.style.display = 'none';
    dom.docs_list.style.display = 'block';
    dom.modal.classList.add('show');
    dom.docs_list.innerHTML = `
      <div style="display:flex;flex-direction:column;gap:0.5rem">
        <textarea id="diff-a" placeholder="version A" style="height:100px;width:100%;padding:0.5rem;background:var(--ink);border:1px solid var(--rule);color:var(--text-bright);font-family:var(--mono);font-size:0.78rem;resize:vertical"></textarea>
        <textarea id="diff-b" placeholder="version B (defaults to current doc)" style="height:100px;width:100%;padding:0.5rem;background:var(--ink);border:1px solid var(--rule);color:var(--text-bright);font-family:var(--mono);font-size:0.78rem;resize:vertical"></textarea>
        <button class="download-option" id="diff-run"><span class="download-icon">[RUN]</span><span>compute diff</span></button>
        <pre id="diff-out" style="margin:0;padding:0.6rem;background:var(--ink);border:1px solid var(--rule);font-family:var(--mono);font-size:0.78rem;max-height:280px;overflow:auto"></pre>
      </div>`;
    getEl('diff-b').value = getText();
    getEl('diff-run').onclick = () => {
      const a = getEl('diff-a').value;
      const b = getEl('diff-b').value;
      const ops = W.diff(a, b);
      const aLines = a.split('\n');
      const bLines = b.split('\n');
      let html = '';
      for (const o of ops) {
        if (o.op === 0) html += `<span style="color:var(--text-dim)">  ${escapeHtml(aLines[o.ai] || '')}</span>\n`;
        else if (o.op === 1) html += `<span style="color:var(--blood)">- ${escapeHtml(aLines[o.ai] || '')}</span>\n`;
        else html += `<span style="color:var(--phosphor)">+ ${escapeHtml(bLines[o.bi] || '')}</span>\n`;
      }
      getEl('diff-out').innerHTML = html;
    };
  },
  showSign: () => {
    dom.modal_title.textContent = 'sign / verify (ed25519)';
    dom.password_form.style.display = 'none';
    dom.docs_list.style.display = 'block';
    dom.modal.classList.add('show');
    let kp = JSON.parse(localStorage.getItem('gt:keypair') || 'null');
    const text = getText();
    dom.docs_list.innerHTML = `
      <div class="download-options">
        <button class="download-option" id="sg-key"><span class="download-icon">[KEY]</span><span>${kp ? 'regenerate keypair' : 'generate keypair'}</span></button>
        <button class="download-option" id="sg-sign" ${kp ? '' : 'disabled'}><span class="download-icon">[SIG]</span><span>sign current doc</span></button>
        <button class="download-option" id="sg-verify"><span class="download-icon">[VRF]</span><span>verify pasted signature</span></button>
      </div>
      <div style="margin-top:0.8rem;font-size:0.7rem;color:var(--text-dim);letter-spacing:0.05em">
        ${kp ? `public key (share): <code style="color:var(--ion)">${kp.pk}</code>` : '(no keypair yet)'}
      </div>
      <pre id="sg-out" style="margin-top:0.6rem;padding:0.6rem;background:var(--ink);border:1px solid var(--rule);font-family:var(--mono);font-size:0.7rem;max-height:240px;overflow:auto;white-space:pre-wrap;word-break:break-all"></pre>
    `;
    getEl('sg-key').onclick = () => {
      const seed = crypto.getRandomValues(new Uint8Array(32));
      const k = W.ed25519KeyFromSeed(seed);
      if (!k) return ui.toast('keygen failed');
      kp = { sk: W.b64enc(k.sk), pk: W.b64enc(k.pk) };
      localStorage.setItem('gt:keypair', JSON.stringify(kp));
      ui.toast('keypair stored');
      ui.showSign();
    };
    getEl('sg-sign').onclick = () => {
      if (!kp) return;
      const sk = W.b64dec(kp.sk);
      const sig = W.ed25519Sign(ENCODER.encode(text), sk);
      const sigB = W.b64enc(sig);
      const blob = JSON.stringify({ sig: sigB, pk: kp.pk, len: text.length, h: W.hash(ENCODER.encode(text)) }, null, 2);
      getEl('sg-out').textContent = blob;
      navigator.clipboard.writeText(blob).then(() => ui.toast('signature copied')).catch(() => {});
    };
    getEl('sg-verify').onclick = () => {
      const j = prompt('paste signature JSON');
      if (!j) return;
      try {
        const { sig, pk } = JSON.parse(j);
        const ok = W.ed25519Verify(ENCODER.encode(text), W.b64dec(sig), W.b64dec(pk));
        ui.toast(ok ? '✓ signature valid' : '✗ INVALID');
      } catch { ui.toast('bad json'); }
    };
  },
  showSearch: () => {
    if (!dom.search_bar) return;
    const open = !dom.search_bar.classList.contains('show');
    dom.search_bar.classList.toggle('show', open);
    if (open) getEl('sr-q')?.focus();
    else { searchState = { matches: [], idx: -1, query: '', flags: 0 }; ui.scheduleHighlight(); }
  },
  runSearch: () => {
    const q = getEl('sr-q')?.value || '';
    const flags = (getEl('sr-i')?.checked ? 1 : 0) | (getEl('sr-w')?.checked ? 2 : 0);
    searchState.query = q;
    searchState.flags = flags;
    searchState.matches = q ? W.search(dom.editor.value, q, flags) : [];
    searchState.idx = searchState.matches.length ? 0 : -1;
    const ct = getEl('sr-count');
    if (ct) ct.textContent = `${searchState.matches.length} matches`;
    ui.scheduleHighlight();
    ui.jumpToMatch();
  },
  jumpToMatch: () => {
    const m = searchState.matches[searchState.idx];
    if (!m) return;
    dom.editor.focus();
    dom.editor.setSelectionRange(m.s, m.s + m.l);
  },
  nextMatch: () => { if (!searchState.matches.length) return; searchState.idx = (searchState.idx + 1) % searchState.matches.length; ui.jumpToMatch(); },
  prevMatch: () => { if (!searchState.matches.length) return; searchState.idx = (searchState.idx - 1 + searchState.matches.length) % searchState.matches.length; ui.jumpToMatch(); },
  replaceMatch: (all) => {
    if (!searchState.matches.length) return;
    const repl = getEl('sr-r')?.value || '';
    const text = dom.editor.value;
    if (all) {
      let out = '', last = 0;
      for (const m of searchState.matches) { out += text.slice(last, m.s) + repl; last = m.s + m.l; }
      out += text.slice(last);
      dom.editor.value = out;
    } else {
      const m = searchState.matches[searchState.idx];
      dom.editor.value = text.slice(0, m.s) + repl + text.slice(m.s + m.l);
    }
    ui.updateAll();
    if (saveTimeout) clearTimeout(saveTimeout);
    doc.save();
    ui.runSearch();
  },
  showPalette: () => {
    dom.modal_title.textContent = 'command palette';
    dom.password_form.style.display = 'none';
    dom.docs_list.style.display = 'block';
    dom.modal.classList.add('show');
    const cmds = [
      { label: 'save', kbd: '⌘S', run: () => doc.save() },
      { label: 'copy share link', kbd: '⌘⇧C', run: () => actions.copy() },
      { label: 'toggle encryption', run: () => actions.toggleEnc() },
      { label: 'cycle language', kbd: '⌘L', run: () => actions.cycleLang() },
      { label: 'go to line…', kbd: '⌘G', run: () => actions.gotoLine() },
      { label: 'search & replace', kbd: '⌘F', run: () => ui.showSearch() },
      { label: 'toggle word wrap', run: () => { prefs.wrap = !prefs.wrap; savePrefs(); ui.applyTheme(); ui.toast('wrap ' + (prefs.wrap ? 'on' : 'off')); } },
      { label: 'toggle theme', run: () => { prefs.theme = prefs.theme === 'phosphor' ? 'paper' : 'phosphor'; savePrefs(); ui.applyTheme(); } },
      { label: 'toggle markdown preview', run: () => ui.togglePreview() },
      { label: 'format json', run: () => actions.formatJSON() },
      { label: 'reflow markdown', run: () => actions.formatMD() },
      { label: 'snapshots…', run: () => ui.showSnapshots() },
      { label: 'diff…', run: () => ui.showDiff() },
      { label: 'sign / verify…', run: () => ui.showSign() },
      { label: 'add new file (multi-file mode)', run: () => addFile() },
      { label: 'documents…', run: () => ui.showDocs() },
      { label: 'download…', run: () => ui.showDL() },
      { label: 'qr code', run: () => ui.showQR() },
      { label: 'session…', run: () => ui.showSessionDlg() },
      { label: 'make read-only share link', run: () => actions.shareReadOnly() },
      { label: 'clear document', run: () => doc.clear() }
    ];
    dom.docs_list.innerHTML = `
      <input id="pl-q" placeholder="type to filter…" style="width:100%;padding:0.65rem;background:var(--ink);border:1px solid var(--rule);color:var(--text-bright);font-family:var(--mono);font-size:0.85rem;margin-bottom:0.6rem">
      <div id="pl-list" style="max-height:340px;overflow:auto"></div>`;
    const render = (filter = '') => {
      const f = filter.toLowerCase();
      const list = cmds.filter(c => c.label.toLowerCase().includes(f));
      getEl('pl-list').innerHTML = list.map((c, i) => `
        <div class="doc-item pl-item" data-i="${cmds.indexOf(c)}" style="cursor:pointer">
          <div class="doc-info"><span class="doc-title">${escapeHtml(c.label)}</span></div>
          ${c.kbd ? `<div class="doc-meta" style="margin-left:auto">${escapeHtml(c.kbd)}</div>` : ''}
        </div>`).join('');
      dom.docs_list.querySelectorAll('.pl-item').forEach(el => el.onclick = () => {
        const c = cmds[parseInt(el.dataset.i)];
        ui.closeModal();
        c.run();
      });
    };
    render();
    getEl('pl-q').oninput = e => render(e.target.value);
    getEl('pl-q').focus();
    getEl('pl-q').onkeydown = e => {
      if (e.key === 'Enter') {
        const first = dom.docs_list.querySelector('.pl-item');
        if (first) first.click();
      }
    };
  }
};

// ----- doc save/load --------------------------------------------------------
const doc = {
  save: async () => {
    if (readOnly) return;
    const text = getText();
    if (!text) {
      history.replaceState(null, '', location.pathname);
      docId = null;
      storageMode = 'url';
      dom.storage_mode.textContent = '[URL]';
      dom.url_size.textContent = '0B';
      return;
    }
    ui.setStatus('saving');
    try {
      // Multi-file: pack into bytes, then url-encode
      let payloadText = text;
      let mfPrefix = '';
      if (files) {
        files[activeFile].body = dom.editor.value;
        const packed = W.packFiles(files);
        payloadText = ' ' + DECODER.decode(packed.subarray(0, 1)); // sentinel won't decode safely; instead path below
      }
      let encoded;
      if (files) {
        // pack-then-compress directly (binary path)
        const packed = W.packFiles(files);
        let data = packed;
        if (password) data = W.encryptV2(data, password);
        const c = await W.compress(data);
        encoded = (password ? 'v' : '') + 'm:' + W.b64enc(c);
      } else {
        encoded = await urlEnc(text, password);
      }
      if (encoded.length < SUPABASE_THRESHOLD) {
        storageMode = 'url';
        docId = null;
        history.replaceState(null, '', location.pathname + '#' + encoded);
        dom.url_size.textContent = ui.fmtBytes(encoded.length);
      } else if (encoded.length < URL_LIMIT) {
        storageMode = 'url';
        docId = null;
        history.replaceState(null, '', location.pathname + '#' + encoded);
        dom.url_size.textContent = ui.fmtBytes(encoded.length);
      } else {
        // Try Supabase first; fallback to IDB
        let key = null;
        try { key = await session.upload(text, password); } catch {}
        if (key) {
          storageMode = 'sb';
          docId = null;
          history.replaceState(null, '', location.pathname + '#k:' + key);
          dom.url_size.textContent = ui.fmtBytes(key.length + 2);
        } else {
          storageMode = 'local';
          const id = await idb.save(text, password);
          if (id) {
            docId = id;
            history.replaceState(null, '', location.pathname + '#d:' + id);
            dom.url_size.textContent = ui.fmtBytes(id.length + 2);
          }
        }
      }
      dom.storage_mode.textContent = storageMode === 'local' ? '[LOCAL]' : storageMode === 'sb' ? '[SBKEY]' : '[URL]';
      ui.setStatus('saved');
      if (sessionKey) session.syncUp();
      // schedule snapshot
      if (snapTimeout) clearTimeout(snapTimeout);
      snapTimeout = setTimeout(() => { try { W.snapshotPush(text, ''); } catch {} }, 4000);
    } catch (e) { console.error(e); ui.setStatus('error'); }
  },
  load: async () => {
    let hash = location.hash.slice(1);
    if (!hash) return;
    readOnly = false;
    if (hash.startsWith('d:')) {
      const id = hash.slice(2);
      docId = id;
      storageMode = 'local';
      const r = await idb.load(id);
      if (!r) return ui.toast('Not found');
      if (r.needPw) return ui.showPassword('decrypt-local', id);
      setText(r.text);
      password = r.doc.enc ? password : null;
      dom.storage_mode.textContent = '[LOCAL]';
      dom.url_size.textContent = ui.fmtBytes(id.length + 2);
      ui.updateAll();
      return;
    }
    if (hash.startsWith('k:')) {
      const key = hash.slice(2);
      storageMode = 'sb';
      try {
        const { data } = await supabase.from('sessions').select('d,e').eq('k', key).single();
        if (!data) return ui.toast('not found');
        const raw = W.b64dec(data.d);
        let plain = await W.decompress(raw);
        if (data.e) {
          if (!password) return ui.showPassword('decrypt');
          plain = W.decryptAuto(plain, password);
        }
        if (plain) { setText(DECODER.decode(plain)); ui.updateAll(); dom.storage_mode.textContent = '[SBKEY]'; }
      } catch (e) { ui.toast('sb load failed'); }
      return;
    }
    if (hash.startsWith('m:') || hash.startsWith('vm:')) {
      // multi-file pack
      let enc = false;
      if (hash.startsWith('vm:')) { enc = true; hash = hash.slice(3); }
      else hash = hash.slice(2);
      const raw = W.b64dec(hash);
      let data = await W.decompress(raw);
      if (enc) {
        if (!password) return ui.showPassword('decrypt');
        data = W.decryptAuto(data, password);
      }
      const arr = W.unpackFiles(data);
      if (!arr) return ui.toast('bad pack');
      files = arr;
      activeFile = 0;
      dom.editor.value = files[0].body;
      ui.renderTabs();
      ui.updateAll();
      return;
    }
    storageMode = 'url';
    if (hash[0] === 'v' || hash[0] === 'e') {
      const t = await urlDec(hash);
      if (t?.needPw) return ui.showPassword('decrypt');
      if (t && t.text) { setText(t.text); dom.url_size.textContent = ui.fmtBytes(hash.length); ui.updateAll(); }
      return;
    }
    try {
      const t = await urlDec(hash);
      if (t && t.text) {
        setText(t.text);
        readOnly = !!t.readOnly;
        dom.editor.readOnly = readOnly;
        if (readOnly) dom.storage_mode.textContent = '[RO]';
        dom.url_size.textContent = ui.fmtBytes(hash.length);
        ui.updateAll();
      }
    } catch (e) { console.error(e); }
  },
  clear: () => {
    setText('');
    files = null;
    activeFile = 0;
    password = null;
    docId = null;
    readOnly = false;
    storageMode = 'url';
    currentLang = 0;
    dom.editor.readOnly = false;
    history.replaceState(null, '', location.pathname);
    ui.renderTabs();
    ui.updateAll();
    dom.encrypt_btn.textContent = 'ENCRYPT';
    dom.encrypt_btn.classList.remove('active');
    dom.highlight_layer.innerHTML = '<br>';
    ui.setStatus('ready');
    dom.editor.focus();
  }
};

// ----- actions ---------------------------------------------------------------
const actions = {
  copy: async () => {
    try { await navigator.clipboard.writeText(location.href); ui.toast('Copied'); }
    catch { ui.toast('Copy failed'); }
  },
  toggleEnc: () => {
    if (password) {
      password = null;
      dom.encrypt_btn.textContent = 'ENCRYPT';
      dom.encrypt_btn.classList.remove('active');
      doc.save();
      ui.toast('decrypted');
    } else ui.showPassword('encrypt');
  },
  cycleLang: () => {
    currentLang = (currentLang + 1) % LANGS.length;
    dom.lang_btn.textContent = LANGS[currentLang];
    ui.scheduleHighlight();
  },
  formatJSON: () => {
    const t = W.formatJSON(getText(), prefs.indent);
    if (!t) return ui.toast('format failed');
    setText(t);
    dom.editor.value = t;
    ui.updateAll();
    doc.save();
    ui.toast('json formatted');
  },
  formatMD: () => {
    const t = W.formatMD(getText());
    if (!t) return ui.toast('format failed');
    setText(t);
    dom.editor.value = t;
    ui.updateAll();
    doc.save();
    ui.toast('md reflowed');
  },
  gotoLine: () => {
    const n = parseInt(prompt('Line number'), 10);
    if (!n) return;
    const lines = dom.editor.value.split('\n');
    let off = 0;
    for (let i = 0; i < n - 1 && i < lines.length; i++) off += lines[i].length + 1;
    dom.editor.focus();
    dom.editor.setSelectionRange(off, off);
    // scroll into view
    dom.editor.scrollTop = (n - 1) * 22;
  },
  shareReadOnly: async () => {
    const text = getText();
    if (!text) return ui.toast('empty');
    const enc = await urlEnc(text);
    const url = location.origin + location.pathname + '#r:' + enc;
    try { await navigator.clipboard.writeText(url); ui.toast('read-only link copied'); }
    catch { prompt('read-only link:', url); }
  }
};

// ----- init ------------------------------------------------------------------
const init = async () => {
  loadPrefs();
  try {
    supabase = window.supabase.createClient(SUPABASE_URL, SUPABASE_KEY);
    await Promise.all([
      fetch('editor.wasm').then(r => r.arrayBuffer()).then(b => WebAssembly.instantiate(b, { env: {} })).then(m => {
        wasm = m.instance.exports;
        memory = wasm.memory;
        updateMemView();
      }),
      idb.init().then(d => db = d).catch(e => console.warn('idb:', e))
    ]);

    ui.applyTheme();
    dom.loading.style.display = 'none';
    dom.editor_wrapper.style.display = 'flex';
    ['copy_btn','clear_btn','encrypt_btn','qr_btn','docs_btn','download_btn','lang_btn','session_btn','palette_btn','more_btn']
      .forEach(b => dom[b] && (dom[b].disabled = false));

    await doc.load();

    dom.editor.addEventListener('input', () => {
      if (files) files[activeFile].body = dom.editor.value;
      ui.updateAll();
      if (saveTimeout) clearTimeout(saveTimeout);
      saveTimeout = setTimeout(() => doc.save(), 300);
      if (searchState.query) ui.runSearch();
    });
    dom.editor.addEventListener('scroll', ui.syncScroll);
    dom.copy_btn.onclick = actions.copy;
    dom.clear_btn.onclick = doc.clear;
    dom.encrypt_btn.onclick = actions.toggleEnc;
    dom.qr_btn.onclick = ui.showQR;
    dom.docs_btn.onclick = ui.showDocs;
    dom.download_btn.onclick = ui.showDL;
    dom.lang_btn.onclick = actions.cycleLang;
    if (dom.session_btn) dom.session_btn.onclick = ui.showSessionDlg;
    if (dom.palette_btn) dom.palette_btn.onclick = ui.showPalette;
    if (dom.more_btn) dom.more_btn.onclick = ui.showPalette;
    dom.modal_close.onclick = ui.closeModal;
    dom.modal.onclick = e => { if (e.target === dom.modal) ui.closeModal(); };
    dom.password_input.onkeydown = dom.password_confirm.onkeydown = e => { if (e.key === 'Enter') dom.password_submit.click(); };
    window.onpopstate = () => { doc.load(); ui.updateStats(); };

    document.onkeydown = e => {
      const mod = e.ctrlKey || e.metaKey;
      if (mod && e.key === 's') { e.preventDefault(); if (saveTimeout) clearTimeout(saveTimeout); doc.save(); }
      else if (mod && e.shiftKey && (e.key === 'C' || e.key === 'c')) { e.preventDefault(); actions.copy(); }
      else if (mod && (e.key === 'k' || e.key === 'K')) { e.preventDefault(); ui.showPalette(); }
      else if (mod && (e.key === 'f' || e.key === 'F')) { e.preventDefault(); ui.showSearch(); }
      else if (mod && (e.key === 'g' || e.key === 'G')) { e.preventDefault(); actions.gotoLine(); }
      else if (mod && (e.key === 'l' || e.key === 'L')) { e.preventDefault(); actions.cycleLang(); }
      else if (mod && e.shiftKey && (e.key === 'I' || e.key === 'i')) { e.preventDefault(); currentLang === 2 ? actions.formatJSON() : actions.formatMD(); }
      else if (e.key === 'Escape') {
        if (dom.modal.classList.contains('show')) ui.closeModal();
        else if (dom.search_bar && dom.search_bar.classList.contains('show')) ui.showSearch();
      }
      else if (mod && e.key === 'Enter' && dom.search_bar?.classList.contains('show')) { e.preventDefault(); ui.replaceMatch(e.shiftKey); }
    };

    dom.editor.ondragover = e => { e.preventDefault(); dom.editor.classList.add('dragover'); };
    dom.editor.ondragleave = () => dom.editor.classList.remove('dragover');
    dom.editor.ondrop = async e => {
      e.preventDefault();
      dom.editor.classList.remove('dragover');
      const dropped = [...e.dataTransfer.files];
      if (!dropped.length) return;
      if (dropped.length === 1) {
        const f = dropped[0];
        const txt = await f.text();
        setText(txt);
        const ext = f.name.split('.').pop().toLowerCase();
        currentLang = { js: 1, jsx: 1, ts: 1, tsx: 1, mjs: 1, json: 2, html: 3, htm: 3, css: 4, scss: 4, py: 5, pyw: 5, md: 6, markdown: 6, rs: 7 }[ext] || 0;
        dom.lang_btn.textContent = LANGS[currentLang];
        ui.updateAll();
        doc.save();
        ui.toast(f.name);
      } else {
        // multi-file: pack
        files = [];
        for (const f of dropped) files.push({ name: f.name, body: await f.text() });
        activeFile = 0;
        dom.editor.value = files[0].body;
        ui.renderTabs();
        ui.updateAll();
        doc.save();
        ui.toast(`loaded ${files.length} files`);
      }
    };

    if (dom.search_bar) {
      dom.search_bar.innerHTML = `
        <input id="sr-q" placeholder="search" />
        <input id="sr-r" placeholder="replace" />
        <label><input type="checkbox" id="sr-i"/> ic</label>
        <label><input type="checkbox" id="sr-w"/> ww</label>
        <button id="sr-prev">‹</button>
        <button id="sr-next">›</button>
        <button id="sr-rep1">repl</button>
        <button id="sr-repa">repl all</button>
        <span id="sr-count"></span>
        <button id="sr-close">×</button>`;
      getEl('sr-q').oninput = () => ui.runSearch();
      getEl('sr-i').onchange = () => ui.runSearch();
      getEl('sr-w').onchange = () => ui.runSearch();
      getEl('sr-prev').onclick = () => ui.prevMatch();
      getEl('sr-next').onclick = () => ui.nextMatch();
      getEl('sr-rep1').onclick = () => ui.replaceMatch(false);
      getEl('sr-repa').onclick = () => ui.replaceMatch(true);
      getEl('sr-close').onclick = () => ui.showSearch();
      getEl('sr-q').onkeydown = e => {
        if (e.key === 'Enter') { e.preventDefault(); e.shiftKey ? ui.prevMatch() : ui.nextMatch(); }
      };
    }

    const url = new URL(location.href);
    const sKey = url.searchParams.get('s');
    if (sKey) await session.join(sKey);

  } catch (e) {
    console.error(e);
    dom.loading.textContent = 'ERROR LOADING';
  }
};

init();
