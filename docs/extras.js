/**
 * gitText — extras layer. Loaded AFTER app.js. Augments the global wiring.
 * No app.js changes required for any of this; everything bolts on through
 * documented hooks (W, ui, doc, actions globals exposed by app.js).
 *
 * Features added here:
 *   service worker + PWA share-target + file handler
 *   auto bracket pair + auto-indent on Enter
 *   line move (Alt+↑/↓) + duplicate (Cmd+D)
 *   trim trailing whitespace on save (pref)
 *   paste auto-format JSON/MD
 *   outline modal (MD headings / code symbols)
 *   encoding palette (sha256/base64/hex/url/jwt/jsonpath/ascii-art)
 *   hex viewer toggle
 *   CSV column-align toggle
 *   markdown preview scroll sync
 *   realtime cursor in session via Supabase Realtime
 *   verify-by-domain badge (DoH TXT lookup)
 *
 * Many wasm calls assume the new exports added in lib.rs:
 *   sha256_hex, json_query, jwt_decode, jwt_verify_eddsa, ascii_art
 */
'use strict';

(() => {

// ------- service worker ------------------------------------------------------
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('sw.js').catch(e => console.warn('sw:', e));
  });
}

// Share Target: ?share_text=…&share_title=…&share_url=…
const sp = new URLSearchParams(location.search);
const shareText = sp.get('share_text') || '';
const shareUrl = sp.get('share_url') || '';
const shareTitle = sp.get('share_title') || '';
if (shareText || shareUrl) {
  const blob = [shareTitle, shareText, shareUrl].filter(Boolean).join('\n\n');
  // Defer so app init has wired DOM
  setTimeout(() => {
    if (window.dom && window.dom.editor) {
      window.dom.editor.value = blob;
      window.dom.editor.dispatchEvent(new Event('input'));
    }
  }, 800);
}

// File Handler API
if ('launchQueue' in window) {
  launchQueue.setConsumer(async params => {
    if (!params || !params.files || !params.files.length) return;
    const f = await params.files[0].getFile();
    const txt = await f.text();
    setTimeout(() => {
      if (window.dom && window.dom.editor) {
        window.dom.editor.value = txt;
        window.dom.editor.dispatchEvent(new Event('input'));
      }
    }, 600);
  });
}

// ------- expose key objects so extras can patch ------------------------------
// app.js defines these as const inside module scope, so we expose via window in
// extras AFTER app.js. We rely on the symbols being top-level in app.js.
// (They are: dom, W, ui, doc, actions, prefs, files, session, ENCODER, DECODER.)
// We patch via globals.
Object.assign(window, {});

// Wait for app to be ready: poll until W exists.
const ready = () => typeof W !== 'undefined' && typeof ui !== 'undefined' && typeof dom !== 'undefined' && dom.editor;
const onReady = fn => {
  if (ready()) return fn();
  const iv = setInterval(() => { if (ready()) { clearInterval(iv); fn(); } }, 60);
};

onReady(() => {

// ------- bracket auto-pair + auto-indent -------------------------------------
const PAIRS = { '(': ')', '[': ']', '{': '}', '"': '"', "'": "'", '`': '`' };
const CLOSERS = new Set(Object.values(PAIRS));

dom.editor.addEventListener('keydown', e => {
  if (e.isComposing) return;
  if (e.key === 'Enter' && !e.shiftKey && !e.metaKey && !e.ctrlKey) {
    const ta = dom.editor;
    const s = ta.selectionStart;
    const text = ta.value;
    const lineStart = text.lastIndexOf('\n', s - 1) + 1;
    const line = text.slice(lineStart, s);
    const indent = (line.match(/^[\t ]*/) || [''])[0];
    const prevCh = text[s - 1] || '';
    const nextCh = text[s] || '';
    let insert = '\n' + indent;
    let extraIndent = '';
    if (/[\{\[\(:]/.test(prevCh)) extraIndent = '  ';
    insert += extraIndent;
    // smart: if next is matching closer, put it on its own indented line
    if ((prevCh === '{' && nextCh === '}') || (prevCh === '[' && nextCh === ']') || (prevCh === '(' && nextCh === ')')) {
      const trailing = '\n' + indent;
      const value = text.slice(0, s) + insert + trailing + text.slice(s);
      e.preventDefault();
      ta.value = value;
      ta.selectionStart = ta.selectionEnd = s + insert.length;
      ta.dispatchEvent(new Event('input'));
      return;
    }
    if (indent.length > 0 || extraIndent) {
      e.preventDefault();
      ta.value = text.slice(0, s) + insert + text.slice(s);
      ta.selectionStart = ta.selectionEnd = s + insert.length;
      ta.dispatchEvent(new Event('input'));
    }
    return;
  }
  if (e.key in PAIRS && !e.metaKey && !e.ctrlKey) {
    const ta = dom.editor;
    const s = ta.selectionStart, end = ta.selectionEnd;
    const text = ta.value;
    const open = e.key, close = PAIRS[open];
    // If selection: wrap
    if (s !== end) {
      e.preventDefault();
      ta.value = text.slice(0, s) + open + text.slice(s, end) + close + text.slice(end);
      ta.selectionStart = s + 1;
      ta.selectionEnd = end + 1;
      ta.dispatchEvent(new Event('input'));
      return;
    }
    // If quote and prev char is alnum, treat as just typed quote (no pair)
    if ((open === '"' || open === "'" || open === '`') && /\w/.test(text[s - 1] || '')) return;
    e.preventDefault();
    ta.value = text.slice(0, s) + open + close + text.slice(s);
    ta.selectionStart = ta.selectionEnd = s + 1;
    ta.dispatchEvent(new Event('input'));
    return;
  }
  // Overtype matching closer
  if (CLOSERS.has(e.key) && !e.metaKey && !e.ctrlKey) {
    const ta = dom.editor;
    if (ta.selectionStart === ta.selectionEnd && ta.value[ta.selectionStart] === e.key) {
      e.preventDefault();
      ta.selectionStart = ta.selectionEnd = ta.selectionStart + 1;
    }
  }
  // Tab indents (2 spaces) — keep tab focusable via Esc-then-Tab
  if (e.key === 'Tab' && !e.metaKey && !e.ctrlKey) {
    e.preventDefault();
    const ta = dom.editor;
    const s = ta.selectionStart, end = ta.selectionEnd;
    if (s === end) {
      ta.value = ta.value.slice(0, s) + '  ' + ta.value.slice(s);
      ta.selectionStart = ta.selectionEnd = s + 2;
    } else {
      // Indent each selected line
      const text = ta.value;
      const ls = text.lastIndexOf('\n', s - 1) + 1;
      const block = text.slice(ls, end);
      const indented = block.replace(/^/gm, e.shiftKey ? '' : '  ');
      const dedented = e.shiftKey ? block.replace(/^ {1,2}/gm, '') : indented;
      ta.value = text.slice(0, ls) + dedented + text.slice(end);
      ta.selectionStart = ls;
      ta.selectionEnd = ls + dedented.length;
    }
    ta.dispatchEvent(new Event('input'));
  }
});

// ------- line move / duplicate ----------------------------------------------
const lineBounds = (text, pos) => {
  const start = text.lastIndexOf('\n', pos - 1) + 1;
  const endNl = text.indexOf('\n', pos);
  const end = endNl === -1 ? text.length : endNl;
  return { start, end };
};
const moveLine = dir => {
  const ta = dom.editor;
  const text = ta.value;
  const { start, end } = lineBounds(text, ta.selectionStart);
  const line = text.slice(start, end);
  if (dir < 0 && start === 0) return;
  if (dir > 0 && end === text.length) return;
  if (dir < 0) {
    const prevStart = text.lastIndexOf('\n', start - 2) + 1;
    const prevLine = text.slice(prevStart, start - 1);
    const replaced = text.slice(0, prevStart) + line + '\n' + prevLine + text.slice(end);
    ta.value = replaced;
    const newStart = prevStart;
    ta.selectionStart = ta.selectionEnd = newStart;
  } else {
    const nextEnd = text.indexOf('\n', end + 1);
    const nx = nextEnd === -1 ? text.length : nextEnd;
    const nextLine = text.slice(end + 1, nx);
    const replaced = text.slice(0, start) + nextLine + '\n' + line + text.slice(nx);
    ta.value = replaced;
    ta.selectionStart = ta.selectionEnd = start + nextLine.length + 1;
  }
  ta.dispatchEvent(new Event('input'));
};
const dupLine = () => {
  const ta = dom.editor;
  const text = ta.value;
  const { start, end } = lineBounds(text, ta.selectionStart);
  const line = text.slice(start, end);
  ta.value = text.slice(0, end) + '\n' + line + text.slice(end);
  ta.selectionStart = ta.selectionEnd = end + 1 + line.length;
  ta.dispatchEvent(new Event('input'));
};

document.addEventListener('keydown', e => {
  if (e.altKey && (e.key === 'ArrowUp' || e.key === 'ArrowDown')) {
    e.preventDefault();
    moveLine(e.key === 'ArrowUp' ? -1 : 1);
  }
  if ((e.metaKey || e.ctrlKey) && (e.key === 'd' || e.key === 'D')) {
    if (document.activeElement === dom.editor) {
      e.preventDefault();
      dupLine();
    }
  }
}, true);

// ------- trim trailing whitespace on save -----------------------------------
prefs.trim = prefs.trim ?? false;
const origSave = doc.save;
doc.save = async function() {
  if (prefs.trim && dom.editor && !dom.editor.readOnly) {
    dom.editor.value = dom.editor.value.replace(/[ \t]+$/gm, '');
  }
  return origSave.apply(this, arguments);
};

// ------- paste auto-format detection ----------------------------------------
dom.editor.addEventListener('paste', e => {
  // Only offer when whole-editor empty or paste looks like JSON
  const cd = e.clipboardData;
  if (!cd) return;
  const text = cd.getData('text/plain');
  const tr = text.trim();
  if ((tr.startsWith('{') && tr.endsWith('}')) || (tr.startsWith('[') && tr.endsWith(']'))) {
    // queue offer after paste lands
    setTimeout(() => {
      if (ui.confirmFmt) return;
      ui.confirmFmt = true;
      ui.toast('Cmd+Shift+I → format JSON');
      setTimeout(() => { ui.confirmFmt = false; }, 4000);
    }, 100);
  }
});

// ------- outline pane (palette command, expanded UI) ------------------------
ui.showOutline = () => {
  dom.modal_title.textContent = 'outline';
  dom.password_form.style.display = 'none';
  dom.docs_list.style.display = 'block';
  dom.modal.classList.add('show');
  const text = (typeof getText === 'function' ? getText() : dom.editor.value);
  const lines = text.split('\n');
  const items = [];
  if (currentLang === 6 || /^\s*#/m.test(text)) {
    // markdown headings
    lines.forEach((l, i) => {
      const m = l.match(/^(#{1,6})\s+(.+)/);
      if (m) items.push({ depth: m[1].length, label: m[2].trim(), line: i + 1 });
    });
  } else {
    // generic symbol-ish: function/def/class/fn/const at start of line
    lines.forEach((l, i) => {
      const m = l.match(/^\s*(?:export\s+)?(?:async\s+)?(?:function|class|const|let|var|def|fn|impl|struct|enum|trait|mod|pub\s+fn|pub\s+struct)\s+([A-Za-z_][\w]*)/);
      if (m) items.push({ depth: 1, label: m[1] + '  (' + (l.trim().slice(0, 60)) + ')', line: i + 1 });
    });
  }
  if (!items.length) { dom.docs_list.innerHTML = '<div class="no-docs">no symbols / headings</div>'; return; }
  dom.docs_list.innerHTML = items.map(it => `
    <div class="doc-item" data-line="${it.line}" style="padding-left:${(it.depth-1) * 16 + 12}px">
      <div class="doc-info">
        <span class="doc-title">${escape(it.label)}</span>
        <span class="doc-meta">L${it.line}</span>
      </div>
    </div>`).join('');
  dom.docs_list.querySelectorAll('.doc-item').forEach(el => el.onclick = () => {
    const n = parseInt(el.dataset.line);
    ui.closeModal();
    if (typeof actions !== 'undefined' && actions.gotoLine) {
      // jump to specific line directly
      const lines = dom.editor.value.split('\n');
      let off = 0;
      for (let i = 0; i < n - 1 && i < lines.length; i++) off += lines[i].length + 1;
      dom.editor.focus();
      dom.editor.setSelectionRange(off, off);
      dom.editor.scrollTop = (n - 1) * 22;
    }
  });
};
const escape = s => { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; };

// ------- encoding palette (sha256/b64/hex/url/jsonpath/jwt/ascii) -----------
const subtleSha256 = async s => {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
};
const sel = () => {
  const ta = dom.editor;
  if (ta.selectionStart === ta.selectionEnd) return ta.value;
  return ta.value.slice(ta.selectionStart, ta.selectionEnd);
};
const replaceSel = (txt) => {
  const ta = dom.editor;
  const s = ta.selectionStart, e = ta.selectionEnd;
  if (s === e) { ta.value = txt; ta.selectionStart = ta.selectionEnd = txt.length; }
  else { ta.value = ta.value.slice(0, s) + txt + ta.value.slice(e); ta.selectionStart = s; ta.selectionEnd = s + txt.length; }
  ta.dispatchEvent(new Event('input'));
};
const toHex = s => [...new TextEncoder().encode(s)].map(b => b.toString(16).padStart(2, '0')).join(' ');
const fromHex = s => {
  const cleaned = s.replace(/[^0-9a-fA-F]/g, '');
  const out = new Uint8Array(cleaned.length / 2);
  for (let i = 0; i < cleaned.length; i += 2) out[i / 2] = parseInt(cleaned.slice(i, i + 2), 16);
  return new TextDecoder().decode(out);
};

ui.runEncodeCmd = async (op) => {
  const s = sel();
  try {
    if (op === 'sha256') {
      const h = await subtleSha256(s);
      navigator.clipboard.writeText(h).catch(() => {});
      ui.toast('sha256 copied: ' + h.slice(0, 16) + '…');
    }
    else if (op === 'b64enc') replaceSel(btoa(unescape(encodeURIComponent(s))));
    else if (op === 'b64dec') { try { replaceSel(decodeURIComponent(escape(atob(s)))); } catch { ui.toast('not base64'); } }
    else if (op === 'b64urlenc') replaceSel(W.b64enc(new TextEncoder().encode(s)));
    else if (op === 'b64urldec') {
      const b = W.b64dec(s);
      if (b) replaceSel(new TextDecoder().decode(b));
      else ui.toast('not base64url');
    }
    else if (op === 'hexenc') replaceSel(toHex(s));
    else if (op === 'hexdec') replaceSel(fromHex(s));
    else if (op === 'urlenc') replaceSel(encodeURIComponent(s));
    else if (op === 'urldec') { try { replaceSel(decodeURIComponent(s)); } catch { ui.toast('bad url'); } }
    else if (op === 'jwt') {
      W.jwtDecode(s).then(out => {
        if (!out) return ui.toast('not a jwt');
        replaceSel(out);
      });
    }
    else if (op === 'jsonpath') {
      const path = prompt('jsonpath, e.g. $.a.b[0].c');
      if (!path) return;
      const out = W.jsonQuery(dom.editor.value, path);
      if (!out) return ui.toast('no match');
      ui.toast('match: ' + out.slice(0, 40));
      navigator.clipboard.writeText(out).catch(() => {});
    }
    else if (op === 'ascii') {
      const t = W.asciiArt(s || prompt('text for banner') || '');
      if (t) replaceSel(t);
    }
    else if (op === 'reverse') replaceSel([...s].reverse().join(''));
    else if (op === 'sort-lines') replaceSel(s.split('\n').sort().join('\n'));
    else if (op === 'uniq-lines') replaceSel([...new Set(s.split('\n'))].join('\n'));
    else if (op === 'upper') replaceSel(s.toUpperCase());
    else if (op === 'lower') replaceSel(s.toLowerCase());
    else if (op === 'wc') ui.toast(`${s.split('\n').length}L · ${s.length}C · ${new TextEncoder().encode(s).length}B`);
  } catch (e) { console.error(e); ui.toast('failed'); }
};

// wire wasm extras
W.sha256Hex = (data) => {
  resetHeap();
  const r = fromW(wasm.sha256_hex(...args(toW(data))));
  return r ? new TextDecoder().decode(r) : null;
};
W.jsonQuery = (src, path) => {
  resetHeap();
  const r = fromW(wasm.json_query(...args(toW(new TextEncoder().encode(src))), ...args(toW(new TextEncoder().encode(path)))));
  return r ? new TextDecoder().decode(r) : null;
};
W.jwtDecode = async (token) => {
  resetHeap();
  const r = fromW(wasm.jwt_decode(...args(toW(new TextEncoder().encode(token)))));
  return r ? new TextDecoder().decode(r) : null;
};
W.jwtVerifyEdDSA = (token, pk32) => {
  resetHeap();
  return wasm.jwt_verify_eddsa(...args(toW(new TextEncoder().encode(token))), toW(pk32).ptr) === 1;
};
W.asciiArt = (text) => {
  if (!text) return '';
  resetHeap();
  const r = fromW(wasm.ascii_art(...args(toW(new TextEncoder().encode(text)))));
  return r ? new TextDecoder().decode(r) : '';
};

// ------- JSON structure tree view -------------------------------------------
const typeOf = v => {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'array';
  return typeof v; // string / number / boolean / object
};
const TYPE_COLORS = {
  string:  '#ffc890',
  number:  '#c1ff7a',
  boolean: '#d49bff',
  null:    '#6a7178',
  object:  '#66e0ff',
  array:   '#ffb648'
};
const renderJsonNode = (v, key, path, isLast = true) => {
  const t = typeOf(v);
  const color = TYPE_COLORS[t];
  const keyHtml = key !== null ? `<span class="jt-key" data-path="${escape(path)}">${escape(String(key))}</span>` : '';
  if (t === 'object' || t === 'array') {
    const entries = t === 'array'
      ? v.map((x, i) => [i, x])
      : Object.entries(v);
    const summary =
      `${keyHtml}` +
      `<span class="jt-bracket">${t === 'array' ? '[' : '{'}</span>` +
      `<span class="jt-meta" style="color:${color}"> ${entries.length} ${t === 'array' ? 'items' : 'keys'} </span>` +
      `<span class="jt-bracket">${t === 'array' ? ']' : '}'}</span>`;
    if (entries.length === 0) return `<div class="jt-leaf">${summary}</div>`;
    const children = entries.map(([k, val], i) => {
      const childPath = t === 'array' ? `${path}[${k}]` : (path ? `${path}.${k}` : `$.${k}`);
      return renderJsonNode(val, k, childPath, i === entries.length - 1);
    }).join('');
    return `<details class="jt-node" open data-path="${escape(path)}"><summary>${summary}</summary><div class="jt-children">${children}</div></details>`;
  }
  // leaf
  let val;
  let extra = '';
  if (t === 'string') {
    val = `<span class="jt-str">"${escape(v)}"</span>`;
    extra = `<span class="jt-meta">len ${[...v].length}</span>`;
  } else if (t === 'number') {
    val = `<span class="jt-num">${v}</span>`;
    if (Number.isInteger(v)) extra = '<span class="jt-meta">int</span>';
    else extra = '<span class="jt-meta">float</span>';
  } else if (t === 'boolean') {
    val = `<span class="jt-bool">${v}</span>`;
  } else if (t === 'null') {
    val = `<span class="jt-null">null</span>`;
  }
  return `<div class="jt-leaf" data-path="${escape(path)}">` +
    `${keyHtml}<span class="jt-val">${val}</span>` +
    `<span class="jt-type" style="color:${color}">${t}</span>${extra}</div>`;
};

const aggregateSchema = (v, schema = { _types: new Set() }) => {
  const t = typeOf(v);
  schema._types.add(t);
  if (t === 'object') {
    schema._keys = schema._keys || {};
    for (const [k, val] of Object.entries(v)) {
      schema._keys[k] = schema._keys[k] || { _types: new Set(), _count: 0 };
      schema._keys[k]._count += 1;
      aggregateSchema(val, schema._keys[k]);
    }
  } else if (t === 'array') {
    schema._items = schema._items || { _types: new Set() };
    for (const x of v) aggregateSchema(x, schema._items);
  }
  return schema;
};
const renderSchema = (s, key = '$', depth = 0) => {
  if (!s) return '';
  const types = [...s._types].sort();
  const tStr = types.map(t => `<span style="color:${TYPE_COLORS[t]}">${t}</span>`).join(' | ');
  const indent = '  '.repeat(depth);
  let out = `${indent}<span class="jt-key">${escape(key)}</span> : ${tStr}`;
  if (s._count !== undefined && s._count > 1) out += ` <span class="jt-meta">×${s._count}</span>`;
  out += '\n';
  if (s._keys) {
    for (const [k, sub] of Object.entries(s._keys)) {
      out += renderSchema(sub, k, depth + 1);
    }
  }
  if (s._items) {
    out += renderSchema(s._items, '[*]', depth + 1);
  }
  return out;
};

ui.showJsonTree = () => {
  dom.modal_title.textContent = 'json structure';
  dom.password_form.style.display = 'none';
  dom.docs_list.style.display = 'block';
  dom.modal.classList.add('show');
  const txt = (typeof getText === 'function' ? getText() : dom.editor.value).trim();
  let val;
  try { val = JSON.parse(txt); }
  catch (e) {
    dom.docs_list.innerHTML = `
      <div class="error" style="text-align:left;padding:1rem">
        <div style="margin-bottom:0.5rem">parse error</div>
        <pre style="margin:0;color:var(--blood);font-size:0.7rem;white-space:pre-wrap">${escape(e.message)}</pre>
      </div>`;
    return;
  }
  const t = typeOf(val);
  const sz = Array.isArray(val) ? val.length
    : (val && typeof val === 'object') ? Object.keys(val).length
    : null;
  dom.docs_list.innerHTML = `
    <style>
      .jt-toolbar { display:flex; gap:0.3rem; margin-bottom:0.6rem; }
      .jt-toolbar button { padding:0.3rem 0.5rem; font-size:0.6rem; }
      .jt-tree { font-family: var(--mono); font-size: 0.74rem; line-height: 1.45;
                 background: var(--ink); border: 1px solid var(--rule); padding: 0.6rem;
                 max-height: 360px; overflow: auto; color: var(--text); }
      .jt-tree details { padding-left: 0.4rem; border-left: 1px dashed var(--rule-soft); margin-left: 0.1rem; }
      .jt-tree summary { cursor: pointer; list-style: none; padding: 0.05rem 0; }
      .jt-tree summary::-webkit-details-marker { display: none; }
      .jt-tree summary::before { content: '▾'; display: inline-block; width: 0.8rem; color: var(--text-dim); }
      .jt-tree details:not([open]) > summary::before { content: '▸'; }
      .jt-tree .jt-children { padding-left: 0.6rem; }
      .jt-tree .jt-leaf { padding: 0.05rem 0 0.05rem 0.8rem; display:flex; gap:0.4rem; align-items:center; }
      .jt-tree .jt-key { color: #b2f2ff; cursor: pointer; }
      .jt-tree .jt-key:hover { text-decoration: underline; }
      .jt-tree .jt-bracket { color: var(--text-dim); margin: 0 0.15rem; }
      .jt-tree .jt-val { flex: 1; min-width: 0; }
      .jt-tree .jt-str { color: #ffc890; }
      .jt-tree .jt-num { color: #c1ff7a; }
      .jt-tree .jt-bool { color: #d49bff; }
      .jt-tree .jt-null { color: var(--text-dim); }
      .jt-tree .jt-type { font-size: 0.6rem; text-transform: uppercase; letter-spacing: 0.1em;
                          padding: 0.05rem 0.35rem; border: 1px solid currentColor; opacity: 0.85; }
      .jt-tree .jt-meta { font-size: 0.62rem; color: var(--text-dim); letter-spacing: 0.05em; }
      .jt-schema { font-family: var(--mono); font-size: 0.72rem; white-space: pre;
                   background: var(--ink); border: 1px solid var(--rule); padding: 0.6rem;
                   max-height: 360px; overflow: auto; color: var(--text); display: none; }
    </style>
    <div class="jt-toolbar">
      <button id="jt-tab-tree" class="active">tree</button>
      <button id="jt-tab-schema">schema</button>
      <span style="flex:1"></span>
      <button id="jt-expand">expand</button>
      <button id="jt-collapse">collapse</button>
      <button id="jt-copy">copy pretty</button>
    </div>
    <div class="jt-tree" id="jt-tree-view">${renderJsonNode(val, null, '$')}</div>
    <div class="jt-schema" id="jt-schema-view"></div>
    <div style="margin-top:0.4rem;font-size:0.62rem;color:var(--text-dim);letter-spacing:0.08em">
      root: <span style="color:${TYPE_COLORS[t]}">${t}</span>${sz !== null ? ` · ${sz} ${t === 'array' ? 'items' : 'keys'}` : ''} · click any key to copy its JSONPath
    </div>`;
  // schema view renders raw HTML; re-render properly:
  const schemaHtml = renderSchema(aggregateSchema(val));
  // schema string contains <span> already; place as innerHTML pre-style
  const schemaEl = document.getElementById('jt-schema-view');
  schemaEl.innerHTML = schemaHtml;

  const treeEl = document.getElementById('jt-tree-view');
  treeEl.addEventListener('click', e => {
    const k = e.target.closest('.jt-key');
    if (!k) return;
    const path = k.dataset.path || k.closest('[data-path]')?.dataset.path;
    if (path) {
      navigator.clipboard.writeText(path).catch(() => {});
      ui.toast('path copied: ' + path);
    }
  });

  document.getElementById('jt-tab-tree').onclick = () => {
    treeEl.style.display = '';
    schemaEl.style.display = 'none';
    document.getElementById('jt-tab-tree').classList.add('active');
    document.getElementById('jt-tab-schema').classList.remove('active');
  };
  document.getElementById('jt-tab-schema').onclick = () => {
    treeEl.style.display = 'none';
    schemaEl.style.display = 'block';
    document.getElementById('jt-tab-schema').classList.add('active');
    document.getElementById('jt-tab-tree').classList.remove('active');
  };
  document.getElementById('jt-expand').onclick = () => treeEl.querySelectorAll('details').forEach(d => d.open = true);
  document.getElementById('jt-collapse').onclick = () => treeEl.querySelectorAll('details').forEach(d => d.open = false);
  document.getElementById('jt-copy').onclick = () => {
    try { navigator.clipboard.writeText(JSON.stringify(val, null, 2)); ui.toast('pretty copied'); }
    catch { ui.toast('copy failed'); }
  };
};

// ------- hex viewer toggle --------------------------------------------------
let hexMode = false;
ui.toggleHexView = () => {
  const ta = dom.editor;
  if (!hexMode) {
    ta.dataset.original = ta.value;
    const bytes = new TextEncoder().encode(ta.value);
    let out = '';
    for (let off = 0; off < bytes.length; off += 16) {
      const chunk = bytes.subarray(off, off + 16);
      const hex = [...chunk].map(b => b.toString(16).padStart(2, '0')).join(' ').padEnd(48, ' ');
      const ascii = [...chunk].map(b => (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : '·').join('');
      out += off.toString(16).padStart(8, '0') + '  ' + hex + ' │ ' + ascii + '\n';
    }
    ta.value = out;
    ta.readOnly = true;
    hexMode = true;
    ui.toast('hex view (read-only)');
  } else {
    ta.value = ta.dataset.original || '';
    delete ta.dataset.original;
    ta.readOnly = false;
    hexMode = false;
    ui.toast('text view');
    ta.dispatchEvent(new Event('input'));
  }
};

// ------- CSV align toggle ---------------------------------------------------
let csvMode = false;
const csvParseLine = line => {
  const cells = [];
  let cur = '', inQ = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (inQ) {
      if (c === '"' && line[i + 1] === '"') { cur += '"'; i++; }
      else if (c === '"') inQ = false;
      else cur += c;
    } else {
      if (c === ',') { cells.push(cur); cur = ''; }
      else if (c === '"') inQ = true;
      else cur += c;
    }
  }
  cells.push(cur);
  return cells;
};
ui.toggleCSVView = () => {
  const ta = dom.editor;
  if (!csvMode) {
    ta.dataset.original = ta.value;
    const lines = ta.value.split('\n').filter(Boolean);
    const rows = lines.map(csvParseLine);
    const cols = Math.max(...rows.map(r => r.length));
    const widths = Array(cols).fill(0);
    for (const r of rows) for (let i = 0; i < r.length; i++) widths[i] = Math.max(widths[i], r[i].length);
    const out = rows.map(r => r.map((c, i) => c.padEnd(widths[i], ' ')).join('  │  ')).join('\n');
    ta.value = out;
    ta.readOnly = true;
    csvMode = true;
    ui.toast('csv aligned (read-only)');
  } else {
    ta.value = ta.dataset.original || '';
    delete ta.dataset.original;
    ta.readOnly = false;
    csvMode = false;
    ui.toast('csv raw');
    ta.dispatchEvent(new Event('input'));
  }
};

// ------- realtime cursor (Supabase Realtime, requires active session) -------
let rtChannel = null;
const cursorBadges = new Map(); // peerId -> { x, y, color, lastSeen }
const peerId = Math.random().toString(36).slice(2, 9);
const peerColor = `hsl(${(peerId.charCodeAt(0) * 17) % 360} 70% 60%)`;
ui.startRealtime = () => {
  if (!supabase || !sessionKey) return;
  if (rtChannel) supabase.removeChannel(rtChannel);
  rtChannel = supabase.channel('gt:' + sessionKey, { config: { broadcast: { ack: false } } });
  rtChannel.on('broadcast', { event: 'cursor' }, (m) => {
    if (m.payload.peer === peerId) return;
    cursorBadges.set(m.payload.peer, { ...m.payload, lastSeen: Date.now() });
    renderCursors();
  });
  rtChannel.subscribe();
  dom.editor.addEventListener('keyup', sendCursor);
  dom.editor.addEventListener('click', sendCursor);
};
ui.stopRealtime = () => {
  if (rtChannel) { try { supabase.removeChannel(rtChannel); } catch {} rtChannel = null; }
  cursorBadges.clear();
  renderCursors();
};
const sendCursor = () => {
  if (!rtChannel) return;
  const ta = dom.editor;
  const text = ta.value;
  const pos = ta.selectionStart;
  const line = (text.slice(0, pos).match(/\n/g) || []).length + 1;
  const col = pos - text.lastIndexOf('\n', pos - 1);
  rtChannel.send({ type: 'broadcast', event: 'cursor', payload: { peer: peerId, line, col, color: peerColor } });
};
const renderCursors = () => {
  let layer = document.getElementById('rt-badges');
  if (!layer) {
    layer = document.createElement('div');
    layer.id = 'rt-badges';
    layer.style.cssText = 'position:absolute;right:1rem;top:0.6rem;display:flex;gap:0.3rem;flex-wrap:wrap;z-index:5;pointer-events:none';
    dom.editor_wrapper.appendChild(layer);
  }
  const now = Date.now();
  for (const [id, b] of [...cursorBadges]) if (now - b.lastSeen > 5000) cursorBadges.delete(id);
  layer.innerHTML = [...cursorBadges].map(([id, b]) =>
    `<span style="background:${b.color};color:#000;padding:1px 5px;font-size:0.6rem;letter-spacing:0.06em">${escape(id)} ${b.line}:${b.col}</span>`
  ).join('');
};
setInterval(renderCursors, 2000);

// patch session.startSync to also start realtime
const origStartSync = session.startSync;
session.startSync = function() { origStartSync.apply(this, arguments); ui.startRealtime(); };
const origStop = session.stop;
session.stop = function() { ui.stopRealtime(); origStop.apply(this, arguments); };

// ------- verify-by-domain (DoH TXT lookup) ---------------------------------
ui.verifyDomain = async (pkB64) => {
  const dom = prompt('domain to check (e.g. example.com)');
  if (!dom) return;
  try {
    const r = await fetch(`https://dns.google/resolve?name=_gitext.${dom}&type=TXT`);
    const j = await r.json();
    const txts = (j.Answer || []).map(a => a.data.replace(/"/g, ''));
    const wantHash = await subtleSha256(pkB64);
    const want = wantHash.slice(0, 32);
    const ok = txts.some(t => t.includes(want));
    ui.toast(ok ? `✓ ${dom} confirms key` : `✗ no match at _gitext.${dom}`);
  } catch (e) { ui.toast('dns lookup failed'); }
};

// ------- markdown preview scroll sync --------------------------------------
const origRenderPreview = ui.renderPreview;
ui.renderPreview = function() {
  origRenderPreview && origRenderPreview.apply(this, arguments);
  if (!dom.preview_pane) return;
  // line-anchored scroll
  const ta = dom.editor;
  const totalLines = ta.value.split('\n').length;
  const frac = ta.scrollTop / Math.max(1, ta.scrollHeight - ta.clientHeight);
  dom.preview_pane.scrollTop = frac * (dom.preview_pane.scrollHeight - dom.preview_pane.clientHeight);
};
dom.editor.addEventListener('scroll', () => {
  if (!prefs.preview || !dom.preview_pane) return;
  const ta = dom.editor;
  const frac = ta.scrollTop / Math.max(1, ta.scrollHeight - ta.clientHeight);
  dom.preview_pane.scrollTop = frac * (dom.preview_pane.scrollHeight - dom.preview_pane.clientHeight);
});

// ------- extend command palette --------------------------------------------
const origPalette = ui.showPalette;
ui.showPalette = function() {
  // Replace with extended version
  dom.modal_title.textContent = 'command palette';
  dom.password_form.style.display = 'none';
  dom.docs_list.style.display = 'block';
  dom.modal.classList.add('show');
  const cmds = [
    // existing top items
    { l: 'save',                     k: '⌘S',  r: () => doc.save() },
    { l: 'copy share link',          k: '⌘⇧C', r: () => actions.copy() },
    { l: 'toggle encryption',                  r: () => actions.toggleEnc() },
    { l: 'cycle language',           k: '⌘L',  r: () => actions.cycleLang() },
    { l: 'go to line…',              k: '⌘G',  r: () => actions.gotoLine() },
    { l: 'search & replace',         k: '⌘F',  r: () => ui.showSearch() },
    { l: 'outline / symbols',                  r: () => ui.showOutline() },
    { l: 'toggle word wrap',                   r: () => { prefs.wrap = !prefs.wrap; savePrefs(); ui.applyTheme(); ui.toast('wrap ' + (prefs.wrap ? 'on' : 'off')); } },
    { l: 'toggle theme',                       r: () => { prefs.theme = prefs.theme === 'phosphor' ? 'paper' : 'phosphor'; savePrefs(); ui.applyTheme(); } },
    { l: 'toggle markdown preview',            r: () => ui.togglePreview() },
    { l: 'toggle hex view',                    r: () => ui.toggleHexView() },
    { l: 'toggle CSV align view',              r: () => ui.toggleCSVView() },
    { l: 'json structure / schema view',       r: () => ui.showJsonTree() },
    { l: 'toggle trim trailing whitespace on save', r: () => { prefs.trim = !prefs.trim; savePrefs(); ui.toast('trim ' + (prefs.trim ? 'on' : 'off')); } },
    // formatters
    { l: 'format json',                        r: () => actions.formatJSON() },
    { l: 'reflow markdown',                    r: () => actions.formatMD() },
    // encoding tools
    { l: 'sha-256 selection → clipboard',      r: () => ui.runEncodeCmd('sha256') },
    { l: 'base64 encode selection',            r: () => ui.runEncodeCmd('b64enc') },
    { l: 'base64 decode selection',            r: () => ui.runEncodeCmd('b64dec') },
    { l: 'base64url encode selection',         r: () => ui.runEncodeCmd('b64urlenc') },
    { l: 'base64url decode selection',         r: () => ui.runEncodeCmd('b64urldec') },
    { l: 'hex encode selection',               r: () => ui.runEncodeCmd('hexenc') },
    { l: 'hex decode selection',               r: () => ui.runEncodeCmd('hexdec') },
    { l: 'url encode selection',               r: () => ui.runEncodeCmd('urlenc') },
    { l: 'url decode selection',               r: () => ui.runEncodeCmd('urldec') },
    { l: 'jwt decode selection',               r: () => ui.runEncodeCmd('jwt') },
    { l: 'jsonpath query…',                    r: () => ui.runEncodeCmd('jsonpath') },
    { l: 'ascii-art banner from selection',    r: () => ui.runEncodeCmd('ascii') },
    { l: 'reverse selection',                  r: () => ui.runEncodeCmd('reverse') },
    { l: 'sort lines in selection',            r: () => ui.runEncodeCmd('sort-lines') },
    { l: 'uniq lines in selection',            r: () => ui.runEncodeCmd('uniq-lines') },
    { l: 'uppercase selection',                r: () => ui.runEncodeCmd('upper') },
    { l: 'lowercase selection',                r: () => ui.runEncodeCmd('lower') },
    { l: 'count selection',                    r: () => ui.runEncodeCmd('wc') },
    // doc / share
    { l: 'snapshots…',                         r: () => ui.showSnapshots() },
    { l: 'diff…',                              r: () => ui.showDiff() },
    { l: 'sign / verify…',                     r: () => ui.showSign() },
    { l: 'verify signer by domain (DNS TXT)',  r: () => {
        const kp = JSON.parse(localStorage.getItem('gt:keypair') || 'null');
        if (!kp) return ui.toast('no keypair to verify');
        ui.verifyDomain(kp.pk);
      } },
    { l: 'add new file (multi-file mode)',     r: () => addFile() },
    { l: 'documents…',                         r: () => ui.showDocs() },
    { l: 'download…',                          r: () => ui.showDL() },
    { l: 'qr code',                            r: () => ui.showQR() },
    { l: 'session…',                           r: () => ui.showSessionDlg() },
    { l: 'make read-only share link',          r: () => actions.shareReadOnly() },
    { l: 'clear document',                     r: () => doc.clear() }
  ];
  dom.docs_list.innerHTML = `
    <input id="pl-q" placeholder="type to filter…" style="width:100%;padding:0.65rem;background:var(--ink);border:1px solid var(--rule);color:var(--text-bright);font-family:var(--mono);font-size:0.85rem;margin-bottom:0.6rem">
    <div id="pl-list" style="max-height:380px;overflow:auto"></div>`;
  const render = (filter = '') => {
    const f = filter.toLowerCase();
    const list = cmds.filter(c => c.l.toLowerCase().includes(f));
    document.getElementById('pl-list').innerHTML = list.map((c) => `
      <div class="doc-item pl-item" data-i="${cmds.indexOf(c)}" style="cursor:pointer">
        <div class="doc-info"><span class="doc-title">${escape(c.l)}</span></div>
        ${c.k ? `<div class="doc-meta" style="margin-left:auto">${escape(c.k)}</div>` : ''}
      </div>`).join('');
    document.querySelectorAll('.pl-item').forEach(el => el.onclick = () => {
      const c = cmds[parseInt(el.dataset.i)];
      ui.closeModal();
      c.r();
    });
  };
  render();
  document.getElementById('pl-q').oninput = e => render(e.target.value);
  document.getElementById('pl-q').focus();
  document.getElementById('pl-q').onkeydown = e => {
    if (e.key === 'Enter') {
      const first = document.querySelector('.pl-item');
      if (first) first.click();
    }
  };
};

console.log('gitText extras loaded.');
});
})();
