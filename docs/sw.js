// gitText service worker — cache-first app shell, network passthrough for rest.
const CACHE = 'gt-shell-v3';
const SHELL = ['./', './index.html', './app.js', './editor.wasm', './manifest.json', './icon.svg'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  const u = new URL(e.request.url);
  // Same-origin GETs from the shell list: cache-first; everything else network-first with cache fallback.
  if (e.request.method !== 'GET') return;
  if (u.origin === location.origin) {
    e.respondWith(
      caches.match(e.request).then(c => c || fetch(e.request).then(r => {
        const copy = r.clone();
        caches.open(CACHE).then(cache => cache.put(e.request, copy)).catch(() => {});
        return r;
      })).catch(() => caches.match('./index.html'))
    );
    return;
  }
  // 3rd-party (CDN scripts, supabase) — network with cache fallback.
  e.respondWith(
    fetch(e.request).then(r => {
      if (r.ok) { const copy = r.clone(); caches.open(CACHE).then(c => c.put(e.request, copy)).catch(() => {}); }
      return r;
    }).catch(() => caches.match(e.request))
  );
});
