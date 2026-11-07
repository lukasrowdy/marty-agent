/* Service worker for the Marty app shell.
   Network first: the server marks every shell file no-store, and a stale app.js must
   never outlive a deploy or a rollback. The cache is only the offline fallback.
   Page loads (navigations) go to the network exactly as before and are never cached; only when
   one fails with no network does the cached offline page answer instead of the browser's error
   (v4, 2026-09-25). Every /api request is never touched, never cached, navigation or not.
   Bump CACHE whenever these rules change; activate deletes every other cache. */
const CACHE = "marty-shell-v4";
const OFFLINE = "/offline.html";
const SHELL = ["/style.css", "/app.js", "/manifest.webmanifest", "/icons/icon-192.png", "/icons/icon-512.png", OFFLINE];

self.addEventListener("install", event => {
  event.waitUntil(
    caches.open(CACHE)
      .then(cache => cache.addAll(SHELL.map(path => new Request(path, {cache: "no-store"}))))
      .catch(() => {})   // an offline install still activates; the network path needs no cache
      .then(() => self.skipWaiting()));
});

self.addEventListener("activate", event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(key => key !== CACHE).map(key => caches.delete(key))))
      .then(() => self.clients.claim()));
});

self.addEventListener("fetch", event => {
  const request = event.request;
  if (request.method !== "GET") return;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin || url.pathname.startsWith("/api/")) return;
  if (request.mode === "navigate") {
    event.respondWith(
      fetch(request).catch(() => caches.match(OFFLINE).then(hit => hit || Response.error())));
    return;
  }
  if (!SHELL.includes(url.pathname)) return;
  event.respondWith(
    fetch(request, {cache: "no-store"})
      .then(response => {
        if (response.ok) {
          const copy = response.clone();
          event.waitUntil(caches.open(CACHE).then(cache => cache.put(url.pathname, copy)).catch(() => {}));
        }
        return response;
      })
      .catch(() => caches.match(url.pathname).then(hit => hit || Response.error())));
});
