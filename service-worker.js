const CACHE_NAME = "nexus-shell-v4";
const APP_SHELL = ["/", "/manifest.webmanifest", "/icons/nexus-icon.svg", "/runtime-center.js"];
self.addEventListener("install", event => {
  event.waitUntil(caches.open(CACHE_NAME).then(cache => cache.addAll(APP_SHELL)).then(() => self.skipWaiting()));
});
self.addEventListener("activate", event => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter(key => key.startsWith("nexus-shell-") && key !== CACHE_NAME).map(key => caches.delete(key)));
    await self.clients.claim();
  })());
});
self.addEventListener("fetch", event => {
  const request = event.request, url = new URL(request.url);
  if (request.method !== "GET" || url.origin !== self.location.origin) return;
  if (url.pathname.startsWith("/api/")) return;
  if (request.mode === "navigate") {
    event.respondWith((async () => {
      try {
        const response = await fetch(request);
        if (response.ok) (await caches.open(CACHE_NAME)).put("/", response.clone()).catch(() => {});
        return response;
      } catch (_) { return (await caches.match(request)) || (await caches.match("/")); }
    })());
    return;
  }
  event.respondWith((async () => {
    const cached = await caches.match(request);
    if (cached) return cached;
    try {
      const response = await fetch(request);
      if (response.ok && (url.pathname.startsWith("/icons/") || url.pathname === "/manifest.webmanifest"))
        (await caches.open(CACHE_NAME)).put(request, response.clone()).catch(() => {});
      return response;
    } catch (_) { return cached || Response.error(); }
  })());
});
