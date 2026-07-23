const CACHE_NAME = "cyber-tools-v1";
const ASSETS_TO_CACHE = [
  "/tools/index.html",
  "/tools/header.html",
  "/tools/footer.html",
  "/tools/favicon.png",
];
self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(ASSETS_TO_CACHE);
    }),
  );
});
self.addEventListener("fetch", (event) => {
  if (event.request.method === "GET") {
    event.respondWith(
      caches.match(event.request).then((cached) => {
        return cached || fetch(event.request);
      }),
    );
  }
});
