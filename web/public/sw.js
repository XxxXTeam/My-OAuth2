/*
 * Service Worker — OAuth2 PWA 离线缓存
 * 功能：缓存静态资源，离线时回退到 offline.html
 * 策略：Network First（API）+ Cache First（静态资源）
 */
const CACHE_NAME = 'oauth2-v1';
const STATIC_ASSETS = [
  '/',
  '/offline.html',
  '/manifest.json',
  '/icons/icon-192x192.svg',
  '/icons/icon-512x512.svg',
];

/* 安装：预缓存核心静态资源 */
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(STATIC_ASSETS))
  );
  self.skipWaiting();
});

/* 激活：清理旧缓存 */
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

/* 请求拦截 */
self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);

  /* API 请求：Network Only，不缓存 */
  if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/oauth/')) {
    return;
  }

  /* 静态资源（JS/CSS/图片）：Cache First */
  if (request.destination === 'script' || request.destination === 'style' || request.destination === 'image' || request.destination === 'font') {
    event.respondWith(
      caches.match(request).then((cached) => {
        if (cached) return cached;
        return fetch(request).then((response) => {
          if (response.ok) {
            const clone = response.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(request, clone));
          }
          return response;
        });
      })
    );
    return;
  }

  /* HTML 页面：Network First，离线回退 */
  if (request.mode === 'navigate') {
    event.respondWith(
      fetch(request).catch(() => caches.match('/offline.html'))
    );
    return;
  }
});
