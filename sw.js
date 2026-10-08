const CACHE = 'mojave-v4';
const ASSETS = ['./','./index.html','./app.js','./config.js','./manifest.json',
  './vendor/qrcode.min.js','./vendor/jspdf.umd.min.js','./vendor/jspdf.plugin.autotable.min.js','./vendor/chart.umd.min.js',
  './assets/fondo-mojave-mobile.webp','./assets/fondo-mojave-desktop.webp','./assets/logo-mojave.jpg',
  './icons/icon-192.png','./icons/icon-512.png','./icons/icon-maskable-512.png','./icons/apple-touch-icon.png'];

// cache:'reload' — GitHub Pages manda Cache-Control max-age=600: con addAll(ASSETS) a secas el
// precache de una versión NUEVA podía llenarse con el app.js/index.html VIEJO que el navegador
// aún tenía en su caché HTTP (hasta 10 min). 'reload' obliga a traer cada archivo del servidor.
self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE)
    .then(c => c.addAll(ASSETS.map(u => new Request(u, { cache:'reload' }))))
    .then(()=>self.skipWaiting()));
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k=>k!==CACHE).map(k=>caches.delete(k)))).then(()=>self.clients.claim()));
});

// La "app shell" (index.html/app.js) va primero-la-red: así una versión nueva se ve de inmediato
// en vez de quedarse pegada a lo que ya estaba en caché. Todo lo demás (vendor, imágenes,
// iconos, manifest) sigue cache-primero como antes: cambia poco y no vale la pena regresar a
// la red por eso en cada carga.
function esAppShell(req, url){
  return req.mode === 'navigate' || url.pathname.endsWith('/app.js') || url.pathname.endsWith('/index.html');
}

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  // Nunca cachear llamadas al Worker ni a Firebase
  if (url.pathname.startsWith('/abrir') || url.hostname.includes('workers.dev') || url.hostname.includes('googleapis')) return;

  if (esAppShell(e.request, url)){
    e.respondWith(
      // cache:'no-cache' — "primero la red" de verdad: revalida con el servidor en vez de
      // aceptar lo que el navegador tenga en su caché HTTP (max-age=600 de GitHub Pages), que
      // podía devolver el app.js viejo hasta 10 min después de publicar.
      fetch(e.request, { cache:'no-cache' })
        .then(res => {
          if (res.ok){
            const copy = res.clone();
            caches.open(CACHE).then(c => c.put(e.request, copy));
          }
          return res;
        })
        .catch(() => caches.match(e.request).then(r => r || caches.match('./index.html')))
    );
    return;
  }
  e.respondWith(caches.match(e.request).then(r => r || fetch(e.request)));
});

// app.js pregunta por postMessage qué versión tiene ESTE service worker activo (para mostrarla
// en Gestión) — así siempre se muestra lo que de verdad está corriendo, no un número fijo.
self.addEventListener('message', e => {
  if (e.data?.type === 'GET_VERSION') e.source?.postMessage({ type:'VERSION', version: CACHE });
});
