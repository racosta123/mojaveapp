// MojaveApp Service Worker — v2
importScripts('https://www.gstatic.com/firebasejs/10.12.0/firebase-app-compat.js');
importScripts('https://www.gstatic.com/firebasejs/10.12.0/firebase-messaging-compat.js');
firebase.initializeApp({
  apiKey: "AIzaSyChuftPnUTXr7KmrVufvMxtmeH14Or0HUU",
  authDomain: "cerradaapp-7179e.firebaseapp.com",
  projectId: "cerradaapp-7179e",
  storageBucket: "cerradaapp-7179e.firebasestorage.app",
  messagingSenderId: "481439052062",
  appId: "1:481439052062:web:c3a0a104bae74763cf590f"
});
const messaging = firebase.messaging();
messaging.onBackgroundMessage((payload) => {
  const { title, body } = payload.notification || {};
  self.registration.showNotification(title || 'MojaveApp', {
    body: body || '',
    icon: '/mojaveapp/icons/icon-192x192.png',
    badge: '/mojaveapp/icons/icon-192x192.png',
    vibrate: [200, 100, 200]
  });
});
self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  e.waitUntil(
    clients.matchAll({type:'window',includeUncontrolled:true}).then(cs => {
      const ex = cs.find(c => c.url.includes('mojaveapp'));
      if (ex) return ex.focus();
      return clients.openWindow('https://racosta123.github.io/mojaveapp/');
    })
  );
});
self.addEventListener('message', (e) => {
  if (!e.data) return;
  if (e.data.type === 'SKIP_WAITING') { self.skipWaiting(); return; }
  if (e.data.type === 'SUSPEND_USER') {
    self.clients.matchAll({type:'window',includeUncontrolled:true}).then(cs => {
      cs.forEach(c => c.postMessage({ type: 'USER_SUSPENDED', house: e.data.house, cerradaCode: e.data.cerradaCode }));
    });
  }
  if (e.data.type === 'REACTIVATE_USER') {
    self.clients.matchAll({type:'window',includeUncontrolled:true}).then(cs => {
      cs.forEach(c => c.postMessage({ type: 'USER_REACTIVATED', house: e.data.house, cerradaCode: e.data.cerradaCode }));
    });
  }
});
const CACHE = 'mojaveapp-v2';
self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(['/mojaveapp/','/mojaveapp/index.html'])));
  self.skipWaiting();
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k=>k!==CACHE).map(k=>caches.delete(k)))));
  self.clients.claim();
});
self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  if (url.pathname.includes('register.html')) { e.respondWith(fetch(e.request)); return; }
  if (url.searchParams.has('reg')) { e.respondWith(fetch(e.request)); return; }
  if (e.request.method !== 'GET') { e.respondWith(fetch(e.request)); return; }
  if (url.hostname !== 'racosta123.github.io') { e.respondWith(fetch(e.request)); return; }
  e.respondWith(fetch(e.request).then(res=>{
    const clone=res.clone();
    caches.open(CACHE).then(c=>c.put(e.request,clone));
    return res;
  }).catch(()=>caches.match(e.request)));
});
