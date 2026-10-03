importScripts('https://www.gstatic.com/firebasejs/10.12.2/firebase-app-compat.js');
importScripts('https://www.gstatic.com/firebasejs/10.12.2/firebase-messaging-compat.js');
// Estos valores son públicos (mismos del config.js).
firebase.initializeApp({
  apiKey: "AIzaSyCW4TIFBY0smiRZiI68IaMR6RUT7Nxsvbk",
  authDomain: "mojaveapp-12b25.firebaseapp.com",
  projectId: "mojaveapp-12b25",
  messagingSenderId: "936025240091",
  appId: "1:936025240091:web:bb750b31b02031a1babebe",
});
const messaging = firebase.messaging();
messaging.onBackgroundMessage(p => {
  self.registration.showNotification(p.notification?.title || 'Cerrada Mojave', {
    body: p.notification?.body || '', icon: 'icons/icon-192.png',
  });
});
