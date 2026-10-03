/* Config pública del cliente (NO lleva secretos del Worker ni de Shelly).
   Valores del proyecto Firebase mojaveapp-12b25. */
const CONFIG = {
  firebase: {
    apiKey: "AIzaSyCW4TIFBY0smiRZiI68IaMR6RUT7Nxsvbk",       // RESTRINGIR a racosta123.github.io en Google Cloud Console
    authDomain: "mojaveapp-12b25.firebaseapp.com",
    projectId: "mojaveapp-12b25",
    storageBucket: "mojaveapp-12b25.firebasestorage.app",
    messagingSenderId: "936025240091",
    appId: "1:936025240091:web:bb750b31b02031a1babebe",
  },
  workerUrl: "https://mojave-proxy.acosta4770.workers.dev",
  appCheckSiteKey: "",  // App Check — pendiente
  vapidKey: "",         // FCM Web Push — pendiente
};
