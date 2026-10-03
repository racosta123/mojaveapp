/* Copia este archivo como config.js y rellena con tus valores reales.
   config.js NO debe contener secretos del Worker ni de la Shelly. */
const CONFIG = {
  firebase: {
    apiKey: "TU_API_KEY",                       // RESTRINGIR a el dominio de GitHub Pages en Google Cloud Console
    authDomain: "TU_PROJECT_ID.firebaseapp.com",
    projectId: "TU_PROJECT_ID",
    storageBucket: "TU_PROJECT_ID.firebasestorage.app",
    messagingSenderId: "TU_SENDER_ID",
    appId: "TU_APP_ID",
  },
  workerUrl: "https://TU-WORKER.TU-SUBDOMINIO.workers.dev",
  appCheckSiteKey: "TU_RECAPTCHA_V3_SITE_KEY",  // App Check
  vapidKey: "TU_VAPID_KEY_WEB_PUSH",            // FCM Web Push (clave PÚBLICA correcta)
};
