/* ===========================================================
   Cerrada Mojave · app.js
   Stack: Firebase (Auth+Firestore+FCM+AppCheck) + Cloudflare Worker + Shelly
   SEGURIDAD: el cliente NUNCA toca la Shelly ni guarda llaves.
   Toda apertura pasa por el Worker, que valida el ID token de Firebase.
   =========================================================== */

/* ---- Init Firebase ---- */
firebase.initializeApp(CONFIG.firebase);
const auth = firebase.auth();
const db   = firebase.firestore();

/* App Check (reCAPTCHA v3) — protege Firestore y el Worker de abuso */
if (CONFIG.appCheckSiteKey) {
  firebase.appCheck().activate(CONFIG.appCheckSiteKey, true);
}

const WORKER = CONFIG.workerUrl;        // ej. https://mojave-proxy.<subdominio>.workers.dev
const DOORS = [
  { id:'visitantes', name:'Visitantes', sub:'Acceso de invitados' },
  { id:'residentes', name:'Residentes', sub:'Entrada principal' },
  { id:'salida',     name:'Salida',     sub:'Barrera de salida' },
  { id:'peatones',   name:'Peatones',   sub:'Puerta peatonal' },
];

let ME = null;          // { uid, nombre, rol, casa, residenteUid? }
let unsubLog = null;
let unsubAlertas = null;   // alertas_bitacora (solo staff)
let unsubAlertasFam = null;   // alertas_familiares (solo staff) — v13
let unsubInvites = null;
let unsubFin = null;
let personasCache = [];       // padrón unificado (FASE 6.5): jefes (casas) + familiares + admins
let miFamiliaCache = [];      // familiares del jefe en sesión (self-service en la pestaña Invitar)

/* FASE 7 — modo de vista del jefe-admin (residente con esAdmin). COSMÉTICO: lo único que
   hace es decidir qué pestañas se pintan. Vive en MEMORIA a propósito (no en localStorage)
   para que quede obvio que no otorga permisos: el Worker revalida esAdmin contra Firestore
   en CADA acción y las reglas hacen lo mismo. Falsificar MODO en F12 pinta la pestaña y
   nada más — toda acción de admin responde 403. */
let MODO = 'residente';                                   // 'residente' | 'admin'
const puedeAdmin  = () => ME?.esAdmin === true;           // jefe con permiso de admin
const enModoStaff = () => ME.rol === 'master' || ME.rol === 'admin' || (puedeAdmin() && MODO === 'admin');

/* ====================== UTILIDADES ====================== */
const $ = s => document.querySelector(s);
const $$ = s => document.querySelectorAll(s);

function toast(msg, kind){
  const t = $('#toast');
  t.textContent = msg;
  t.className = 'toast show' + (kind ? ' '+kind : '');
  clearTimeout(t._t);
  t._t = setTimeout(()=> t.className='toast', 2600);
}

async function authedFetch(path, body){
  const token = await auth.currentUser.getIdToken();
  const headers = { 'Content-Type':'application/json', 'Authorization':'Bearer '+token };
  // App Check token (si está activo) para el Worker
  try {
    if (firebase.appCheck && CONFIG.appCheckSiteKey){
      const ac = await firebase.appCheck().getToken();
      if (ac?.token) headers['X-Firebase-AppCheck'] = ac.token;
    }
  } catch(e){}
  const res = await fetch(WORKER + path, { method:'POST', headers, body: JSON.stringify(body||{}) });
  if (!res.ok){
    let m = 'Error '+res.status, data = null;
    try { data = await res.json(); m = data.error || m; } catch(e){}
    const err = new Error(m); err.status = res.status; err.data = data;
    throw err;
  }
  return res.json().catch(()=> ({}));
}

/* ====================== LOGIN ====================== */
$('#loginBtn').addEventListener('click', doLogin);
$('#password').addEventListener('keydown', e => { if(e.key==='Enter') doLogin(); });

async function doLogin(){
  const btn = $('#loginBtn');
  const email = $('#email').value.trim();
  const pass  = $('#password').value;
  $('#loginErr').textContent = '';
  if (!email || !pass){ $('#loginErr').textContent = 'Completa correo y contraseña'; return; }
  btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>';
  try {
    await auth.signInWithEmailAndPassword(email, pass);
  } catch(e){
    $('#loginErr').textContent = mapAuthError(e.code);
    btn.disabled = false; btn.textContent = 'Entrar';
  }
}

function mapAuthError(code){
  const m = {
    'auth/invalid-credential':'Correo o contraseña incorrectos',
    'auth/invalid-email':'Correo no válido',
    'auth/user-disabled':'Usuario deshabilitado',
    'auth/too-many-requests':'Demasiados intentos. Espera un momento.',
  };
  return m[code] || 'No se pudo iniciar sesión';
}

$('#logoutBtn').addEventListener('click', ()=> auth.signOut());

/* ====================== RECUPERAR CONTRASEÑA ======================
   Mismo mensaje exista o no el correo (no se puede averiguar quién está registrado) y botón
   bloqueado 30 s tras cada envío (sin ráfagas). El envío lo hace Firebase Auth en español. */
const MSG_RECUPERAR = 'Si el correo está registrado, te llegará un enlace. Revisa también Spam.';
const ESPERA_RECUPERAR = 30;
let recuperarBloqueado = false;
function abrirRecuperar(abrir){
  $('#forgotBox').classList.toggle('hidden', !abrir);
  $('#forgotBtn').classList.toggle('hidden', abrir);
  $('#forgotMsg').textContent = '';
  if (abrir) $('#forgotEmail').value = $('#email').value.trim();
}
$('#forgotBtn').addEventListener('click', () => abrirRecuperar(true));
$('#forgotBack').addEventListener('click', () => abrirRecuperar(false));
$('#forgotSend').addEventListener('click', async () => {
  if (recuperarBloqueado) return;
  const email = $('#forgotEmail').value.trim();
  const msg = $('#forgotMsg'), btn = $('#forgotSend');
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)){ msg.textContent = 'Escribe un correo válido.'; return; }
  recuperarBloqueado = true; btn.disabled = true;
  try {
    auth.languageCode = 'es';
    await auth.sendPasswordResetEmail(email);
    msg.textContent = MSG_RECUPERAR;
  } catch(e){
    if (e && e.code === 'auth/too-many-requests') msg.textContent = 'Demasiados intentos. Espera un momento.';
    else if (e && e.code === 'auth/network-request-failed') msg.textContent = 'No se pudo enviar. Revisa tu internet e intenta de nuevo.';
    else msg.textContent = MSG_RECUPERAR;   // correo inexistente u otro error: mismo mensaje
  }
  let s = ESPERA_RECUPERAR;
  btn.textContent = 'Espera ' + s + ' s';
  const t = setInterval(() => {
    s--;
    if (s <= 0){ clearInterval(t); recuperarBloqueado = false; btn.disabled = false; btn.textContent = 'Enviar enlace'; }
    else btn.textContent = 'Espera ' + s + ' s';
  }, 1000);
});

/* ====================== SESIÓN ====================== */
auth.onAuthStateChanged(async user => {
  if (!user){ showLogin(); return; }
  try {
    const snap = await db.collection('usuarios').doc(user.uid).get();
    if (!snap.exists){
      toast('Tu cuenta no tiene perfil asignado', 'bad');
      await auth.signOut(); return;
    }
    ME = { uid:user.uid, ...snap.data() };
    enterApp();
  } catch(e){
    toast('Error cargando perfil', 'bad');
    await auth.signOut();
  }
});

function showLogin(){
  avisoPago = null; pintarAvisoPago();
  document.body.classList.remove('in-app');   // fondo con capa suave en el login
  $('#appView').classList.add('hidden');
  $('#loginView').classList.remove('hidden');
  $('#password').value = '';
  abrirRecuperar(false);
  $('#loginBtn').disabled = false; $('#loginBtn').textContent = 'Entrar';
  if (unsubLog) unsubLog();
  if (unsubAlertas){ unsubAlertas(); unsubAlertas = null; }
  if (unsubAlertasFam){ unsubAlertasFam(); unsubAlertasFam = null; }
  if (unsubInvites) unsubInvites();
  if (unsubFin) unsubFin();
}

function enterApp(){
  document.body.classList.add('in-app');   // fondo con capa ~85% en pantallas internas
  $('#loginView').classList.add('hidden');
  $('#appView').classList.remove('hidden');
  $('#avatar').textContent = (ME.nombre||'?').trim()[0].toUpperCase();
  $('#userName').textContent = ME.nombre || '—';
  $('#userRole').textContent = roleLabel(ME.rol) + (ME.casa ? ' · '+ME.casa : '');
  MODO = 'residente';        // el jefe-admin siempre entra en su modo primario
  renderModoBtn();
  buildTabs();
  renderDoors();
  watchLog();
  watchFinanzas();
  if (ME.rol==='residente' || ME.rol==='esclavo') watchInvites();
  setupMiFamilia();
  registerPush();
  refrescarAvisoPago(true);
  cargarLogoMojave();   // dispara la precarga del logo del recibo; no bloquea nada
}

/* Logo de la cerrada (assets/logo-mojave.jpg, 662x300) para el banner del recibo PDF.
   Se precarga en cuanto arranca la app y de nuevo al abrir un recibo (por si el primer intento
   falló, p.ej. sin conexión antes de que el SW lo precacheara). construirReciboPDF() es
   síncrona a propósito (ver su comentario) así que esto nunca puede bloquearla: si no está
   lista a tiempo, el recibo se genera igual, solo que sin el banner. */
let logoMojaveDataUrl = null;
async function cargarLogoMojave(){
  if (logoMojaveDataUrl) return logoMojaveDataUrl;
  try {
    const resp = await fetch('assets/logo-mojave.jpg');
    if (!resp.ok) return null;                              // sin logo: el recibo se genera sin banner
    const blob = await resp.blob();
    logoMojaveDataUrl = await new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = reject;
      reader.readAsDataURL(blob);
    });
  } catch(e){ console.error('cargarLogoMojave', e); }
  return logoMojaveDataUrl;
}

function roleLabel(r){
  return { master:'Master', admin:'Administrador', residente:'Residente', esclavo:'Invitado' }[r] || r;
}

/* ====================== MODO (FASE 7) ====================== */
/* El botón solo existe para el jefe-admin: master y admin puro no tienen lado residente
   (sin casa, sin cuota, sin familiares), así que su "modo residente" sería una pantalla
   vacía. Ellos siguen viendo su staff de siempre, sin botón. */
function renderModoBtn(){
  const b = $('#modoBtn');
  b.classList.toggle('hidden', !puedeAdmin());
  if (!puedeAdmin()) return;
  const aAdmin = MODO === 'residente';        // a dónde lleva el botón
  b.classList.toggle('on', MODO === 'admin');
  b.innerHTML = aAdmin
    ? `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg><span>Modo administrador</span>`
    : `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 10.5L12 3l9 7.5"/><path d="M5 9.5V21h14V9.5"/></svg><span>Modo residente</span>`;
}
$('#modoBtn').addEventListener('click', () => {
  if (!puedeAdmin()) return;                  // sin permiso el botón ni existe
  MODO = MODO === 'admin' ? 'residente' : 'admin';
  renderModoBtn();
  buildTabs();                                // repinta pestañas...
  watchLog();                                 // ...y las vistas que dependen del modo
  watchFinanzas();
  toast(MODO === 'admin' ? 'Modo administrador' : 'Modo residente', 'ok');
});

/* ====================== TABS ====================== */
function buildTabs(){
  const isStaff = enModoStaff();
  const tabs = [
    { id:'doors',   label:'Puertas', icon:'M4 10h16v11H4z M8 10V7a4 4 0 0 1 8 0v3' },
  ];
  // Invitar es del lado residente: el jefe-admin en modo admin no la ve.
  if (!isStaff && (ME.rol==='residente' || ME.rol==='esclavo'))
    tabs.push({ id:'invites', label:'Invitar', icon:'M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2 M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8 M19 8v6 M22 11h-6' });
  tabs.push({ id:'log', label: isStaff?'Bitácora':'Historial', icon:'M9 11l3 3L22 4 M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11' });
  tabs.push({ id:'finanzas', label:'Finanzas', icon:'M12 1v22 M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6' });
  tabs.push({ id:'votaciones', label:'Votación', icon:'M5 8h14v12H5z M9 12l2 2 4-4 M8 8V6a4 4 0 0 1 8 0v2' });
  if (isStaff)
    tabs.push({ id:'admin', label:'Gestión', icon:'M12 2a3 3 0 0 1 3 3v1m-6 0V5a3 3 0 0 1 3-3 M4 9h16v11H4z' });

  const bar = $('#tabbar'); bar.innerHTML = '';
  tabs.forEach((t,i) => {
    const b = document.createElement('button');
    b.className = 'tab' + (i===0?' active':'');
    b.dataset.tab = t.id;
    b.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="${t.icon}"/></svg><span>${t.label}</span>`;
    b.onclick = ()=> switchTab(t.id, b);
    bar.appendChild(b);
  });
  // Al reconstruir por un cambio de modo, el pane abierto puede ya no tener pestaña
  // (p.ej. Invitar al pasar a admin): vuelve siempre a la primera para no dejarlo huérfano.
  $$('.tabpane').forEach(p => p.classList.add('hidden'));
  $('#tab-'+tabs[0].id).classList.remove('hidden');
  if (isStaff) loadPersonas();
  // Configuración de cobranza (cuota/fecha) y suspensión automática: cualquier staff
  // (master/admin/jefe-admin) — el Worker revalida esStaff() en ambos endpoints.
  // El campo de link de pago dentro de cobranzaConfigSection sigue siendo SOLO master
  // (ver #ccLinkField más abajo): el Worker rechaza linkPago si quien llama no es master.
  $('#cobranzaConfigSection').classList.toggle('hidden', !isStaff);
  $('#susAutoSection').classList.toggle('hidden', !isStaff);
  $('#recSimularBtn').classList.toggle('hidden', !(ME.rol === 'master' || ME.rol === 'admin'));   // cosmético; el Worker revalida
  $('#ccLinkField').classList.toggle('hidden', ME.rol !== 'master');
  if (isStaff) cargarConfigCobranza();
}

/* Jefe de familia = residente sin jefeId (es la CASA). Los familiares (residente CON jefeId)
   y los esclavos no invitan familia. Cuentas viejas sin jefeId cuentan como jefe. */
function soyJefe(){ return ME.rol === 'residente' && !ME.jefeId; }

function switchTab(id, btn){
  $$('.tabpane').forEach(p => p.classList.add('hidden'));
  $('#tab-'+id).classList.remove('hidden');
  $$('.tab').forEach(t => t.classList.remove('active'));
  btn.classList.add('active');
  if (id !== 'votaciones' && votUnsub){ votUnsub(); votUnsub = null; }
  if (id === 'finanzas') resizeFinCharts();
  if (id === 'votaciones') loadVotaciones();
  if (id === 'admin') refrescarGestion();   // padrón al día cada vez que se abre Gestión
}

/* ====================== PUERTAS ====================== */
/* Suspendido por mora (propio o del hogar, vía cascada de /personas/suspender que sincroniza
   usuarios/{uid}.suspendido): solo cosmético — el Worker revalida y es quien realmente
   bloquea/permite cada puerta (ver abrir() en worker.js). */
function renderDoors(){
  const grid = $('#doorsGrid'); grid.innerHTML = '';
  const susp = ME.suspendido === true;
  if (susp){
    grid.innerHTML = '<div class="empty" style="grid-column:1/-1;padding:14px 10px">'
      + 'Suspendido por mora — solo puedes usar Peatones y Salida.</div>';
  }
  // El invitado (visitante con QR) no usa esta app; los esclavos sí abren las 4 (si no hay suspensión).
  DOORS.forEach(d => {
    const bloqueada = susp && d.id !== 'peatones' && d.id !== 'salida';
    const el = document.createElement('div');
    el.className = 'door' + (bloqueada ? ' door-disabled' : '');
    el.innerHTML = `
      <div class="pulse"></div>
      <div class="ic"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="9" width="16" height="12" rx="2"/><path d="M8 9V6a4 4 0 0 1 8 0v3"/><circle cx="12" cy="15" r="1.4"/></svg></div>
      <div class="dn">${d.name}</div>
      <div class="ds">${bloqueada ? 'No disponible (suspendido)' : d.sub}</div>`;
    if (bloqueada){
      el.style.opacity = '.45';
      el.style.pointerEvents = 'none';
      el.setAttribute('aria-disabled', 'true');
    } else {
      el.onclick = ()=> openDoor(d, el);
      // Solo visual: bloquea el menú contextual que un mantener-presionado dispara en
      // algunos navegadores/Android. El toque sigue abriendo de inmediato (sin retardo,
      // sin mantener presionado) — ver openDoor arriba.
      el.addEventListener('contextmenu', e => e.preventDefault());
    }
    grid.appendChild(el);
  });
}

/* ====================== AVISO DE PAGO (días 1 al 4) ======================
   El Worker decide (/cobranza/aviso-pago, solo lectura, solo la casa del propio usuario); aquí
   solo se pinta. Se consulta al abrir la app, al volver a primer plano y tras ver el estado de
   cuenta — NUNCA al abrir una puerta (el toast usa lo ya cargado). Si la consulta falla, no hay
   aviso y la app sigue normal. */
let avisoPago = null, avisoPagoT = 0, avisoPagoBusy = false, avisoPagoLink;
function textoAvisoPago(){
  return `Tienes pendiente tu cuota de ${avisoPago.mes}. Paga antes del día 5 para evitar la suspensión del acceso vehicular.`;
}
function pintarAvisoPago(){
  const el = $('#avisoPagoBanner'); if (!el) return;
  if (!avisoPago || !avisoPago.mostrar){ el.classList.add('hidden'); el.innerHTML = ''; return; }
  const link = (avisoPagoLink || '').trim();
  el.innerHTML = `<b>⚠️ ${esc(textoAvisoPago())}</b>`
    + (link ? `<a class="btn-primary" style="display:block;text-align:center;margin-top:10px;text-decoration:none" href="${esc(link)}" target="_blank" rel="noopener">Pagar cuota</a>` : '');
  el.classList.remove('hidden');
}
async function refrescarAvisoPago(forzar){
  if (!ME || ME.rol !== 'residente' || !ME.casa) return;   // staff sin casa: no aplica
  if (avisoPagoBusy || (!forzar && Date.now() - avisoPagoT < 20000)) return;
  avisoPagoBusy = true;
  try {
    const r = await authedFetch('/cobranza/aviso-pago', {});
    avisoPago = r && r.mostrar ? r : null;
    if (avisoPago && avisoPagoLink === undefined){
      try { avisoPagoLink = (await authedFetch('/config/cobranza', {})).linkPago || ''; } catch(e){ /* sin botón, el aviso igual sale */ }
    }
  } catch(e){
    avisoPago = null;   // consulta caída: sin aviso, todo lo demás normal
  } finally {
    avisoPagoT = Date.now(); avisoPagoBusy = false; pintarAvisoPago();
  }
}
function avisoPagoToast(){
  if (!avisoPago || !avisoPago.mostrar) return;
  setTimeout(() => { if (avisoPago && avisoPago.mostrar) toast(`Tienes pendiente tu cuota de ${avisoPago.mes}. Paga antes del día 5 para evitar la suspensión.`); }, 1600);
}
document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') refrescarAvisoPago(false); });
window.addEventListener('focus', () => refrescarAvisoPago(false));

let opening = false;
async function openDoor(door, el){
  if (opening) return;
  opening = true; el.classList.add('opening');
  try {
    await authedFetch('/abrir', { puerta: door.id });
    toast(door.name + ' abriéndose', 'ok');
    avisoPagoToast();   // DESPUÉS de la respuesta de /abrir; solo usa el estado ya cargado (sin consulta)
  } catch(e){
    toast(e.message || 'No se pudo abrir', 'bad');
  } finally {
    setTimeout(()=>{ el.classList.remove('opening'); opening=false; }, 1400);
  }
}

/* ====================== BITÁCORA / HISTORIAL ====================== */
/* Bitácora. Residente: su hogar + todas las visitas de su casa (jefe y familiares, por casaId);
   esclavo: el hogar de su titular (lo imponen las reglas; aquí solo se consulta eso). Staff: todo, más las ALERTAS ("⚠️ Posible residente suspendido") que viven aparte en
   alertas_bitacora — colección que solo el staff puede leer — y se cruzan por id de registro. */
let logDocsCache = null;                              // [{id, data}] de aperturas, más reciente primero
let alertasBitacora = { porId: new Map(), lista: [] };
let logSoloAlertas = false;
/* v13 — alertas_familiares (solo staff): personaId → alerta. Solo cuentan las ACTIVAS: al
   marcar "Revisado, es correcto" el familiar deja de salir en rojo en Gestión y en la bitácora. */
let alertasFamiliares = new Map();
function alertaFamActiva(personaId){
  const a = personaId && alertasFamiliares.get(personaId);
  return a && a.estado === 'activa' ? a : null;
}
/* La alerta a pintar en un registro de la bitácora (o null). Las de "otra casa" solo si la
   alerta del familiar sigue activa; y si por algo faltara el doc de alertas_bitacora de una
   apertura, se marca igual por el personaId del familiar. */
function alertaDeRegistro(id, a){
  let al = alertasBitacora.porId.get(id) || null;
  if (al && al.tipoAlerta === 'posible-otra-casa' && !alertaFamActiva(al.personaId)) al = null;
  if (!al && a && a.tipo === 'app' && alertaFamActiva(a.personaId)){
    al = { tipoAlerta: 'posible-otra-casa', coincideCon: alertaFamActiva(a.personaId).coincideCon };
  }
  return al;
}
/* Casa = persona del JEFE (jefe: su personaId; familiar: su jefeId). Misma cuenta que miCasaId()
   en las reglas. '' si no es residente (esclavo/admin/master). */
function miCasaId(){
  if (ME.rol !== 'residente') return '';
  return ME.jefeId || ME.personaId || '';
}
function watchLog(){
  if (unsubLog) unsubLog();
  if (unsubAlertas){ unsubAlertas(); unsubAlertas = null; }
  if (unsubAlertasFam){ unsubAlertasFam(); unsubAlertasFam = null; }
  alertasBitacora = { porId: new Map(), lista: [] };
  alertasFamiliares = new Map();
  logDocsCache = null;
  const isStaff = enModoStaff();
  const qs = [];
  if (isStaff){
    qs.push(db.collection('aperturas').orderBy('ts','desc').limit(60));
  } else {
    // Su hogar (lo suyo + sus esclavos/visitantes; el esclavo, lo de su titular) y, si es
    // residente, TODAS las visitas de su casa (jefe y familiares). Las reglas no dejan ver otra casa.
    const scope = ME.rol==='residente' ? ME.uid : (ME.residenteUid || ME.uid);
    qs.push(db.collection('aperturas').where('hogar','==',scope).orderBy('ts','desc').limit(60));
    const casaId = miCasaId();
    if (casaId) qs.push(db.collection('aperturas').where('casaId','==',casaId).orderBy('ts','desc').limit(60));
    logSoloAlertas = false;
  }
  $('#logTitle').textContent = isStaff ? 'Bitácora general' : 'Historial';
  $('#logAlertasBtn').classList.toggle('hidden', !isStaff);
  $('#logAlertasBtn').classList.toggle('sel', logSoloAlertas);
  // Une los resultados por id (una visita propia sale en las dos consultas) y ordena por hora.
  const partes = qs.map(() => null);
  const unir = () => {
    const porId = new Map();
    partes.forEach(p => (p || []).forEach(d => porId.set(d.id, d)));
    const ms = d => { const t = d.data.ts; return t ? (t.toMillis ? t.toMillis() : +new Date(t)) : 0; };
    logDocsCache = [...porId.values()].sort((a, b) => ms(b) - ms(a)).slice(0, 60);
    renderLog();
  };
  const unsubs = qs.map((q, i) => q.onSnapshot(snap => {
    partes[i] = snap.docs.map(d => ({ id: d.id, data: d.data() }));
    unir();
  }, err => {
    console.error(err);
    if (i === 0) $('#logList').innerHTML = '<div class="empty">Sin acceso al historial</div>';
  }));
  unsubLog = () => unsubs.forEach(u => u());
  if (isStaff){
    unsubAlertas = db.collection('alertas_bitacora').orderBy('ts','desc').limit(100)
      .onSnapshot(snap => {
        const lista = []; const porId = new Map();
        snap.forEach(d => { const a = { id: d.id, ...d.data() }; lista.push(a); porId.set(d.id, a); });
        alertasBitacora = { porId, lista };
        renderLog();
      }, err => console.error('alertas_bitacora', err));
    // Colección chica (una por familiar marcado): se escucha completa, sin índice.
    unsubAlertasFam = db.collection('alertas_familiares').onSnapshot(snap => {
      const m = new Map(); snap.forEach(d => m.set(d.id, { id: d.id, ...d.data() }));
      alertasFamiliares = m;
      renderLog();
      if (personasCache.length) renderPersonas();
    }, err => console.error('alertas_familiares', err));
  }
}
$('#logAlertasBtn')?.addEventListener('click', () => {
  logSoloAlertas = !logSoloAlertas;
  $('#logAlertasBtn').classList.toggle('sel', logSoloAlertas);
  renderLog();
});

const SVG_ENGRANE = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>';
const SVG_CANDADO = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="9" width="16" height="12" rx="2"/><path d="M8 9V6a4 4 0 0 1 8 0v3"/></svg>';

/* Una fila de apertura/visita. `alerta` (solo staff) = doc de alertas_bitacora de ese registro. */
function filaBitacora(a, alerta){
  const row = document.createElement('div');
  row.className = 'row' + (alerta ? ' alerta' : '');
  if (a.tipo === 'gestion'){
    // Acción administrativa (FASE 5), no una apertura de puerta: ícono de engrane,
    // el texto ya describe la acción, sin etiqueta Entrada/Salida.
    row.innerHTML = `
      <div class="ri">${SVG_ENGRANE}</div>
      <div class="rt"><div class="a">${esc(a.nombre || 'Gestión')}</div><div class="b">Gestión · ${fmtTime(a.ts)}</div></div>
      <span class="tag">Gestión</span>`;
    return row;
  }
  // Sentido: las visitas guardan tipo 'entrada'/'salida' (el lector peatonal de salida usa la
  // puerta 'peatones'); las aperturas desde la app, la puerta 'salida'.
  const sentido = (a.tipo === 'salida' || a.puerta === 'salida') ? 'out' : 'in';
  const metodo = a.metodo || ((a.uid === 'qr' || a.uid === 'pin') ? a.uid : '');
  const esVisita = !!metodo;
  const titulo = esVisita ? (a.visitante || a.nombre || 'Visita') : (a.nombre || 'Usuario');
  // Si el registro trae la nota "— revisar" (entrada/salida sin su par), se conserva abajo.
  const nota = (esVisita && a.nombre && a.visitante && a.nombre !== a.visitante) ? a.nombre : '';
  // Visita: "Invitado por …". Apertura desde la app de un FAMILIAR (v13): "Familiar de <Jefe> ·
  // <Casa> · dado de alta por <quien>" — datos que el Worker toma del padrón al registrarla.
  const invito = esVisita
    ? ((a.invitadoPor || a.casa)
      ? `<div class="mov-liga">Invitado por ${esc(a.invitadoPor || '—')}${a.casa ? ' · ' + esc(a.casa) : ''}</div>` : '')
    : (a.familiarDe
      ? `<div class="mov-liga">Familiar de ${esc(a.familiarDe)}${a.casa ? ' · ' + esc(a.casa) : ''}`
        + `${a.dadoDeAltaNombre ? ' · dado de alta por ' + esc(a.dadoDeAltaNombre) : ''}</div>` : '');
  const alertaHtml = alerta
    ? `<div class="mov-liga bad">⚠️ ${alerta.tipoAlerta === 'posible-otra-casa' ? 'Posible residente de otra casa' : 'Posible residente suspendido'}`
      + ` · coincide con ${esc(alerta.coincideCon || '')}</div>` : '';
  row.innerHTML = `
    <div class="ri">${SVG_CANDADO}</div>
    <div class="rt"><div class="a">${esc(titulo)}</div>`
    + `<div class="b">${esc(puertaName(a.puerta))} · ${fmtTime(a.ts)}${metodo ? ' · ' + metodo.toUpperCase() : ''}</div>`
    + `${invito}${nota ? `<div class="mov-liga">${esc(nota)}</div>` : ''}${alertaHtml}</div>
    <span class="tag ${sentido}">${sentido==='out'?'Salida':'Entrada'}</span>`;
  return row;
}

function renderLog(){
  const list = $('#logList');
  const soloAlertas = logSoloAlertas && enModoStaff();
  if (soloAlertas){
    // Se pinta desde alertas_bitacora (trae visitante, puerta, hora, quién invitó y casa):
    // así aparecen también alertas más viejas que las 60 aperturas recientes.
    // Las de "otra casa" cuyo familiar ya se marcó "Revisado, es correcto" no salen.
    const al = alertasBitacora.lista.filter(a => a.tipoAlerta !== 'posible-otra-casa' || alertaFamActiva(a.personaId));
    if (!al.length){ list.innerHTML = '<div class="empty">Sin alertas</div>'; return; }
    list.innerHTML = '';
    al.forEach(a => list.appendChild(filaBitacora(a, a)));
    return;
  }
  const docs = logDocsCache;
  if (!docs || !docs.length){ list.innerHTML = '<div class="empty">Sin movimientos</div>'; return; }
  list.innerHTML = '';
  // alertaDeRegistro solo devuelve algo para staff: a un residente nunca le llegan alertas.
  docs.forEach(d => list.appendChild(filaBitacora(d.data, enModoStaff() ? alertaDeRegistro(d.id, d.data) : null)));
}

function puertaName(id){ return (DOORS.find(d=>d.id===id)||{}).name || id; }
function fmtTime(ts){
  if (!ts) return '';
  const d = ts.toDate ? ts.toDate() : new Date(ts);
  return d.toLocaleString('es-MX', { day:'2-digit', month:'short', hour:'2-digit', minute:'2-digit' });
}
function esc(s){ return (s||'').replace(/[<>&]/g, c=>({'<':'&lt;','>':'&gt;','&':'&amp;'}[c])); }

/* ====================== INVITACIONES (QR visitante) ====================== */
let inviteDur = 4, inviteUses = 1;

$('#newInviteBtn').addEventListener('click', openInviteSheet);
$('#durSeg').addEventListener('click', e => segPick(e, '#durSeg', v => inviteDur = +v, 'h'));
$('#usesSeg').addEventListener('click', e => segPick(e, '#usesSeg', v => inviteUses = +v, 'u'));
$('#genInviteBtn').addEventListener('click', generateInvite);
$('#inviteOverlay').addEventListener('click', e => { if(e.target.id==='inviteOverlay') closeSheet('#inviteOverlay'); });

function segPick(e, sel, set, attr){
  const b = e.target.closest('button'); if(!b) return;
  $$(sel+' button').forEach(x=>x.classList.remove('sel'));
  b.classList.add('sel'); set(b.dataset[attr]);
}

function openInviteSheet(){
  $('#inviteForm').classList.remove('hidden');
  $('#inviteResult').classList.add('hidden');
  $('#visitorName').value = '';
  openSheet('#inviteOverlay');
}

async function generateInvite(){
  const name = $('#visitorName').value.trim();
  if (!name){ toast('Escribe el nombre del visitante', 'bad'); return; }
  const btn = $('#genInviteBtn');
  btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>';
  try {
    // El Worker crea la invitación: genera token único, la guarda en Firestore,
    // y la PRE-SINCRONIZA al lector QR físico (resiliencia offline).
    const r = await authedFetch('/invitacion/crear', {
      visitante: name,
      horas: inviteDur,
      usos: inviteUses,          // 0 = ilimitado dentro de la vigencia
      hogar: ME.rol==='residente' ? ME.uid : (ME.residenteUid || ME.uid),
    });
    // r.payload = token opaco (cadena aleatoria sin datos) que va dentro del QR; los datos reales viven en Firestore
    const dataUrl = await QRCode.toDataURL(r.payload, { margin:1, width:460, errorCorrectionLevel:'M' });
    $('#qrImg').src = dataUrl;
    $('#qrMeta').textContent = `${name} · válido ${inviteDur} h`;
    $('#qrCount').textContent = inviteUses===0 ? 'Usos ilimitados durante la vigencia' : `${inviteUses} ${inviteUses===1?'uso':'usos'} · solo puerta de visitantes`;
    $('#inviteForm').classList.add('hidden');
    $('#inviteResult').classList.remove('hidden');
    // Captura los parámetros de ESTA invitación (las globales pueden cambiar si se reabre la hoja).
    const dur = inviteDur, uses = inviteUses, payload = r.payload, expira = r.expira, pin = r.pin;
    $('#shareQrBtn').onclick = ()=> shareQR({ payload, name, dur, uses, expira, pin });
  } catch(e){
    toast(e.message || 'No se pudo generar', 'bad');
  } finally {
    btn.disabled = false; btn.textContent = 'Generar código QR';
  }
}

/* ---- Compartir invitación de visita: mensaje + tarjeta-imagen (QR) ---- */

function fmtInviteDur(h){
  h = +h || 1;
  if (h === 24) return '24 horas';
  return h + (h === 1 ? ' hora' : ' horas');
}
function fmtInviteUses(u){
  u = +u || 0;
  return u === 0 ? 'usos ilimitados' : (u + (u === 1 ? ' uso' : ' usos'));
}
/* Vigencia como hora local exacta: "Vence hoy 8:30 PM" / "Vence mañana 8:30 AM".
   Si no llega `expira` (p. ej. Worker aún sin desplegar), cae a la vigencia relativa. */
function fmtInviteVigencia(expira, dur){
  const d = expira ? new Date(expira) : null;
  if (!d || isNaN(d.getTime())) return `Válido por ${fmtInviteDur(dur)}`;
  const hora = d.toLocaleTimeString('en-US', { hour:'numeric', minute:'2-digit', hour12:true }); // "8:30 PM"
  const startOf = x => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();
  const days = Math.round((startOf(d) - startOf(new Date())) / 86400000);
  const cuando = days <= 0 ? 'hoy' : (days === 1 ? 'mañana'
    : 'el ' + d.toLocaleDateString('es-MX', { day:'numeric', month:'long' }));
  return `Vence ${cuando} ${hora}`;
}
/* Texto que acompaña al QR en Web Share / WhatsApp. `pin` es opcional (compatibilidad si
   alguna vez falta en la respuesta) — código de respaldo por si el QR no se puede escanear. */
/* Link de ruta al portón de visitas (Google Maps). Vacío = no se incluye la línea "Cómo llegar" en el mensaje. */
const LINK_COMO_LLEGAR = 'https://www.google.com/maps?q=29.047751241293177,-111.00625485272762';
function buildInviteText(name, dur, uses, expira, pin){
  return `¡Hola, ${name}! 👋\n`
    + `Tienes acceso a *Cerrada Mojave*.\n`
    + `🕐 ${fmtInviteVigencia(expira, dur)} · ${fmtInviteUses(uses)}\n`
    + (LINK_COMO_LLEGAR ? `📍 Cómo llegar: ${LINK_COMO_LLEGAR}\n\n` : '\n')
    + `Muestra el código QR adjunto al llegar a la caseta de acceso.`
    + (pin ? `\n🔢 Código de respaldo (si el QR no funciona): ${pin}` : '');
}

/* Carga una imagen y resuelve cuando está lista (para componer en canvas). */
function loadImage(src){
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => resolve(img);
    img.onerror = reject;
    img.src = src;
  });
}
/* Rectángulo redondeado (no todos los navegadores traen ctx.roundRect). */
function roundRectPath(ctx, x, y, w, h, r){
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.arcTo(x + w, y,     x + w, y + h, r);
  ctx.arcTo(x + w, y + h, x,     y + h, r);
  ctx.arcTo(x,     y + h, x,     y,     r);
  ctx.arcTo(x,     y,     x + w, y,     r);
  ctx.closePath();
}
/* Recorta un texto con "…" si excede maxW con la fuente activa (nombres largos). */
function fitText(ctx, text, maxW){
  if (ctx.measureText(text).width <= maxW) return text;
  let t = text;
  while (t.length > 1 && ctx.measureText(t + '…').width > maxW) t = t.slice(0, -1);
  return t + '…';
}

/* Compone una tarjeta vertical (foto + capa oscura + recuadro BLANCO con el QR + datos)
   con <canvas> nativo y la devuelve como File JPG. Sin librerías nuevas. */
async function buildInviteCard({ payload, name, dur, uses, expira, pin }){
  const W = 1080, H = 1460;   // +110 vs antes: espacio nuevo para el PIN de respaldo, abajo
  const cv = document.createElement('canvas');
  cv.width = W; cv.height = H;
  const ctx = cv.getContext('2d');
  const cx = W / 2;

  // Fondo: foto existente escalada "cover". Si falla, color sólido.
  try {
    const bg = await loadImage('assets/fondo-mojave-mobile.webp');
    const s = Math.max(W / bg.width, H / bg.height);
    const bw = bg.width * s, bh = bg.height * s;
    ctx.drawImage(bg, (W - bw) / 2, (H - bh) / 2, bw, bh);
  } catch(e){
    ctx.fillStyle = '#0e1b2a'; ctx.fillRect(0, 0, W, H);
  }
  // Capa oscura para legibilidad del texto sobre la foto.
  const g = ctx.createLinearGradient(0, 0, 0, H);
  g.addColorStop(0,   'rgba(8,15,26,0.74)');
  g.addColorStop(0.5, 'rgba(8,15,26,0.58)');
  g.addColorStop(1,   'rgba(8,15,26,0.84)');
  ctx.fillStyle = g; ctx.fillRect(0, 0, W, H);

  // Encabezado.
  ctx.textAlign = 'center';
  ctx.fillStyle = 'rgba(255,255,255,0.82)';
  ctx.font = '600 30px system-ui, -apple-system, "Segoe UI", Roboto, sans-serif';
  ctx.fillText('A C C E S O   D E   V I S I T A', cx, 150);
  ctx.fillStyle = '#ffffff';
  ctx.font = '700 58px system-ui, -apple-system, "Segoe UI", Roboto, sans-serif';
  ctx.fillText('Cerrada Mojave', cx, 226);

  // Recuadro BLANCO sólido con el QR (obligatorio: un QR sobre fondo oscuro no escanea).
  const boxW = 720, boxH = 720, boxX = (W - boxW) / 2, boxY = 300;
  ctx.fillStyle = '#ffffff';
  roundRectPath(ctx, boxX, boxY, boxW, boxH, 40); ctx.fill();
  const pad = 70, qs = boxW - pad * 2;
  // QR generado al tamaño exacto del recuadro → nítido y escaneable.
  const qrUrl = await QRCode.toDataURL(payload, { margin: 1, width: qs, errorCorrectionLevel: 'M' });
  const qr = await loadImage(qrUrl);
  ctx.imageSmoothingEnabled = false;
  ctx.drawImage(qr, boxX + pad, boxY + pad, qs, qs);
  ctx.imageSmoothingEnabled = true;

  // Datos del visitante.
  ctx.fillStyle = '#ffffff';
  ctx.font = '700 52px system-ui, -apple-system, "Segoe UI", Roboto, sans-serif';
  ctx.fillText(fitText(ctx, name, W - 160), cx, 1110);
  ctx.fillStyle = 'rgba(255,255,255,0.90)';
  ctx.font = '400 36px system-ui, -apple-system, "Segoe UI", Roboto, sans-serif';
  ctx.fillText(`${fmtInviteVigencia(expira, dur)} · ${fmtInviteUses(uses)}`, cx, 1168);
  ctx.fillStyle = 'rgba(255,255,255,0.72)';
  ctx.font = '400 30px system-ui, -apple-system, "Segoe UI", Roboto, sans-serif';
  ctx.fillText('Muestra este código en la caseta de acceso', cx, 1216);

  // Código de respaldo (PIN): grande y legible, por si el QR no se puede escanear.
  if (pin) {
    ctx.fillStyle = 'rgba(255,255,255,0.72)';
    ctx.font = '600 28px system-ui, -apple-system, "Segoe UI", Roboto, sans-serif';
    ctx.fillText('CÓDIGO DE RESPALDO (SI EL QR NO FUNCIONA)', cx, 1268);
    ctx.fillStyle = '#ffffff';
    ctx.font = '700 66px system-ui, -apple-system, "Segoe UI", Roboto, sans-serif';
    ctx.fillText(pin, cx, 1340);
  }

  // Pie discreto.
  ctx.fillStyle = 'rgba(255,255,255,0.55)';
  ctx.font = '400 26px system-ui, -apple-system, "Segoe UI", Roboto, sans-serif';
  ctx.fillText('Sistema por Diagonal Catorce', cx, 1410);

  const blob = await new Promise(res => cv.toBlob(res, 'image/jpeg', 0.92));
  return new File([blob], 'acceso-mojave.jpg', { type: 'image/jpeg' });
}

/* Comparte la tarjeta + el texto. Web Share con archivos cuando el dispositivo lo soporta;
   si no, descarga la tarjeta y copia el mensaje al portapapeles para pegarlo en WhatsApp. */
async function shareQR({ payload, name, dur, uses, expira, pin }){
  const texto = buildInviteText(name, dur, uses, expira, pin);
  let file = null;
  try { file = await buildInviteCard({ payload, name, dur, uses, expira, pin }); }
  catch(e){ console.error('buildInviteCard', e); }

  // Camino principal: Web Share nivel 2 (imagen + texto en una sola hoja de compartir).
  if (file && navigator.canShare && navigator.canShare({ files:[file] })){
    try {
      await navigator.share({ files:[file], title:'Acceso Cerrada Mojave', text: texto });
      return;
    } catch(e){
      if (e && e.name === 'AbortError') return;   // el usuario canceló: no es error
      // cualquier otro error → plan B
    }
  }

  // Plan B (sin soporte de compartir archivos): descarga la tarjeta + copia el mensaje.
  let img = file;
  if (!img){   // si la tarjeta falló, al menos el QR crudo
    try {
      const qrUrl = await QRCode.toDataURL(payload, { margin: 1, width: 560, errorCorrectionLevel: 'M' });
      const b = await (await fetch(qrUrl)).blob();
      img = new File([b], 'acceso-mojave.png', { type: 'image/png' });
    } catch(e){ toast('No se pudo generar la imagen', 'bad'); return; }
  }
  const objUrl = URL.createObjectURL(img);
  const a = document.createElement('a'); a.href = objUrl; a.download = img.name; a.click();
  setTimeout(() => URL.revokeObjectURL(objUrl), 5000);
  try {
    await navigator.clipboard.writeText(texto);
    toast('Tarjeta descargada y mensaje copiado — pégalo en WhatsApp', 'ok');
  } catch(e){
    toast('Tarjeta descargada — compártela por WhatsApp', 'ok');
  }
}

function watchInvites(){
  if (unsubInvites) unsubInvites();
  const hogar = ME.rol==='residente' ? ME.uid : (ME.residenteUid || ME.uid);
  unsubInvites = db.collection('invitaciones')
    .where('hogar','==',hogar).where('activa','==',true)
    .orderBy('expira','desc').limit(20)
    .onSnapshot(snap => {
      const list = $('#invitesList');
      if (snap.empty){ list.innerHTML = '<div class="empty">Sin invitaciones activas</div>'; return; }
      list.innerHTML = '';
      snap.forEach(doc => {
        const v = doc.data();
        const row = document.createElement('div');
        row.className = 'row';
        row.innerHTML = `
          <div class="ri"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><path d="M14 14h3v3h-3z M21 14v.01 M21 21v.01 M17 21h.01"/></svg></div>
          <div class="rt"><div class="a">${esc(v.visitante)}</div><div class="b">Expira ${fmtTime(v.expira)} · ${v.usosRestantes==null?'∞':v.usosRestantes} restantes</div></div>
          <span class="tag">Activa</span>`;
        list.appendChild(row);
      });
    }, err => console.error(err));
}

/* ====================== PERSONAS (FASE 6.5) ======================
   Padrón unificado leído del Worker (/personas/listar, solo staff). Jefe = residente sin
   jefeId (= la CASA, fuente de verdad del domicilio en Finanzas). Familiar = residente con
   jefeId (hereda el domicilio del jefe). Admin/master = sin domicilio. usuarios/{uid} es solo
   un índice que sincroniza el Worker; aquí NO se lee/escribe esa colección directo. */
const normDom = s => String(s||'').trim().replace(/\s+/g,' ').toUpperCase();
const esBajaP = p => p.estado === 'baja';
function esJefeP(p){ return p.rol === 'residente' && !p.jefeId && !esBajaP(p); }
/* jefes() = TODAS las casas (activas y suspendidas) — también el dropdown de registro de
   ingreso: se puede cobrar a una casa suspendida. El termómetro y las listas de cobranza
   usan el conteo del Worker (todas las casas). */
function jefes(){ return personasCache.filter(esJefeP); }

let personasError = '';   // texto del último fallo de /personas/listar ('' = sin error)
async function cargarPersonas(){
  try {
    const r = await authedFetch('/personas/listar', {});
    personasCache = Array.isArray(r.personas) ? r.personas : [];
    personasError = '';
  } catch(e){
    // No se vacía la lista en silencio: se conserva lo último bueno y se avisa con Reintentar.
    console.error('cargarPersonas', e);
    personasError = (e && e.message) || 'No se pudo cargar';
  }
}
/* recarga el padrón y refresca TODO lo que depende de él: la lista y, si Finanzas ya se
   pintó, la cobranza (termómetro + listas pagaron/sin pago, conteo del Worker). */
async function refrescarPersonas(sinCobranza){
  await Promise.all([cargarPersonas(), cargarPendientes()]);
  renderPersonas();
  renderPendientes();
  if (!sinCobranza && finMonths.length) cargarCobranza();
}
async function loadPersonas(){ await refrescarPersonas(); }
/* Gestión: una sola carga por apertura/clic. Si ya hay una en vuelo se reutiliza (sin cadenas). */
let gestionCargando = null;
function refrescarGestion(){
  if (gestionCargando) return gestionCargando;
  const btn = $('#refreshPersonasBtn'); if (btn) btn.disabled = true;
  if (ME.rol === 'master') cargarDispositivos();   // solo lista (no consulta a Shelly Cloud)
  gestionCargando = refrescarPersonas(true).finally(() => { gestionCargando = null; if (btn) btn.disabled = false; });
  return gestionCargando;
}
$('#refreshPersonasBtn')?.addEventListener('click', () => refrescarGestion());

/* Compartir app (staff): wa.me sin número para que quien comparte elija el contacto. */
const APP_URL = 'https://racosta123.github.io/mojaveapp/';
const APP_SHARE_MSG = 'Hola, este es el enlace de la app de Cerrada Mojave:\n' + APP_URL +
  '\nÁbrelo en Chrome (Android) o Safari (iPhone) y entra con tu mismo correo y contraseña.\nDespués agrégala a tu pantalla de inicio.';
$('#shareAppWaBtn')?.addEventListener('click', () => {
  window.open('https://wa.me/?text=' + encodeURIComponent(APP_SHARE_MSG), '_blank', 'noopener');
});
$('#shareAppCopyBtn')?.addEventListener('click', async () => {
  try { await navigator.clipboard.writeText(APP_URL); toast('Enlace copiado'); }
  catch { window.prompt('Copia el enlace:', APP_URL); }
});

/* -------- Pendientes de activar: altas sin cuenta (staff). El Worker decide todo; aquí solo se pinta. -------- */
let pendientesCache = [];
let pendientesError = '';
async function cargarPendientes(){
  try {
    const r = await authedFetch('/personas/pendientes', {});
    pendientesCache = Array.isArray(r.pendientes) ? r.pendientes : [];
    pendientesError = '';
  } catch(e){
    console.error('cargarPendientes', e);
    pendientesError = (e && e.message) || 'No se pudo cargar';
  }
}
const fmtPend = iso => iso ? new Date(iso).toLocaleString('es-MX', { timeZone:'America/Hermosillo', day:'numeric', month:'short', hour:'2-digit', minute:'2-digit' }) : '—';
function renderPendientes(){
  const sec = $('#pendSection'); if (!sec) return;
  const lista = $('#pendList');
  $('#pendCount').textContent = String(pendientesCache.length);
  if (pendientesError){
    sec.classList.remove('hidden');
    lista.innerHTML = `<div class="empty">No se pudieron cargar los pendientes (${esc(pendientesError)}). <button class="row-act" data-act="reintentar-pend">Reintentar</button></div>`;
    return;
  }
  sec.classList.toggle('hidden', !pendientesCache.length);
  lista.innerHTML = pendientesCache.map(p => {
    const esAdm = p.rol === 'admin';
    const titulo = esAdm ? p.nombre : (p.domicilio || p.nombre);
    const liga = p.liga.estado === 'viva' ? `liga viva hasta ${fmtPend(p.liga.expiraEn)}`
      : p.liga.estado === 'vencida' ? `liga vencida (${fmtPend(p.liga.expiraEn)})` : 'sin liga';
    const sub = (esAdm ? 'Administrador' : p.nombre) + ` · alta por ${p.creadoPorNombre || '—'} · ${fmtPend(p.creadoEn)} · ${liga}`;
    let acts = '';
    if (p.estado !== 'suspendido') acts += `<button class="row-act" data-act="reenviar" data-id="${p.id}">📲 Reenviar liga</button>`;
    if (!esAdm || ME.rol === 'master') acts += `<button class="row-act danger" data-act="cancelar-alta" data-id="${p.id}">Cancelar alta</button>`;
    return `<div class="row${p.duplicadoEstado==='activa'?' alerta':''}"><div class="ri">${esc(((p.nombre||'?').trim()[0]||'?').toUpperCase())}</div>`
      + `<div class="rt"><div class="a">${esc(titulo)}</div><div class="b">${esc(sub)}</div></div>`
      + `<div class="tags"><span class="tag${p.liga.estado==='viva'?' in':''}">${p.liga.estado==='viva'?'Liga viva':p.liga.estado==='vencida'?'Vencida':'Sin liga'}</span></div></div>`
      + (acts ? `<div class="persona-acts">${acts}</div>` : '');
  }).join('');
}
$('#pendList')?.addEventListener('click', async e => {
  const b = e.target.closest('[data-act]'); if (!b) return;
  if (b.dataset.act === 'reintentar-pend'){ refrescarGestion(); return; }
  const p = pendientesCache.find(x => x.id === b.dataset.id); if (!p) return;
  if (b.dataset.act === 'reenviar'){
    await invitarPersona(p, b);
    await cargarPendientes(); renderPendientes();   // la liga nueva cambia el estado
  } else if (b.dataset.act === 'cancelar-alta'){
    cancelarAltaPendiente(p, b);
  }
});
/* Cancelar alta: confirmación en 2 pasos (mismo patrón que "Revisado"); el Worker revalida todo. */
async function cancelarAltaPendiente(p, btn){
  if (btn.dataset.armado !== '1'){
    btn.dataset.armado = '1'; btn.textContent = '¿Seguro? Toca de nuevo';
    setTimeout(() => { if (btn.isConnected && btn.dataset.armado === '1'){ btn.dataset.armado = ''; btn.textContent = 'Cancelar alta'; } }, 4000);
    return;
  }
  btn.dataset.armado = '';
  btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>';
  try {
    await authedFetch('/personas/alta-cancelar', { id: p.id });
    toast(`Alta cancelada: ${p.nombre}`, 'ok');
    await refrescarPersonas(true);
  } catch(e){
    toast(e.message || 'No se pudo cancelar el alta', 'bad');
    btn.disabled = false; btn.textContent = 'Cancelar alta';
  }
}

/* ====================== CONFIGURACIÓN DE COBRANZA (cuota/fecha: staff · link: SOLO master) ==
   Pantalla en Gestión que solo LLAMA a /config/cobranza (leer) y /config/cobranza-actualizar
   (escribir) — ambos ya existentes y ya validados en el Worker. No agrega ninguna lógica de
   negocio nueva; solo la pinta y la envía. El campo de link de pago (#ccLinkField) se oculta
   y se omite del payload para quien no sea master — el Worker lo rechaza de todos modos. */
let ccFechaOriginal = '';   // YYYY-MM-DD tal como llegó del servidor, para detectar cambios reales

async function cargarConfigCobranza(){
  $('#ccErr').textContent = '';
  try {
    const cfg = await authedFetch('/config/cobranza', {});
    $('#ccCuota').value = cfg.cuotaMensual ?? '';
    const iso = cfg.fechaInicioCobro || '';
    ccFechaOriginal = iso ? iso.slice(0, 10) : '';
    $('#ccFecha').value = ccFechaOriginal;
    $('#ccFechaActual').textContent = iso
      ? 'Actualmente: ' + new Date(iso).toLocaleDateString('es-MX', { day:'numeric', month:'long', year:'numeric' })
      : '';
    $('#ccLink').value = cfg.linkPago || '';
    $('#ccWarnFecha').classList.add('hidden');
  } catch(e){
    $('#ccErr').textContent = votErr(e);
  }
}

/* La advertencia (banner, no un confirm() del navegador) solo aparece cuando master REALMENTE
   cambia la fecha respecto a la ya guardada — así no distrae si solo vino a tocar la cuota o
   el link. Cambiar fechaInicioCobro mueve fechaEfectiva de TODAS las casas en
   /finanzas/estado-cuenta y /finanzas/cobranza (ver calcularEstadoCuenta en worker.js). */
$('#ccFecha')?.addEventListener('input', () => {
  $('#ccWarnFecha').classList.toggle('hidden', $('#ccFecha').value === ccFechaOriginal);
});

$('#ccGuardarBtn')?.addEventListener('click', async () => {
  const btn = $('#ccGuardarBtn');
  $('#ccErr').textContent = '';
  const cuota = $('#ccCuota').value;
  const fecha = $('#ccFecha').value;
  const link = $('#ccLink').value.trim();
  if (cuota === '' || Number(cuota) < 0){ $('#ccErr').textContent = 'La cuota debe ser un número válido, mayor o igual a 0.'; return; }
  if (!fecha){ $('#ccErr').textContent = 'Elige la fecha de inicio de cobro.'; return; }

  const orig = btn.textContent; btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>';
  try {
    // linkPago debe empezar con "https://" — el Worker lo rechaza con 400 si no (o si sobra
    // algo raro); aquí no se duplica esa validación, solo se muestra el error que regrese.
    // linkPago SOLO se manda si eres master: el Worker rechaza con 403 cualquier payload que
    // lo incluya viniendo de admin/jefe-admin, así que ni se intenta (evita un 403 al guardar
    // cuota/fecha, que sí les toca).
    const payload = { cuotaMensual: Number(cuota), fechaInicioCobro: fecha };
    if (ME.rol === 'master') payload.linkPago = link;
    const cfg = await authedFetch('/config/cobranza-actualizar', payload);
    toast('Configuración de cobranza guardada', 'ok');
    ccFechaOriginal = (cfg.fechaInicioCobro || '').slice(0, 10);
    $('#ccFechaActual').textContent = cfg.fechaInicioCobro
      ? 'Actualmente: ' + new Date(cfg.fechaInicioCobro).toLocaleDateString('es-MX', { day:'numeric', month:'long', year:'numeric' })
      : '';
    $('#ccWarnFecha').classList.add('hidden');
  } catch(e){
    $('#ccErr').textContent = votErr(e);
  } finally {
    btn.disabled = false; btn.textContent = orig;
  }
});

/* ====================== SUSPENSIÓN AUTOMÁTICA POR MORA (staff: master/admin/jefe-admin) ======
   "Simular" y "Aplicar de verdad" llaman al MISMO endpoint (/admin/probar-suspension-
   automatica) con distinto `modo` — el Worker decide qué escribe o no; aquí solo se pinta
   el resumen que regresa. Nunca se llama sola: siempre es un clic de staff. */
function renderResumenSuspension(r){
  const el = $('#susResultado');
  if (!r.suspendidas || !r.suspendidas.length){
    const motivo = r.modo === 'aplicar' && !r.aplico
      ? (r.ultimoMesProcesado === r.mesActual ? 'Este mes ya se procesó.' : 'Todavía no toca (antes del día 5 en Hermosillo).')
      : 'Ninguna casa activa tiene adeudo.';
    el.innerHTML = `<div class="empty">${motivo}</div>`;
    return;
  }
  el.innerHTML = r.suspendidas.map(c =>
    `<div class="row"><div class="rt"><div class="a">${esc(c.domicilio || '')}</div>`
    + `${c.nombre?`<div class="b">${esc(c.nombre)}</div>`:''}</div><span class="tag out">${money(c.adeudo)}</span></div>`
  ).join('');
}
async function ejecutarSuspensionAutomatica(modo){
  const btn = modo === 'aplicar' ? $('#susAplicarBtn') : $('#susSimularBtn');
  const orig = btn.textContent; btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>';
  try {
    const r = await authedFetch('/admin/probar-suspension-automatica', { modo });
    renderResumenSuspension(r);
    if (modo === 'aplicar'){
      toast(r.aplico ? `${r.suspendidas.length} casa(s) suspendida(s) por mora` : 'No se aplicó (ver detalle abajo)', r.aplico ? 'bad' : 'ok');
      if (r.aplico) refrescarPersonas();   // el padrón cambió: refleja los nuevos suspendidos
    } else {
      toast(`Simulación: ${r.suspendidas.length} casa(s) se suspenderían hoy`, 'ok');
    }
  } catch(e){
    toast(e.message || 'No se pudo ejecutar', 'bad');
  } finally {
    btn.disabled = false; btn.textContent = orig;
  }
}
$('#susSimularBtn')?.addEventListener('click', () => ejecutarSuspensionAutomatica('simular'));

/* Simular recordatorio de pago (master/admin): solo muestra a quién y qué texto; el Worker no envía nada. */
$('#recSimularBtn')?.addEventListener('click', async () => {
  const btn = $('#recSimularBtn'), el = $('#recResultado');
  const orig = btn.textContent; btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>';
  try {
    const r = await authedFetch('/admin/simular-recordatorio-pago', {});
    if (!r.texto) el.innerHTML = '<div class="empty">Hoy no toca recordatorio (solo los días 1 y 3 del mes).</div>';
    else if (!r.casas.length) el.innerHTML = `<div class="empty">Ninguna casa recibiría recordatorio hoy.</div><div class="vnote">Texto: ${esc(r.texto)}</div>`;
    else el.innerHTML = `<div class="vnote" style="margin:0 0 6px">Texto: ${esc(r.texto)}</div>` + r.casas.map(c =>
      `<div class="row"><div class="rt"><div class="a">${esc(c.domicilio || '')}</div>`
      + `<div class="b">${esc(c.nombre || '')}${c.push ? '' : ' · sin push activado'}${c.yaEnviado ? ' · ya enviado hoy' : ''}</div></div>`
      + `<span class="tag out">${money(c.adeudo)}</span></div>`).join('');
    toast('Simulación: no se envió nada', 'ok');
  } catch(e){
    toast(e.message || 'No se pudo simular', 'bad');
  } finally {
    btn.disabled = false; btn.textContent = orig;
  }
});
$('#susAplicarBtn')?.addEventListener('click', () => ejecutarSuspensionAutomatica('aplicar'));

/* -------- lista agrupada por casa: jefe + sus familiares anidados; admins aparte -------- */
function renderPersonas(){
  const list = $('#personasList');
  const eb = $('#personasErr');
  if (eb){
    eb.classList.toggle('hidden', !personasError);
    eb.innerHTML = personasError
      ? `⚠️ No se pudo cargar el padrón (${esc(personasError)})${personasCache.length ? ' — se muestra la última lista cargada.' : '.'} <button class="row-act" id="personasRetryBtn">Reintentar</button>` : '';
  }
  if (personasError && !personasCache.length){ list.innerHTML = ''; return; }
  const raw = $('#personaSearch').value.trim();
  const q = normDom(raw);
  const match = p => !q || normDom(p.nombre).includes(q)
    || (p.domicilioNorm||'').includes(q) || (p.telefono||'').includes(raw);

  const familiaresDe = id => personasCache.filter(p => p.jefeId === id && !esBajaP(p))
    .sort((a,b)=>normDom(a.nombre).localeCompare(normDom(b.nombre),'es'));

  const casas = jefes().slice().sort((a,b)=>a.domicilio.localeCompare(b.domicilio,'es',{numeric:true}));
  const admins = personasCache.filter(p => (p.rol==='admin' || p.rol==='master') && !esBajaP(p))
    .sort((a,b)=>normDom(a.nombre).localeCompare(normDom(b.nombre),'es'));

  let html = '';
  casas.forEach(j => {
    const fam = familiaresDe(j.id);
    const jefeMatch = match(j);
    const famMatch = fam.filter(match);
    if (q && !jefeMatch && !famMatch.length) return;   // esta casa no casa con la búsqueda
    const visFam = q ? (jefeMatch ? fam : famMatch) : fam;   // si casa el jefe, muestra toda su familia
    html += `<div class="casa-group">${personaRow(j)}`
      + `<div class="fam-list">`
      + (visFam.length ? visFam.map(personaRow).join('') : `<div class="fam-empty">Sin familiares aún (hasta 5)</div>`)
      + `</div></div>`;
  });

  const visAdmins = admins.filter(match);
  if (visAdmins.length){
    html += `<div class="grp-admin"><div class="grp-label">Administración</div>`
      + visAdmins.map(personaRow).join('') + `</div>`;
  }
  list.innerHTML = html || '<div class="empty">Sin personas en el padrón</div>';
  renderBajas();
}

/* -------- Bajas: SOLO consulta (nadie las edita ni reactiva desde aquí) -------- */
function renderBajas(){
  const sec = $('#bajasSection'); if (!sec) return;
  const bajas = personasCache.filter(esBajaP)
    .sort((a,b)=>String(b.bajaEn||'').localeCompare(String(a.bajaEn||'')));
  $('#bajasCount').textContent = String(bajas.length);
  sec.classList.toggle('hidden', !bajas.length);
  $('#bajasList').innerHTML = bajas.map(p => {
    const dom = p.domicilio ? p.domicilio + ' · ' : '';
    const cuando = p.bajaEn ? new Date(p.bajaEn).toLocaleDateString('es-MX', { timeZone:'America/Hermosillo', day:'numeric', month:'short', year:'numeric' }) : '—';
    return `<div class="row"><div class="ri">${esc(((p.nombre||'?').trim()[0]||'?').toUpperCase())}</div>`
      + `<div class="rt"><div class="a">${esc(p.nombre)}</div>`
      + `<div class="b">${esc(dom)}baja el ${esc(cuando)} · por ${esc(p.bajaNombre||'—')} · ${esc(p.bajaMotivo||'sin motivo')}</div></div>`
      + `<div class="tags"><span class="tag susp">Baja</span></div></div>`;
  }).join('');
}

/* -------- una fila de persona: identidad + tags + botones de acción (según rol/estado) -------- */
function personaRow(p){
  const susp = p.estado === 'suspendido';
  const esFam = !!p.jefeId;
  const esAdmin = p.rol === 'admin';
  const esMaster = p.rol === 'master';
  const esYo = p.uid && p.uid === ME.uid;

  const titulo = (esFam || esAdmin || esMaster) ? esc(p.nombre) : esc(p.domicilio || p.nombre);
  const sub = (esFam || esAdmin || esMaster)
    ? (p.telefono ? esc(p.telefono) : '')
    : esc(p.nombre) + (p.telefono ? ' · '+esc(p.telefono) : '');

  const tagEstado = susp
    ? `<span class="tag susp">Suspendido${p.suspendidoPor==='cascada'?' (casa)':''}</span>`
    : `<span class="tag in">Activo</span>`;
  const tagCuenta = esMaster ? `<span class="tag">Master</span>`
    : (p.registrado ? `<span class="tag in">Registrado</span>` : `<span class="tag">Sin cuenta</span>`);
  // FASE 7: un jefe con permiso de admin se distingue en el padrón.
  const tagAdmin = p.esAdmin ? `<span class="tag">🛡 Admin</span>` : '';

  // Acciones (delegadas por data-act). Al master no se le toca; tampoco a tu propia fila.
  let acts = '';
  if (!esMaster && !esYo){
    acts += `<button class="row-act" data-act="editar" data-id="${p.id}">Editar</button>`;
    // Invitar: solo jefe/admin ACTIVO y SIN cuenta (a los familiares los invita su jefe).
    if (!esFam && !p.registrado && !susp)
      acts += `<button class="row-act" data-act="invitar" data-id="${p.id}">📲 Invitar</button>`;
    if (susp) acts += `<button class="row-act" data-act="reactivar" data-id="${p.id}">Reactivar</button>`;
    else      acts += `<button class="row-act danger" data-act="suspender" data-id="${p.id}">Suspender</button>`;
    // Permiso de admin: SOLO master, y solo sobre un jefe de familia (el Worker revalida
    // las dos cosas). Un familiar no puede serlo; un admin puro ya es staff por su rol.
    if (ME.rol === 'master' && !esFam && !esAdmin)
      acts += `<button class="row-act" data-act="admin" data-id="${p.id}">${p.esAdmin ? 'Quitar admin' : '🛡 Hacer admin'}</button>`;
    if (ME.rol === 'master')
      acts += `<button class="row-act danger" data-act="baja" data-id="${p.id}">Dar de baja</button>`
            + `<button class="row-act danger" data-act="borrar" data-id="${p.id}">Borrar</button>`;
  }

  // Motivo de la suspensión MANUAL, visible sin tener que preguntar (ausente si la suspendió
  // el cron de mora — motivoManual es exclusivo de /personas/suspender, staff).
  const motivoLine = (susp && p.motivoManual)
    ? `<div class="vnote" style="padding:0 2px 8px">📝 Motivo: ${esc(p.motivoManual)}</div>` : '';

  // v13 — familiar marcado "Posible residente de otra casa" (solo staff ve alertas_familiares).
  // NO bloquea: el comité decide con Suspender/Borrar, o quita la marca si es legítimo.
  const alFam = esFam ? alertaFamActiva(p.id) : null;
  const alertaLine = alFam
    ? `<div class="mov-liga bad" style="padding:0 2px 6px">⚠️ Posible residente de otra casa · coincide con ${esc(alFam.coincideCon || '')}`
      + `${alFam.dadoDeAltaNombre ? ' · dado de alta por ' + esc(alFam.dadoDeAltaNombre) : ''}</div>` : '';
  if (alFam) acts = `<button class="row-act" data-act="revisar-alerta" data-id="${p.id}">✓ Revisado, es correcto</button>` + acts;

  // Alta con teléfono o nombre ya existentes (confirmada por el staff): en rojo hasta que el comité la revise.
  const dup = p.duplicadoEstado === 'activa';
  const dupLine = dup
    ? `<div class="mov-liga bad" style="padding:0 2px 6px">⚠️ Posible duplicado · coincide con ${esc(p.duplicadoCon || '')}`
      + `${p.dadoDeAltaNombre ? ' · dado de alta por ' + esc(p.dadoDeAltaNombre) : ''}</div>` : '';
  if (dup) acts = `<button class="row-act" data-act="revisar-dup" data-id="${p.id}">✓ Revisado, es correcto</button>` + acts;

  return `<div class="row${(alFam || dup) ? ' alerta' : ''}">`
      + `<div class="ri">${esc(((p.nombre||'?').trim()[0]||'?').toUpperCase())}</div>`
      + `<div class="rt"><div class="a">${titulo}</div>${sub?`<div class="b">${sub}</div>`:''}</div>`
      + `<div class="tags">${tagEstado}${tagAdmin}${tagCuenta}</div>`
    + `</div>` + alertaLine + dupLine + motivoLine + (acts ? `<div class="persona-acts">${acts}</div>` : '');
}

/* "Revisado, es correcto": el Worker revalida staff, marca la alerta como revisada y deja
   registro (quién y cuándo) en la alerta y en la bitácora. La tarjeta se actualiza sola con
   el listener de alertas_familiares. */
async function revisarAlertaFamiliar(p, btn){
  // Confirmación en el mismo botón (dos toques), sin confirm() del navegador.
  if (btn.dataset.armado !== '1'){
    btn.dataset.armado = '1'; btn.textContent = '¿Seguro? Toca de nuevo';
    setTimeout(() => { if (btn.isConnected && btn.dataset.armado === '1'){ btn.dataset.armado = ''; btn.textContent = '✓ Revisado, es correcto'; } }, 4000);
    return;
  }
  btn.dataset.armado = '';
  const orig = '✓ Revisado, es correcto'; btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>';
  try {
    await authedFetch('/personas/alerta-revisar', { personaId: p.id });
    toast(`Marca quitada: ${p.nombre}`, 'ok');
  } catch(e){
    toast(e.message || 'No se pudo marcar como revisado', 'bad');
    btn.disabled = false; btn.textContent = orig;
  }
}

/* Mismo patrón que "Revisado" de familiares: dos toques; el Worker revalida staff y deja bitácora. */
async function revisarDuplicado(p, btn){
  if (btn.dataset.armado !== '1'){
    btn.dataset.armado = '1'; btn.textContent = '¿Seguro? Toca de nuevo';
    setTimeout(() => { if (btn.isConnected && btn.dataset.armado === '1'){ btn.dataset.armado = ''; btn.textContent = '✓ Revisado, es correcto'; } }, 4000);
    return;
  }
  btn.dataset.armado = '';
  btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>';
  try {
    await authedFetch('/personas/duplicado-revisar', { id: p.id });
    toast(`Marca quitada: ${p.nombre}`, 'ok');
    await refrescarPersonas(true);
  } catch(e){
    toast(e.message || 'No se pudo marcar como revisado', 'bad');
    btn.disabled = false; btn.textContent = '✓ Revisado, es correcto';
  }
}

$('#personaSearch')?.addEventListener('input', renderPersonas);
/* Delegación: cada botón de fila lleva data-act + data-id. */
$('#personasErr')?.addEventListener('click', e => { if (e.target.closest('#personasRetryBtn')) refrescarGestion(); });
$('#personasList')?.addEventListener('click', e => {
  const b = e.target.closest('[data-act]'); if (!b) return;
  const p = personasCache.find(x => x.id === b.dataset.id); if (!p) return;
  switch (b.dataset.act){
    case 'editar':    abrirPersonaSheet(p); break;
    case 'invitar':   invitarPersona(p, b); break;
    case 'suspender': abrirPersonaSuspenderSheet(p); break;
    case 'reactivar': cambiarEstadoPersona(p, 'reactivar', b); break;
    case 'admin':     cambiarAdminPersona(p, b); break;
    case 'borrar':    abrirPersonaDelSheet(p); break;
    case 'baja':      abrirPersonaBajaSheet(p); break;
    case 'revisar-alerta': revisarAlertaFamiliar(p, b); break;
    case 'revisar-dup': revisarDuplicado(p, b); break;
  }
});

/* -------- permiso de admin sobre un jefe (FASE 7) — solo master. El front solo pinta el
   botón; /personas/admin revalida master + que el objetivo sea jefe, server-side. -------- */
async function cambiarAdminPersona(p, btn){
  const dar = !p.esAdmin;
  const orig = btn.textContent; btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>';
  try {
    await authedFetch('/personas/admin', { id: p.id, esAdmin: dar });
    toast(dar ? `${p.nombre} ya es administrador` : `${p.nombre} dejó de ser administrador`, 'ok');
    await refrescarPersonas();
  } catch(e){
    toast(e.message || 'No se pudo cambiar el permiso', 'bad');
    btn.disabled = false; btn.textContent = orig;
  }
}

/* -------- alta / edición de persona (jefe o admin). El familiar se crea al invitarlo. -------- */
let personaEditId = null;   // null = alta; id = edición
let personaRolSel = 'residente';
function setPersonaRol(r){
  personaRolSel = r;
  $$('#peRolSeg button').forEach(x=>x.classList.toggle('sel', x.dataset.r===r));
  $('#peDomField').classList.toggle('hidden', r!=='residente');
}
$('#peRolSeg')?.addEventListener('click', e => {
  const b = e.target.closest('button'); if (!b || b.classList.contains('hidden')) return;
  setPersonaRol(b.dataset.r);
});

let peDupOk = false;   // el staff ya vio el aviso de duplicado y eligió continuar
function peResetDup(){ peDupOk = false; $('#peDupWarn')?.classList.add('hidden'); }
$('#peName')?.addEventListener('input', peResetDup);
$('#peTel')?.addEventListener('input', peResetDup);
function abrirPersonaSheet(p){
  peResetDup();
  personaEditId = p ? p.id : null;
  const esFam = p && !!p.jefeId;
  const esAdmin = p && p.rol === 'admin';
  $('#personaTitle').textContent = p ? (esFam?'Editar familiar':'Editar persona') : 'Alta de persona';
  $('#peName').value = p?.nombre || '';
  $('#peTel').value  = p?.telefono || '';
  $('#peDom').value  = (p && !esFam) ? (p.domicilio||'') : '';
  // Rol: solo elegible en ALTA (el Worker no cambia rol al actualizar). "Administrador" solo master.
  $('#peRolAdminBtn').classList.toggle('hidden', ME.rol !== 'master');
  $('#peRolField').classList.toggle('hidden', !!p);
  setPersonaRol(p ? (esAdmin?'admin':(esFam?'familiar':'residente')) : 'residente');
  // En edición el domicilio se muestra solo para jefes (el familiar lo hereda; el admin no tiene).
  if (p) $('#peDomField').classList.toggle('hidden', esFam || esAdmin);
  $('#peHint').classList.toggle('hidden', !!p);
  // Borrar: solo master, no sobre master ni sobre tu propia cuenta (el Worker revalida).
  $('#delPersonaBtn').classList.toggle('hidden', !(p && ME.rol==='master' && p.rol!=='master' && p.uid!==ME.uid));
  $('#peErr').textContent = '';
  $('#savePersonaBtn').textContent = p ? 'Guardar cambios' : 'Guardar';
  openSheet('#personaOverlay');
}
$('#newPersonaBtn')?.addEventListener('click', () => abrirPersonaSheet(null));
$('#personaOverlay')?.addEventListener('click', e => { if(e.target.id==='personaOverlay') closeSheet('#personaOverlay'); });
$('#savePersonaBtn')?.addEventListener('click', guardarPersona);

async function guardarPersona(){
  const nombre = $('#peName').value.trim();
  const telefono = $('#peTel').value.trim();
  const domicilio = $('#peDom').value.trim();
  $('#peErr').textContent = '';
  if (!nombre){ $('#peErr').textContent = 'Falta el nombre'; return; }
  if (!telefono){ $('#peErr').textContent = 'El teléfono es obligatorio'; return; }
  const esEdicion = !!personaEditId;
  const editP = esEdicion ? personasCache.find(x=>x.id===personaEditId) : null;
  const rol = esEdicion ? editP.rol : personaRolSel;
  const jefeConDom = esEdicion ? esJefeP(editP) : (rol==='residente');
  if (jefeConDom && !domicilio){ $('#peErr').textContent = 'El domicilio es obligatorio para una casa'; return; }
  const btn = $('#savePersonaBtn'); btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>';
  try {
    // El Worker valida rol staff y el anti-duplicados de domicilio server-side.
    if (esEdicion){
      const body = { id: personaEditId, nombre, telefono };
      if (jefeConDom) body.domicilio = domicilio;   // solo el jefe edita domicilio
      await authedFetch('/personas/actualizar', body);
      toast('Persona actualizada', 'ok');
    } else {
      const body = { nombre, telefono, rol };
      if (rol === 'residente') body.domicilio = domicilio;
      if (peDupOk) body.confirmarDuplicado = true;
      const r = await authedFetch('/personas/crear', body);
      toast(r && r.duplicado ? 'Alta registrada y marcada para revisión' : (rol==='admin' ? 'Administrador dado de alta' : 'Casa dada de alta'), r && r.duplicado ? 'bad' : 'ok');
      peResetDup();
    }
    closeSheet('#personaOverlay');
    await refrescarPersonas();
  } catch(e){
    if (e && e.data && e.data.requiereConfirmacion){
      // Duplicado: no se bloquea. Se avisa y, si el staff continúa, el alta queda marcada en rojo.
      peDupOk = true;
      $('#peDupWarn').innerHTML = (e.data.duplicados || []).map(t => `Ya existe <b>${esc(t)}</b>.`).join('<br>')
        + '<br>¿Continuar? Si sí, el alta quedará marcada en rojo para que el comité la revise.';
      $('#peDupWarn').classList.remove('hidden');
      return;
    }
    $('#peErr').textContent = e.message || 'No se pudo guardar';
  } finally {
    btn.disabled = false;
    btn.textContent = peDupOk ? 'Continuar de todos modos' : (esEdicion ? 'Guardar cambios' : 'Guardar');
  }
}

/* -------- suspender (staff), con motivo obligatorio por MODAL (no prompt nativo) — mismo
   patrón visual que abrirPersonaDelSheet. El Worker rechaza con 400 si el motivo viene vacío;
   aquí solo se valida antes para no hacer el viaje al servidor en vano. -------- */
let personaSuspenderId = null;
function abrirPersonaSuspenderSheet(p){
  personaSuspenderId = p.id;
  $('#personaSuspenderInfo').innerHTML = esJefeP(p)
    ? `<b>${esc(p.domicilio||'')}</b> · ${esc(p.nombre||'')}`
    : `<b>${esc(p.nombre||'')}</b>${p.domicilio?' · '+esc(p.domicilio):''}`;
  $('#personaSuspenderMotivo').value = '';
  $('#personaSuspenderErr').textContent = '';
  openSheet('#personaSuspenderOverlay');
}
$('#personaSuspenderCancel')?.addEventListener('click', () => closeSheet('#personaSuspenderOverlay'));
$('#personaSuspenderOverlay')?.addEventListener('click', e => { if(e.target.id==='personaSuspenderOverlay') closeSheet('#personaSuspenderOverlay'); });
$('#personaSuspenderConfirm')?.addEventListener('click', async () => {
  if (!personaSuspenderId) return;
  const motivo = $('#personaSuspenderMotivo').value.trim();
  $('#personaSuspenderErr').textContent = '';
  if (!motivo){ $('#personaSuspenderErr').textContent = 'Escribe el motivo de la suspensión'; return; }
  const btn = $('#personaSuspenderConfirm'); btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>';
  try {
    await authedFetch('/personas/suspender', { id: personaSuspenderId, motivo });
    const p = personasCache.find(x => x.id === personaSuspenderId);
    const cascada = p && esJefeP(p) ? ' (y su familia)' : '';
    toast('Suspendido'+cascada+' · no podrá abrir puertas', 'bad');
    closeSheet('#personaSuspenderOverlay');
    await refrescarPersonas();
  } catch(e){
    $('#personaSuspenderErr').textContent = e.message || 'No se pudo suspender';
  } finally { btn.disabled = false; btn.textContent = 'Sí, suspender'; }
});

/* -------- reactivar (staff). Reactivar un jefe hace cascada a su familia. -------- */
async function cambiarEstadoPersona(p, accion, btn){
  const orig = btn.textContent; btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>';
  try {
    await authedFetch('/personas/'+accion, { id: p.id });
    const cascada = esJefeP(p) ? ' (y su familia)' : '';
    toast(accion==='suspender' ? 'Suspendido'+cascada+' · no podrá abrir puertas' : 'Reactivado'+cascada,
          accion==='suspender' ? 'bad' : 'ok');
    await refrescarPersonas();
  } catch(e){
    toast(e.message || 'No se pudo actualizar', 'bad');
    btn.disabled = false; btn.textContent = orig;
  }
}

/* ====================== DISPOSITIVOS (Shelly) — SOLO master ======================
   La pantalla solo PIDE: el Worker valida master, contraseña reciente, formato, y que el Shelly
   nuevo exista y esté en línea ANTES de guardar. La apertura de puertas no se toca desde aquí. */
const DISP_NOMBRE = { visitantes:'Visitantes', residentes:'Residentes', peatones:'Peatonal', salida:'Salida' };
let dispCache = [];
let dispEstado = {};   // puerta -> { online, existe } (solo si el master pulsó "Verificar estado")
async function cargarDispositivos(){
  const sec = $('#dispSection'); if (!sec) return;
  if (ME.rol !== 'master'){ sec.classList.add('hidden'); return; }
  sec.classList.remove('hidden');
  try {
    const r = await authedFetch('/dispositivos/listar', {});
    dispCache = r.puertas || [];
    renderDispositivos();
  } catch(e){
    $('#dispList').innerHTML = `<div class="empty">No se pudo cargar (${esc(e.message||'error')}). <button class="row-act" data-act="reintentar">Reintentar</button></div>`;
  }
}
function renderDispositivos(){
  $('#dispList').innerHTML = dispCache.map(d => {
    const nom = DISP_NOMBRE[d.puerta] || d.puerta;
    const est = dispEstado[d.puerta];
    const tagEst = !d.id ? '<span class="tag">Sin asignar</span>'
      : est ? (est.online ? '<span class="tag in">En línea</span>' : '<span class="tag susp">'+(est.existe===false?'No existe':'Fuera de línea')+'</span>') : '<span class="tag">—</span>';
    const sub = d.id ? `Gen${d.gen} · …${esc(String(d.id).slice(-6))} · ${d.origen==='documento'?'cambiado desde la app':'original (respaldo)'}${d.ultimoCambio?' · último cambio: '+esc(d.ultimoCambio.nombre||''):''}` : 'Sin dispositivo asignado';
    let acts = '';
    if (d.id) acts += `<button class="row-act" data-act="estado" data-p="${d.puerta}">Verificar estado</button>`;
    acts += `<button class="row-act" data-act="cambiar" data-p="${d.puerta}">Cambiar Shelly</button>`;
    if (d.puedeRegresar) acts += `<button class="row-act" data-act="regresar" data-p="${d.puerta}">↩ Regresar al anterior</button>`;
    if (d.id) acts += `<button class="row-act danger" data-act="probar" data-p="${d.puerta}">Pulso de prueba</button>`;
    return `<div class="row"><div class="ri">${esc(nom[0])}</div><div class="rt"><div class="a">${esc(nom)}</div><div class="b">${sub}</div></div><div class="tags">${tagEst}</div></div><div class="persona-acts">${acts}</div>`;
  }).join('');
}
$('#dispList')?.addEventListener('click', async e => {
  const b = e.target.closest('[data-act]'); if (!b) return;
  if (b.dataset.act === 'reintentar'){ cargarDispositivos(); return; }
  const p = b.dataset.p;
  if (b.dataset.act === 'estado'){
    const orig = b.textContent; b.disabled = true; b.innerHTML = '<span class="spinner"></span>';
    try {
      const r = await authedFetch('/dispositivos/estado', { puerta: p });
      dispEstado[p] = { online: r.online === true, existe: r.existe };
      if (r.error) toast('No se pudo consultar Shelly Cloud (' + r.error + ')', 'bad');
    } catch(err){ toast(err.message || 'No se pudo consultar', 'bad'); }
    renderDispositivos();
  } else abrirDispSheet(b.dataset.act, p);
});

/* Diagnóstico (SOLO LECTURA): una consulta a Shelly Cloud con la lista de la cuenta. No cambia nada, no abre nada, no guarda nada.
   Muestra qué repuestos ve la app y la FORMA de la respuesta real (campos y tipos; sin IDs ni llaves) para validar el parser. */
$('#dispDiagBtn')?.addEventListener('click', async () => {
  const b = $('#dispDiagBtn'), out = $('#dispDiag'); const orig = b.textContent;
  b.disabled = true; b.innerHTML = '<span class="spinner"></span>'; out.classList.remove('hidden'); out.textContent = 'Consultando Shelly Cloud…';
  try {
    const r = await authedFetch('/dispositivos/disponibles', { diagnostico: true });
    const etiqueta = c => `  • ${c.nombre || '(sin nombre en la app de Shelly)'} · ${c.genEtiqueta || c.gen ? 'Gen' + (c.genEtiqueta || c.gen) : 'gen ?'} · ${c.modelo || ''} · …${c.id6} · ${c.online ? 'EN LÍNEA' : 'fuera de línea'} · asignado a: ${c.asignadoA ? (DISP_NOMBRE[c.asignadoA] || c.asignadoA) : 'nadie (repuesto)'}\n      criterios → gen: ${c.criterioGen || '?'} · línea: ${c.criterioOnline || '?'} · nombre: ${c.criterioNombre || 'no viene'}`;
    out.textContent = `Consulta correcta.\nDispositivos en la cuenta: ${r.totalCuenta}\n` + (r.cuenta || []).map(etiqueta).join('\n')
      + `\n\nRepuestos EN LÍNEA y sin asignar: ${r.disponibles.length}\nSin asignar y fuera de línea: ${r.fueraDeLinea}`
      + (r.errorV2 ? `\n(Aviso: la consulta de nombres (v2) falló: ${r.errorV2})` : '')
      + `\n\nFORMA de /device/all_status (todas las llaves, sin valores):\n${JSON.stringify(r.forma)}\n\nFORMA de /v2/devices/api/get:\n${JSON.stringify(r.formaV2)}`;
  } catch(e){
    out.textContent = 'No se pudo consultar: ' + (e.message || 'error') + (e.data && e.data.forma ? '\n\nFORMA de la respuesta:\n' + JSON.stringify(e.data.forma, null, 1) : '');
  } finally { b.disabled = false; b.textContent = orig; }
});

let dispModo = null, dispPuerta = null, dispValidado = null, dispForzar = false;
function abrirDispSheet(modo, puerta){
  dispModo = modo; dispPuerta = puerta; dispValidado = null; dispForzar = false;
  const d = dispCache.find(x => x.puerta === puerta) || {};
  const nom = DISP_NOMBRE[puerta] || puerta;
  $('#dispTitle').textContent = modo === 'cambiar' ? 'Cambiar Shelly · ' + nom : modo === 'regresar' ? 'Regresar al anterior · ' + nom : 'Pulso de prueba · ' + nom;
  $('#dispInfo').innerHTML = `<b>${esc(nom)}</b>${d.id ? ' · actual …' + esc(String(d.id).slice(-6)) + ' (Gen' + d.gen + ')' : ' · sin asignar'}`;
  $('#dispIdField').classList.toggle('hidden', modo !== 'cambiar');
  $('#dispId').value = ''; $('#dispValid').textContent = ''; $('#dispGenField').classList.add('hidden'); $('#dispGen').value = '';
  $('#dispLista').innerHTML = ''; $('#dispListaMsg').textContent = ''; $('#dispSel').textContent = ''; $('#dispManual').classList.add('hidden');
  const av = $('#dispAviso');
  av.classList.toggle('hidden', modo === 'cambiar');
  av.textContent = modo === 'probar' ? '⚠️ Esto ABRIRÁ la puerta física ahora mismo (pasa por la ruta normal de apertura).'
    : modo === 'regresar' ? 'Vuelve al Shelly que tenía esta puerta antes del último cambio. Se comprueba que esté en línea.' : '';
  $('#dispPass').value = ''; $('#dispErr').textContent = '';
  const c = $('#dispConfirmBtn'); c.disabled = false; c.textContent = modo === 'cambiar' ? 'Guardar cambio' : modo === 'regresar' ? 'Regresar al anterior' : 'Abrir ahora (prueba)';
  c.dataset.armado = '';
  openSheet('#dispOverlay');
  if (modo === 'cambiar') buscarRepuestos();   // UNA consulta a Shelly Cloud por toque (manual, nunca automática en bucle)
}
/* Repuestos: el Worker pide a Shelly Cloud la lista de la cuenta y devuelve SOLO los EN LÍNEA y SIN asignar. La llave de
   Shelly nunca llega aquí. Teclear el ID a mano queda como respaldo. */
async function buscarRepuestos(){
  const lista = $('#dispLista'), msg = $('#dispListaMsg'), b = $('#dispBuscarBtn');
  lista.innerHTML = ''; $('#dispSel').textContent = ''; dispValidado = null; $('#dispGenField').classList.add('hidden');
  msg.textContent = 'Buscando repuestos en línea…'; b.disabled = true;
  try {
    const r = await authedFetch('/dispositivos/disponibles', {});
    if (!r.disponibles.length){
      msg.textContent = 'No hay repuestos en línea. Revisa que el Shelly tenga corriente y WiFi de la cerrada.'
        + (r.fueraDeLinea ? ` (Hay ${r.fueraDeLinea} sin conexión.)` : '');
    } else {
      msg.textContent = 'Toca el repuesto que vas a instalar:';
      dispRepuestos = r.disponibles;
      lista.innerHTML = r.disponibles.map((d, i) => `<div class="row" data-rep="${i}" style="cursor:pointer"><div class="ri">⚡</div><div class="rt"><div class="a">${esc(d.nombre || '(sin nombre en la app de Shelly)')}</div><div class="b">${(d.genEtiqueta || d.gen) ? 'Gen' + (d.genEtiqueta || d.gen) : 'Generación sin informar'} · ${esc(d.modelo || '')} · ID …${esc(d.id.slice(-6))}</div></div><div class="tags"><span class="tag in">En línea</span></div></div>`).join('');
    }
  } catch(e){ msg.textContent = e.message || 'No se pudo consultar Shelly Cloud'; }
  finally { b.disabled = false; }
}
let dispRepuestos = [], dispGenSel = null;
$('#dispLista')?.addEventListener('click', e => {
  const row = e.target.closest('[data-rep]'); if (!row) return;
  const d = dispRepuestos[+row.dataset.rep]; if (!d) return;
  $('#dispId').value = d.id; dispValidado = d.id; dispGenSel = d.gen;
  $$('#dispLista .row').forEach(x => x.style.outline = ''); row.style.outline = '2px solid var(--gold)';
  $('#dispSel').textContent = `Seleccionado: ${d.nombre || '(sin nombre en la app de Shelly)'} · ${(d.genEtiqueta || d.gen) ? 'Gen' + (d.genEtiqueta || d.gen) : 'elige la generación abajo'} · …${d.id.slice(-6)}`;
  $('#dispGenField').classList.toggle('hidden', !!d.gen);
});
$('#dispBuscarBtn')?.addEventListener('click', () => buscarRepuestos());
$('#dispManualBtn')?.addEventListener('click', () => $('#dispManual').classList.toggle('hidden'));
$('#dispCancelBtn')?.addEventListener('click', () => closeSheet('#dispOverlay'));
$('#dispOverlay')?.addEventListener('click', e => { if(e.target.id==='dispOverlay') closeSheet('#dispOverlay'); });
$('#dispId')?.addEventListener('input', () => { dispValidado = null; $('#dispValid').textContent = ''; $('#dispGenField').classList.add('hidden'); });
$('#dispValidarBtn')?.addEventListener('click', async () => {
  const id = $('#dispId').value.trim(); $('#dispErr').textContent = '';
  if (!id){ $('#dispErr').textContent = 'Pega el ID del Shelly nuevo'; return; }
  const b = $('#dispValidarBtn'); const orig = b.textContent; b.disabled = true; b.innerHTML = '<span class="spinner"></span>';
  try {
    const r = await authedFetch('/dispositivos/verificar', { id, puerta: dispPuerta });
    dispValidado = id;
    $('#dispValid').innerHTML = r.online
      ? `✅ Existe y está en línea · ${r.gen ? 'Gen' + r.gen + ' detectado' : 'no informó su generación'}`
      : '⚠️ Existe pero está FUERA DE LÍNEA: no se podrá asignar hasta que se conecte.';
    $('#dispGenField').classList.toggle('hidden', !!r.gen);
  } catch(e){ dispValidado = null; $('#dispValid').textContent = ''; $('#dispErr').textContent = e.message || 'No se pudo validar'; }
  finally { b.disabled = false; b.textContent = orig; }
});
/* Contraseña de nuevo: se reautentica con Firebase y se pide un token fresco (el Worker exige auth_time <= 5 min). */
async function reautenticarMaster(pass){
  const u = auth.currentUser;
  const cred = firebase.auth.EmailAuthProvider.credential(u.email, pass);
  await u.reauthenticateWithCredential(cred);
  await u.getIdToken(true);
}
$('#dispConfirmBtn')?.addEventListener('click', async () => {
  if (ME.rol !== 'master' || !dispModo) return;
  const btn = $('#dispConfirmBtn'); $('#dispErr').textContent = '';
  const pass = $('#dispPass').value;
  if (!pass){ $('#dispErr').textContent = 'Escribe tu contraseña'; return; }
  const id = $('#dispId').value.trim();
  if (dispModo === 'cambiar'){
    if (!id){ $('#dispErr').textContent = 'Pega el ID del Shelly nuevo'; return; }
    if (dispValidado !== id){ $('#dispErr').textContent = 'Primero toca "Validar" con este ID'; return; }
  }
  if (btn.dataset.armado !== '1'){   // confirmación en 2 toques
    btn.dataset.armado = '1'; const t0 = btn.textContent; btn.textContent = '¿Seguro? Toca de nuevo';
    setTimeout(() => { if (btn.isConnected && btn.dataset.armado === '1'){ btn.dataset.armado = ''; btn.textContent = t0; } }, 5000);
    return;
  }
  btn.dataset.armado = ''; btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>';
  try {
    try { await reautenticarMaster(pass); }
    catch(e){ throw new Error('Contraseña incorrecta'); }
    if (dispModo === 'cambiar'){
      const body = { puerta: dispPuerta, id };
      const g = parseInt($('#dispGen').value, 10); if (g) body.genManual = g;
      const r = await authedFetch('/dispositivos/cambiar', body);
      toast(`Shelly de ${DISP_NOMBRE[dispPuerta]} cambiado (Gen${r.gen})`, 'ok');
    } else if (dispModo === 'regresar'){
      try { await authedFetch('/dispositivos/revertir', dispForzar ? { puerta: dispPuerta, forzar: true } : { puerta: dispPuerta }); toast('Regresó al Shelly anterior', 'ok'); }
      catch(e){
        if (e.data && e.data.anteriorFueraDeLinea){
          // Sin confirm() nativo: se avisa en la hoja y el siguiente intento va con forzar.
          dispForzar = true;
          const av = $('#dispAviso'); av.classList.remove('hidden');
          av.textContent = '⚠️ El Shelly anterior está FUERA DE LÍNEA. Si regresas ahora la puerta podría no abrir. Para regresar de todos modos, vuelve a escribir tu contraseña y confirma otra vez.';
          throw new Error('Shelly anterior fuera de línea');
        } else throw e;
      }
    } else {
      await authedFetch('/dispositivos/probar', { puerta: dispPuerta, confirmar: true });
      toast('Pulso enviado a ' + DISP_NOMBRE[dispPuerta], 'ok');
    }
    closeSheet('#dispOverlay');
    delete dispEstado[dispPuerta];
    await cargarDispositivos();
  } catch(e){
    $('#dispErr').textContent = e.message || 'No se pudo completar';
  } finally { btn.disabled = false; btn.textContent = dispModo === 'cambiar' ? 'Guardar cambio' : dispModo === 'regresar' ? 'Regresar al anterior' : 'Abrir ahora (prueba)'; }
});

/* -------- DAR DE BAJA (solo master): motivo obligatorio + confirmación en 2 pasos (mismo botón).
   El Worker revalida master, motivo y que no sea master/uno mismo; aquí solo se pide. -------- */
let personaBajaId = null;
function abrirPersonaBajaSheet(p){
  personaBajaId = p.id;
  const fam = esJefeP(p) ? personasCache.filter(x => x.jefeId === p.id && !esBajaP(x)).length : 0;
  $('#personaBajaInfo').innerHTML = esJefeP(p)
    ? `<b>${esc(p.domicilio||'')}</b> · ${esc(p.nombre||'')}${fam ? ` · y sus ${fam} familiar(es)` : ''}`
    : `<b>${esc(p.nombre||'')}</b>${p.domicilio?' · '+esc(p.domicilio):''}`;
  $('#personaBajaMotivo').value = '';
  $('#personaBajaErr').textContent = '';
  const b = $('#personaBajaConfirm'); b.dataset.armado = ''; b.disabled = false; b.textContent = 'Dar de baja';
  openSheet('#personaBajaOverlay');
}
$('#personaBajaCancel')?.addEventListener('click', () => closeSheet('#personaBajaOverlay'));
$('#personaBajaOverlay')?.addEventListener('click', e => { if(e.target.id==='personaBajaOverlay') closeSheet('#personaBajaOverlay'); });
$('#personaBajaMotivo')?.addEventListener('input', () => { const b = $('#personaBajaConfirm'); b.dataset.armado = ''; b.textContent = 'Dar de baja'; });
$('#personaBajaConfirm')?.addEventListener('click', async () => {
  if (!personaBajaId || ME.rol !== 'master') return;
  const btn = $('#personaBajaConfirm');
  const motivo = $('#personaBajaMotivo').value.trim();
  $('#personaBajaErr').textContent = '';
  if (motivo.length < 3){ $('#personaBajaErr').textContent = 'Escribe el motivo de la baja'; return; }
  if (btn.dataset.armado !== '1'){
    btn.dataset.armado = '1'; btn.textContent = '¿Seguro? Toca de nuevo';
    setTimeout(() => { if (btn.isConnected && btn.dataset.armado === '1'){ btn.dataset.armado = ''; btn.textContent = 'Dar de baja'; } }, 5000);
    return;
  }
  btn.dataset.armado = ''; btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>';
  try {
    const r = await authedFetch('/personas/baja', { id: personaBajaId, motivo });
    toast(`Baja registrada (${(r.bajas||[]).length} persona(s))`, 'bad');
    closeSheet('#personaBajaOverlay');
    await refrescarPersonas(true);
  } catch(e){
    $('#personaBajaErr').textContent = e.message || 'No se pudo dar de baja';
  } finally { btn.disabled = false; btn.textContent = 'Dar de baja'; }
});

/* -------- borrado de persona (solo master) — confirmación por MODAL, no confirm nativo.
   El Worker revalida master, bloquea jefe con familiares/pagos y respalda a personas_borradas. -------- */
let personaDelId = null;
function abrirPersonaDelSheet(p){
  personaDelId = p.id;
  $('#personaDelInfo').innerHTML = esJefeP(p)
    ? `<b>${esc(p.domicilio||'')}</b> · ${esc(p.nombre||'')}`
    : `<b>${esc(p.nombre||'')}</b>${p.domicilio?' · '+esc(p.domicilio):''}`;
  $('#personaDelErr').textContent = '';
  openSheet('#personaDelOverlay');
}
$('#personaDelCancel')?.addEventListener('click', () => closeSheet('#personaDelOverlay'));
$('#personaDelOverlay')?.addEventListener('click', e => { if(e.target.id==='personaDelOverlay') closeSheet('#personaDelOverlay'); });
$('#personaDelConfirm')?.addEventListener('click', async () => {
  if (!personaDelId || ME.rol !== 'master') return;
  const btn = $('#personaDelConfirm'); btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>';
  try {
    await authedFetch('/personas/borrar', { id: personaDelId });
    toast('Persona borrada', 'bad');
    closeSheet('#personaDelOverlay');
    await refrescarPersonas();
  } catch(e){
    $('#personaDelErr').textContent = e.message || 'No se pudo borrar';
  } finally { btn.disabled = false; btn.textContent = 'Sí, borrar'; }
});

/* -------- invitación de registro (staff → jefe/admin sin cuenta). El token lo genera el
   Worker; el link se arma desde location.origin. SIEMPRE Web Share; jamás wa.me ni pestañas
   nuevas. Plan B: modal "Copiar link" si navigator.share no existe. -------- */
async function invitarPersona(p, btn){
  const orig = btn.textContent; btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>';
  try {
    const r = await authedFetch('/invitaciones/crear', { personaId: p.id });
    const url = new URL('registro.html', location.href).href + '#' + r.token;
    const destino = esJefeP(p) ? `el domicilio ${p.domicilio}` : 'la administración';
    const texto = `Hola, te invito a registrarte en la app de Cerrada Mojave para ${destino}. Abre este enlace (vence en 72 h):`;
    await compartirInvitacion({ title:'Cerrada Mojave', text: texto, url },
      { titulo: esJefeP(p) ? p.domicilio : p.nombre, sub: p.nombre });
  } catch(e){
    toast(e.message || 'No se pudo generar la invitación', 'bad');
  } finally { btn.disabled = false; btn.textContent = orig; }
}

/* Web Share primero (AbortError = el usuario canceló, no es error). Plan B: modal copiar link. */
let inviteFallbackUrl = null;
async function compartirInvitacion(shareData, info){
  if (navigator.share){
    try { await navigator.share(shareData); }
    catch(e){ if (!(e && e.name === 'AbortError')) abrirInviteFallback(shareData.url, info); }
  } else {
    abrirInviteFallback(shareData.url, info);
  }
}
function abrirInviteFallback(url, info){
  inviteFallbackUrl = url;
  $('#inviteFallbackInfo').innerHTML = `<b>${esc(info.titulo||'')}</b>${info.sub?' · '+esc(info.sub):''}`;
  $('#inviteFallbackLink').value = url;
  openSheet('#inviteFallbackOverlay');
}
$('#inviteFallbackClose')?.addEventListener('click', () => closeSheet('#inviteFallbackOverlay'));
$('#inviteFallbackOverlay')?.addEventListener('click', e => { if(e.target.id==='inviteFallbackOverlay') closeSheet('#inviteFallbackOverlay'); });
$('#inviteCopyBtn')?.addEventListener('click', async () => {
  try { await navigator.clipboard.writeText(inviteFallbackUrl); toast('Link copiado', 'ok'); }
  catch(e){ $('#inviteFallbackLink').select(); document.execCommand('copy'); toast('Link copiado', 'ok'); }
});

/* ====================== MI FAMILIA (FASE 6.5 · self-service del jefe) ======================
   El jefe de familia (residente sin jefeId) invita hasta 5 familiares. El tope y la
   pertenencia los valida el Worker; aquí solo pintamos N/5 y permitimos cancelar a los que
   sigan "Sin cuenta". Se lee de /personas/mis-familiares (jefe-only). */
function setupMiFamilia(){
  const sec = $('#miFamiliaSection');
  if (!sec) return;
  if (!soyJefe()){ sec.classList.add('hidden'); return; }
  sec.classList.remove('hidden');
  cargarMiFamilia();
}
async function cargarMiFamilia(){
  try {
    const r = await authedFetch('/personas/mis-familiares', {});
    miFamiliaCache = Array.isArray(r.familiares) ? r.familiares : [];
    renderMiFamilia(r.max || 5, r.puedeInvitar !== false);
  } catch(e){
    // Cuenta previa a FASE 6.5 (sin persona vinculada) u otro error: oculta la sección.
    console.error('cargarMiFamilia', e);
    $('#miFamiliaSection').classList.add('hidden');
  }
}
function renderMiFamilia(max, puedeInvitar){
  const n = miFamiliaCache.length;
  $('#famCount').textContent = `(${n}/${max})`;
  const btn = $('#newFamiliarBtn');
  const lleno = n >= max;
  btn.disabled = lleno || !puedeInvitar;
  btn.textContent = lleno ? `Máximo ${max} familiares` : 'Invitar familiar';

  const list = $('#familiaList');
  if (!n){ list.innerHTML = '<div class="empty">Aún no has invitado a nadie</div>'; return; }
  list.innerHTML = '';
  miFamiliaCache.slice().sort((a,b)=>normDom(a.nombre).localeCompare(normDom(b.nombre),'es')).forEach(f => {
    const susp = f.estado === 'suspendido';
    const tagEstado = susp ? `<span class="tag susp">Suspendido</span>` : `<span class="tag in">Activo</span>`;
    const tagCuenta = f.registrado ? `<span class="tag in">Registrado</span>` : `<span class="tag">Sin cuenta</span>`;
    const row = document.createElement('div'); row.className = 'row';
    row.innerHTML = `<div class="ri">${esc(((f.nombre||'?').trim()[0]||'?').toUpperCase())}</div>`
      + `<div class="rt"><div class="a">${esc(f.nombre)}</div>${f.telefono?`<div class="b">${esc(f.telefono)}</div>`:''}</div>`
      + `<div class="tags">${tagEstado}${tagCuenta}</div>`;
    list.appendChild(row);
    // Sin cuenta: puede REENVIAR el link (emite uno nuevo) o CANCELAR al familiar.
    if (!f.registrado){
      const wrap = document.createElement('div'); wrap.className = 'persona-acts';
      const r = document.createElement('button');
      r.className = 'row-act'; r.textContent = 'Reenviar';
      r.addEventListener('click', () => reenviarFamiliar(f, r));
      const c = document.createElement('button');
      c.className = 'row-act danger'; c.textContent = 'Cancelar';
      c.addEventListener('click', () => abrirFamiliarCancel(f));
      wrap.appendChild(r); wrap.appendChild(c); list.appendChild(wrap);
    }
  });
}
$('#newFamiliarBtn')?.addEventListener('click', () => {
  $('#faName').value = ''; $('#faTel').value = ''; $('#faErr').textContent = '';
  openSheet('#familiarOverlay');
});
$('#familiarOverlay')?.addEventListener('click', e => { if(e.target.id==='familiarOverlay') closeSheet('#familiarOverlay'); });
$('#saveFamiliarBtn')?.addEventListener('click', async () => {
  const nombre = $('#faName').value.trim();
  const telefono = $('#faTel').value.trim();
  $('#faErr').textContent = '';
  if (!nombre){ $('#faErr').textContent = 'Falta el nombre del familiar'; return; }
  if (!telefono){ $('#faErr').textContent = 'El teléfono es obligatorio'; return; }
  const btn = $('#saveFamiliarBtn'); btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>';
  try {
    // El Worker crea la persona familiar + token y valida el tope de 5 server-side.
    const r = await authedFetch('/invitaciones/familiar', { nombre, telefono });
    closeSheet('#familiarOverlay');
    await cargarMiFamilia();
    const url = new URL('registro.html', location.href).href + '#' + r.token;
    const texto = `Hola ${nombre}, te invito a registrarte en la app de Cerrada Mojave como parte de mi familia. Abre este enlace (vence en 72 h):`;
    await compartirInvitacion({ title:'Cerrada Mojave', text: texto, url }, { titulo: nombre, sub:'Familiar' });
  } catch(e){
    $('#faErr').textContent = e.message || 'No se pudo generar la invitación';
  } finally { btn.disabled = false; btn.textContent = 'Generar invitación'; }
});

/* Reenviar: re-emite el link de un familiar "Sin cuenta" (el jefe perdió el mensaje). El
   Worker emite un token nuevo e invalida el anterior; mismas validaciones que invitar. */
async function reenviarFamiliar(f, btn){
  const orig = btn.textContent; btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>';
  try {
    const r = await authedFetch('/invitaciones/familiar-reenviar', { id: f.id });
    toast('Link nuevo generado. El anterior ya no sirve.', 'ok');
    const url = new URL('registro.html', location.href).href + '#' + r.token;
    const texto = `Hola ${f.nombre}, te invito a registrarte en la app de Cerrada Mojave como parte de mi familia. Abre este enlace (vence en 72 h):`;
    await compartirInvitacion({ title:'Cerrada Mojave', text: texto, url }, { titulo: f.nombre, sub:'Familiar' });
  } catch(e){
    toast(e.message || 'No se pudo reenviar la invitación', 'bad');
  } finally { btn.disabled = false; btn.textContent = orig; }
}

let familiarCancelId = null;
function abrirFamiliarCancel(f){
  familiarCancelId = f.id;
  $('#familiarCancelInfo').innerHTML = `<b>${esc(f.nombre||'')}</b>${f.telefono?' · '+esc(f.telefono):''}`;
  $('#familiarCancelErr').textContent = '';
  openSheet('#familiarCancelOverlay');
}
$('#familiarCancelClose')?.addEventListener('click', () => closeSheet('#familiarCancelOverlay'));
$('#familiarCancelOverlay')?.addEventListener('click', e => { if(e.target.id==='familiarCancelOverlay') closeSheet('#familiarCancelOverlay'); });
$('#familiarCancelConfirm')?.addEventListener('click', async () => {
  if (!familiarCancelId) return;
  const btn = $('#familiarCancelConfirm'); btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>';
  try {
    await authedFetch('/personas/familiar-cancelar', { id: familiarCancelId });
    toast('Familiar cancelado', 'bad');
    closeSheet('#familiarCancelOverlay');
    await cargarMiFamilia();
  } catch(e){
    $('#familiarCancelErr').textContent = e.message || 'No se pudo cancelar';
  } finally { btn.disabled = false; btn.textContent = 'Sí, cancelar'; }
});

/* ====================== FINANZAS ====================== */
let movType = 'ingreso';
let finTodos = [];      // TODOS los movimientos de los últimos 6 meses, cancelados incluidos (lista visible)
let finCache = [];      // solo los VIGENTES — base de TODOS los cálculos: caja, gráficas, PDF, cobranza.
                        // Un cancelado sigue visible (tachado) en la lista, pero nunca suma.
let finMonths = [];     // [{key,start,end,label}] los últimos 6 meses, más viejo primero
let finCharts = { barras:null, pastel:null, linea:null };
// Paleta compartida: colores de las categorías en la dona del PDF y su leyenda nativa (mismo orden,
// gama sobria para papel: dorado, ocre, terracota, verde seco + tonos tierra de respaldo).
const DOUGHNUT_PALETTE = ['#d4a017', '#d97706', '#b7472a', '#6b8e63', '#8a6d3b', '#94a3b8'];
function hexToRgb(hex){
  const n = parseInt(hex.replace('#',''), 16);
  return [(n>>16)&255, (n>>8)&255, n&255];
}
// Identidad visual del PDF "despacho contable" (FASE 0 del plan maestro).
const PDF = {
  text: [17,24,39],        // #111827 — nunca negro puro
  secondary: [100,116,139],// #64748b
  notes: [156,163,175],    // #9ca3af
  gold: [212,160,23],      // #d4a017 — solo filetes/acentos
  green: [15,118,110],     // #0f766e — ingresos
  red: [153,27,27],        // #991b1b — gastos
  navy: [30,58,138],       // #1e3a8a — saldo
  grid: [226,232,240],     // #e2e8f0
  zebra: [248,250,252],    // #f8fafc
  badgeGreenBg: [204,251,241], badgeGreenFg: [15,118,110],
  badgeRedBg: [254,226,226], badgeRedFg: [153,27,27],
  MARGIN: 25 * 72 / 25.4,  // 25mm en pt
};
/* folio determinista FIN-YYYYMM-### — no hay contador persistente en Firestore (fuera de alcance
   escribir uno sin autorización), así que se deriva de mes+totales: estable mientras no cambien
   los movimientos del mes, único por combinación mes/monto. */
function folioDelMes(curKey, cobrado, gastos){
  const seed = curKey.replace('-','') + '|' + Math.round(cobrado) + '|' + Math.round(gastos);
  let hash = 0;
  for (let i=0;i<seed.length;i++) hash = (hash*31 + seed.charCodeAt(i)) >>> 0;
  const num = (hash % 900) + 100;
  return `FIN-${curKey.replace('-','')}-${num}`;
}

function monthRange(){
  const now = new Date();
  const start = new Date(now.getFullYear(), now.getMonth(), 1);
  const end = new Date(now.getFullYear(), now.getMonth()+1, 1);
  return { start, end, label: now.toLocaleDateString('es-MX',{month:'long',year:'numeric'}) };
}
function last6Months(){
  const now = new Date();
  const arr = [];
  for (let i=5; i>=0; i--){
    const d = new Date(now.getFullYear(), now.getMonth()-i, 1);
    arr.push({
      key: d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0'),
      start: new Date(d.getFullYear(), d.getMonth(), 1),
      end: new Date(d.getFullYear(), d.getMonth()+1, 1),
      label: d.toLocaleDateString('es-MX',{month:'short',year:'2-digit'}),
    });
  }
  return arr;
}
const money = n => '$'+(n||0).toLocaleString('es-MX',{minimumFractionDigits:0,maximumFractionDigits:2});
const monthKey = ts => { const d = ts.toDate ? ts.toDate() : new Date(ts); return d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0'); };

function watchFinanzas(){
  if (unsubFin) unsubFin();
  const isStaff = enModoStaff();
  // El aviso de corte es de la propia casa: en modo staff se oculta siempre (abajo se vuelve a
  // mostrar si aplica, vía cargarMiEstadoCuenta) — evita que quede un aviso viejo pegado al
  // cambiar de modo residente a admin con el botón modoBtn (no recarga la app).
  renderAvisoCorte(null);

  // Detalle de movimientos, gráficas y morosos: solo staff. Residentes/esclavos ya no
  // leen "finanzas" directo (bloqueado por Firestore rules) — reciben solo el agregado
  // del Worker, nunca el detalle por casa.
  $('#newMovBtn').style.display = isStaff ? 'block' : 'none';
  $('#finCharts').classList.toggle('hidden', !isStaff);
  $('#finActionsMain').classList.toggle('hidden', !isStaff);
  $('#finActionsShare').classList.toggle('hidden', !isStaff);
  $('#morososSection').classList.toggle('hidden', !isStaff);
  $('#finDetalle').classList.toggle('hidden', !isStaff);
  // Estado de cuenta propio (cuota + adeudo acumulado): solo residente/familiar, nunca staff
  // en modo admin (ese ve el padrón completo en Gestión/cobranza, no su propia casa aquí).
  $('#miEstadoCuenta').classList.toggle('hidden', isStaff);

  finMonths = last6Months();
  const { label } = monthRange();
  $('#finMonth').textContent = 'Finanzas · ' + label;

  if (isStaff){
    // FASE 6.5: el padrón alimenta los dropdowns; la cobranza (termómetro + listas pagaron/
    // sin pago) la calcula el Worker. Carga el padrón primero (para el dropdown de detalle)
    // y luego la cobranza.
    cargarPersonas().then(() => cargarCobranza());
    unsubFin = db.collection('finanzas')
      .where('ts','>=',finMonths[0].start)
      .orderBy('ts','desc').limit(1200)
      .onSnapshot(snap => {
        finTodos = [];
        snap.forEach(doc => finTodos.push({ id: doc.id, ...doc.data() }));
        finCache = finTodos.filter(m => !esCanceladoMov(m));
        renderFinanzas();
      }, err => { console.error(err); $('#movList').innerHTML='<div class="empty">Sin acceso a finanzas</div>'; });
  } else {
    loadResumenResidente();
    cargarMiEstadoCuenta();
  }
}

/* -------- resumen agregado para residentes/esclavos (vía Worker) -------- */
async function loadResumenResidente(){
  try {
    const r = await authedFetch('/finanzas/resumen', {});
    $('#finCobrado').textContent = money(r.ingreso);
    $('#finGastos').textContent = money(r.egreso);
    $('#finCaja').textContent = money(r.balance);
    renderTermometro(r.pagaron, r.totalCasas);
  } catch(e){
    console.error(e);
    $('#thermText').textContent = 'No se pudo cargar la información financiera.';
  }
}

/* -------- mi estado de cuenta (cuota mensual + adeudo acumulado) — vía Worker, siempre la
   propia casa de quien llama (el Worker nunca confía en un parámetro del cliente). -------- */
async function cargarMiEstadoCuenta(){
  const el = $('#miEstadoCuentaBody');
  try {
    // /finanzas/estado-cuenta trae el adeudo (lógica intacta, no se toca); /config/cobranza
    // trae linkPago aparte, porque el link es config global, no algo por-casa.
    const [r, cfg] = await Promise.all([
      authedFetch('/finanzas/estado-cuenta', {}),
      authedFetch('/config/cobranza', {}),
    ]);

    renderAvisoCorte(r.avisoCorte);
    refrescarAvisoPago(true);   // el usuario acaba de ver su estado de cuenta/pagos: aviso al día

    if (r.alCorriente){
      el.innerHTML = `<p class="vnote" style="margin:0;color:var(--ok);font-size:14px">✅ Estás al corriente.</p>
         <p class="vnote" style="margin:6px 0 0">Cuota mensual: ${money(r.cuotaMensual)}</p>`;
      return;
    }

    const linkPago = (cfg.linkPago || '').trim();
    // El botón SOLO abre el link externo de pago en una pestaña nueva (target="_blank" +
    // rel="noopener"); la app NUNCA recibe, procesa ni guarda ningún dato de tarjeta. Cuando el
    // residente pague, el abono en Finanzas lo sigue registrando el staff a mano (como ya
    // funciona hoy) — esto todavía NO incluye confirmación automática del pago.
    const pagoHtml = linkPago
      ? `<p class="vnote" style="margin:10px 0 0">Tu adeudo es de <b style="color:var(--text)">${money(r.adeudo)}</b>. Al pagar, escribe exactamente ese monto en la página de pago.</p>
         <a class="btn-primary" style="display:block;text-align:center;margin-top:10px;text-decoration:none" href="${esc(linkPago)}" target="_blank" rel="noopener">Pagar cuota</a>`
      : `<p class="vnote" style="margin:10px 0 0">Pago en línea próximamente disponible. Mientras tanto, consulta con administración cómo ponerte al corriente.</p>`;

    el.innerHTML = `<div class="fin-val bad" style="font-size:22px">${money(r.adeudo)}</div>
         <p class="vnote" style="margin:6px 0 0">Adeudo acumulado · cuota mensual ${money(r.cuotaMensual)} · ${r.mesesTranscurridos} ${r.mesesTranscurridos===1?'mes':'meses'}</p>
         ${pagoHtml}`;
  } catch(e){
    console.error('estado-cuenta', e);
    el.innerHTML = '<div class="empty">No se pudo cargar tu estado de cuenta.</div>';
    renderAvisoCorte(null);
  }
}

/* Aviso global de corte por mora (banner fuera de las tabpanes, visible en cualquier pestaña
   — ver #avisoCorteBanner en index.html). avisoCorte llega en la respuesta de
   /finanzas/estado-cuenta, recalculado por el Worker en cada carga; null lo oculta. */
function renderAvisoCorte(avisoCorte){
  const el = $('#avisoCorteBanner');
  if (!avisoCorte){ el.classList.add('hidden'); el.innerHTML = ''; return; }
  const texto = avisoCorte.horasRestantes > 0
    ? `⚠️ No te quedes sin servicio. Tus permisos se cancelarán en ${avisoCorte.horasRestantes} horas por falta de pago.`
    : `⚠️ No te quedes sin servicio. Tus permisos se cancelarán hoy por falta de pago.`;
  el.innerHTML = `<b>${texto}</b>`;
  el.classList.remove('hidden');
}

/* -------- termómetro "X de Y casas pagaron" (compartido staff/residente) -------- */
function renderTermometro(pagaron, totalCasas){
  const fill = $('#thermFill');
  if (!totalCasas){
    fill.style.width = '0%';
    fill.className = 'therm-fill';
    const isStaff = enModoStaff();
    $('#thermText').textContent = isStaff
      ? 'Da de alta casas en Gestión para activar el termómetro.'
      : 'El termómetro aún no está disponible.';
    return;
  }
  const pct = Math.round((pagaron / totalCasas) * 100);
  const color = pct >= 80 ? 'ok' : pct >= 50 ? 'warn' : 'bad';
  fill.style.width = Math.min(pct, 100) + '%';
  fill.className = 'therm-fill therm-' + color;
  $('#thermText').textContent = `${pagaron} de ${totalCasas} casas pagaron (${pct}%)`;
}

/* -------- Map(domicilioNorm → pago) de casas que pagaron Cuota este mes, desde finCache.
   Solo lo usa "Consultar casa (detalle)" para mostrar folio/monto/fecha del pago; el conteo
   de la cobranza (termómetro + listas) lo hace el Worker, no esto. -------- */
function pagosPorCasaDelMes(){
  const curKey = monthKey(new Date());
  const map = new Map();
  finCache.forEach(m => {
    if (m.tipo==='ingreso' && (m.categoria||'')==='Cuota' && monthKey(m.ts)===curKey && m.casa) {
      const k = normDom(m.casa);
      if (!map.has(k)) map.set(k, m);   // finCache viene desc por ts → conserva el más reciente
    }
  });
  return map;
}

/* -------- cobranza del mes (solo staff): DOS listas colapsables (pagaron / sin pago),
   sin seleccionar nada. Universo = TODAS las casas (jefes activos Y suspendidos); las
   suspendidas llevan etiqueta. El conteo lo hace el Worker (/finanzas/cobranza), no el
   frontend, para que termómetro y listas nunca diverjan. -------- */
let cobranzaCache = { pagaron: [], sinPago: [], totalCasas: 0 };
let pagaronExpandido = false, sinPagoExpandido = false;

async function cargarCobranza(){
  try {
    const r = await authedFetch('/finanzas/cobranza', {});
    cobranzaCache = { pagaron: r.pagaron || [], sinPago: r.sinPago || [], totalCasas: r.totalCasas || 0 };
  } catch(e){ console.error('cargarCobranza', e); cobranzaCache = { pagaron: [], sinPago: [], totalCasas: 0 }; }
  renderCobranza();
}
/* una fila de casa: domicilio + nombre del jefe (+ etiqueta Suspendido si aplica) */
function casaRowCobranza(c){
  const tag = c.suspendido ? '<span class="tag susp">Suspendido</span>' : '';
  // Adeudo acumulado (cuota fija, PARTE 4): solo se etiqueta si hay algo pendiente.
  const adeudoTag = c.adeudo > 0 ? `<span class="tag out">${money(c.adeudo)}</span>` : '';
  return `<div class="row"><div class="rt"><div class="a">${esc(c.domicilio)}</div>`
    + `${c.nombre?`<div class="b">${esc(c.nombre)}</div>`:''}</div>${adeudoTag}${tag}</div>`;
}
function renderCobranza(){
  poblarConsultaCasa();
  const { pagaron, sinPago, totalCasas } = cobranzaCache;
  // Termómetro (staff) con el conteo del Worker: denominador = TODAS las casas.
  renderTermometro(pagaron.length, totalCasas);

  $('#pagaronCount').textContent = `✅ Pagaron (${pagaron.length})`;
  $('#sinPagoCount').textContent = `❌ Sin pago (${sinPago.length})`;
  $('#pagaronList').innerHTML = pagaron.length
    ? pagaron.map(casaRowCobranza).join('')
    : '<div class="empty">Nadie ha pagado aún este mes</div>';
  $('#sinPagoList').innerHTML = sinPago.length
    ? sinPago.map(casaRowCobranza).join('')
    : (totalCasas ? '<div class="empty">Todas las casas están al corriente</div>'
                  : '<div class="empty">Da de alta casas en Gestión</div>');
  $('#pagaronList').classList.toggle('hidden', !pagaronExpandido);
  $('#pagaronToggle').classList.toggle('abierto', pagaronExpandido);
  $('#sinPagoList').classList.toggle('hidden', !sinPagoExpandido);
  $('#sinPagoToggle').classList.toggle('abierto', sinPagoExpandido);
}
$('#pagaronToggle')?.addEventListener('click', () => {
  pagaronExpandido = !pagaronExpandido;
  $('#pagaronList').classList.toggle('hidden', !pagaronExpandido);
  $('#pagaronToggle').classList.toggle('abierto', pagaronExpandido);
});
$('#sinPagoToggle')?.addEventListener('click', () => {
  sinPagoExpandido = !sinPagoExpandido;
  $('#sinPagoList').classList.toggle('hidden', !sinPagoExpandido);
  $('#sinPagoToggle').classList.toggle('abierto', sinPagoExpandido);
});

/* -------- consultar el detalle de un domicilio (solo staff). Lista TODAS las casas
   (activas y suspendidas); las suspendidas se marcan en la opción. -------- */
function poblarConsultaCasa(){
  const sel = $('#consultaCasaSel');
  const casas = jefes().slice().sort((a,b)=>a.domicilio.localeCompare(b.domicilio,'es',{numeric:true}));
  const prev = sel.value;
  sel.innerHTML = '';
  if (!casas.length){ sel.appendChild(new Option('—','')); renderConsultaCasa(); return; }
  sel.appendChild(new Option('Elige un domicilio…',''));
  casas.forEach(v => sel.appendChild(new Option(   // new Option escapa seguro
    v.estado === 'suspendido' ? v.domicilio + ' (suspendido)' : v.domicilio, v.domicilio)));
  if (prev) sel.value = prev;
  renderConsultaCasa();
}
function renderConsultaCasa(){
  const box = $('#consultaCasaResult');
  const casa = $('#consultaCasaSel').value;
  if (!casa){ box.classList.add('hidden'); box.classList.remove('pagado'); return; }
  const pago = pagosPorCasaDelMes().get(normDom(casa));
  box.classList.remove('hidden');
  if (pago){
    box.classList.add('pagado');
    box.innerHTML = `<div class="a">${esc(casa)} · <b>pagó</b></div>`
      + `<div class="sub">${esc(pago.folioRecibo||'sin folio')} · ${money(pago.monto)} · ${fmtTime(pago.ts)}</div>`;
  } else {
    box.classList.remove('pagado');
    box.innerHTML = `<div class="a">${esc(casa)} · sin pago este mes</div>`
      + `<div class="sub">No hay Cuota registrada para este domicilio en el mes en curso.</div>`;
  }
}
$('#consultaCasaSel').addEventListener('change', renderConsultaCasa);

function groupByMonth(){
  const map = {};
  finMonths.forEach(m => map[m.key] = { ingreso:0, gasto:0 });
  finCache.forEach(m => {
    const k = monthKey(m.ts);
    if (!map[k]) return; // fuera de la ventana de 6 meses visible
    if (m.tipo==='ingreso') map[k].ingreso += m.monto; else map[k].gasto += m.monto;
  });
  return map;
}

function renderCmp(el, cur, prev, higherIsBetter){
  if (!cur && !prev){ el.innerHTML = '<span class="muted">Sin datos mes pasado</span>'; return; }
  if (!prev){ el.innerHTML = '<span class="muted">Sin datos mes pasado</span>'; return; }
  const pct = ((cur - prev) / prev) * 100;
  const up = pct >= 0;
  const good = higherIsBetter ? up : !up;
  el.innerHTML = `<span class="${good?'ok':'bad'}">${up?'▲':'▼'}${Math.abs(pct).toFixed(0)}% vs mes pasado</span>`;
}

function renderFinanzas(){
  const byMonth = groupByMonth();
  const curKey = finMonths[finMonths.length-1].key;
  const prevKey = finMonths[finMonths.length-2].key;
  const cur = byMonth[curKey], prev = byMonth[prevKey];

  const cobrado = cur.ingreso, gastos = cur.gasto, caja = cur.ingreso - cur.gasto;
  const prevCaja = prev.ingreso - prev.gasto;

  $('#finCobrado').textContent = money(cobrado);
  $('#finGastos').textContent = money(gastos);
  $('#finCaja').textContent = money(caja);

  renderCmp($('#cmpCobrado'), cobrado, prev.ingreso, true);
  renderCmp($('#cmpGastos'), gastos, prev.gasto, false);
  renderCmp($('#cmpCaja'), caja, prevCaja, true);

  renderFinCharts(byMonth, curKey);
  populateFiltros();
  filterAndRenderMovs();
  // Un movimiento nuevo puede cambiar quién pagó → recalcula la cobranza en el Worker.
  cargarCobranza();
}

/* -------- gastos por categoría del mes (compartido: dashboard + PDF) -------- */
function categoriasDelMes(curKey){
  const catTotals = {};
  finCache.filter(m => m.tipo==='egreso' && monthKey(m.ts)===curKey).forEach(m => {
    const c = m.categoria || 'Otro';
    catTotals[c] = (catTotals[c]||0) + m.monto;
  });
  const labels = Object.keys(catTotals);
  return {
    labels,
    data: labels.map(c=>catTotals[c]),
    hasData: labels.length > 0,
  };
}

/* meses con al menos un movimiento (para no graficar 5 meses vacíos en el PDF) */
function mesesConMovimientos(byMonth){
  const activos = finMonths.filter(m => byMonth[m.key].ingreso > 0 || byMonth[m.key].gasto > 0);
  const usados = activos.length ? activos : [finMonths[finMonths.length-1]];
  return {
    labels: usados.map(m => m.label),
    ingresos: usados.map(m => byMonth[m.key].ingreso),
    gastos: usados.map(m => byMonth[m.key].gasto),
  };
}

/* -------- gráficas (Chart.js) -------- */
function renderFinCharts(byMonth, curKey){
  if (typeof Chart === 'undefined') return;
  const gold='#F5A623', goldSoft='#FFC15A', ok='#34d399', bad='#f87171', muted='#a1a1aa', text='#f5f5f4', line='#2B2B45';

  const labels = finMonths.map(m => m.label);
  const ingresos = finMonths.map(m => byMonth[m.key].ingreso);
  const gastosArr = finMonths.map(m => byMonth[m.key].gasto);
  const saldos = finMonths.map(m => byMonth[m.key].ingreso - byMonth[m.key].gasto);

  if (finCharts.barras) finCharts.barras.destroy();
  finCharts.barras = new Chart($('#chartBarras'), {
    type:'bar',
    data:{ labels, datasets:[
      { label:'Ingresos', data:ingresos, backgroundColor:ok, borderRadius:4, maxBarThickness:26 },
      { label:'Gastos', data:gastosArr, backgroundColor:bad, borderRadius:4, maxBarThickness:26 },
    ]},
    options:{ responsive:true, plugins:{ legend:{ labels:{ color:text } } },
      scales:{ x:{ ticks:{ color:muted }, grid:{ color:line } }, y:{ ticks:{ color:muted }, grid:{ color:line }, beginAtZero:true } } }
  });

  const { labels: catLabels, data: catData, hasData } = categoriasDelMes(curKey);
  const palette = [gold, goldSoft, ok, bad, muted, '#9c7d1e', '#3b82f6'];

  if (finCharts.pastel){ finCharts.pastel.destroy(); finCharts.pastel = null; }
  $('#chartPastel').classList.toggle('hidden', !hasData);
  $('#chartPastelEmpty').classList.toggle('hidden', hasData);
  if (hasData){
    finCharts.pastel = new Chart($('#chartPastel'), {
      type:'doughnut',
      data:{
        labels: catLabels,
        datasets:[{
          data: catData,
          backgroundColor: catLabels.map((_,i)=>palette[i%palette.length]),
        }],
      },
      options:{ responsive:true, cutout:'55%', plugins:{ legend:{ position:'bottom', labels:{ color:text, boxWidth:12 } } } }
    });
  }

  if (finCharts.linea) finCharts.linea.destroy();
  finCharts.linea = new Chart($('#chartLinea'), {
    type:'line',
    data:{ labels, datasets:[{
      label:'Saldo en caja', data:saldos, borderColor:gold, backgroundColor:'rgba(245,166,35,.15)',
      fill:true, tension:.35, pointBackgroundColor:gold,
    }]},
    options:{ responsive:true, plugins:{ legend:{ display:false } },
      scales:{ x:{ ticks:{ color:muted }, grid:{ color:line } }, y:{ ticks:{ color:muted }, grid:{ color:line } } } }
  });
}
function resizeFinCharts(){
  requestAnimationFrame(()=> Object.values(finCharts).forEach(c => c && c.resize()));
}

/* -------- barras (Ingresos vs Gastos) en alta resolución, solo para el PDF --------
   Colores de la identidad "despacho contable" (verde/rojo oscuros, legibles en papel blanco).
   Sin leyenda horneada — esa va como texto nativo (ver dibujarLeyendaSeries). Valores encima
   de cada barra vía plugin propio (afterDatasetsDraw), grid casi invisible. */
async function renderBarrasHiRes(labels, ingresos, gastos){
  const off = document.createElement('canvas');
  off.width = 1400; off.height = 700;

  const valueLabelsPlugin = {
    id: 'valueLabels',
    afterDatasetsDraw(chart){
      const { ctx } = chart;
      chart.data.datasets.forEach((dataset, di) => {
        const meta = chart.getDatasetMeta(di);
        meta.data.forEach((bar, i) => {
          const value = dataset.data[i];
          if (!value) return;
          ctx.save();
          ctx.fillStyle = '#111827';
          ctx.font = 'bold 20px Helvetica, Arial, sans-serif';
          ctx.textAlign = 'center';
          ctx.fillText(money(value), bar.x, bar.y - 12);
          ctx.restore();
        });
      });
    },
  };

  const chart = new Chart(off, {
    type:'bar',
    data:{ labels, datasets:[
      { label:'Ingresos', data:ingresos, backgroundColor:'#0f766e', borderRadius:6, maxBarThickness:46 },
      { label:'Gastos', data:gastos, backgroundColor:'#991b1b', borderRadius:6, maxBarThickness:46 },
    ]},
    options:{
      responsive:false, animation:false,
      layout:{ padding:{ top:36 } },
      plugins:{ legend:{ display:false }, tooltip:{ enabled:false } },
      scales:{
        x:{ ticks:{ color:'#64748b', font:{ size:22 } }, grid:{ display:false } },
        y:{ ticks:{ color:'#64748b', font:{ size:20 } }, grid:{ color:'#e2e8f0' }, beginAtZero:true },
      },
    },
    plugins: [valueLabelsPlugin],
  });
  await new Promise(r => setTimeout(r, 0));
  const dataUrl = off.toDataURL('image/png');
  chart.destroy();
  return dataUrl;
}
/* leyenda nativa simple (swatch + texto) para series de una gráfica, ej. Ingresos/Gastos */
function dibujarLeyendaSeries(doc, W, gy, items){
  const itemW = 110;
  let x = (W - items.length*itemW) / 2;
  items.forEach(({label, color}) => {
    doc.setFillColor(...hexToRgb(color));
    doc.roundedRect(x, gy, 12, 12, 3, 3, 'F');
    doc.setFont('helvetica','bold'); doc.setFontSize(10); doc.setTextColor(...PDF.text);
    doc.text(label, x + 18, gy + 10);
    x += itemW;
  });
  return gy + 12 + 14;
}

/* -------- doughnut de gastos en alta resolución, solo para el PDF --------
   Solo el círculo (+ total al centro): sin leyenda ni etiquetas de categoría horneadas en la
   imagen — esas van como texto nativo del PDF (ver dibujarLeyendaCategorias), para que queden
   nítidas a cualquier zoom en vez de pixeleadas dentro de un PNG. */
async function renderPastelDoughnutHiRes(catLabels, catData, hasData, totalTexto){
  // sin gastos: anillo gris de relleno solo dentro de esta imagen (el dato falso no sale de aquí)
  if (!hasData){ catLabels = ['Sin gastos']; catData = [1]; }
  const SIZE = 900; // px reales del canvas (cuadrado, > 800 mínimo pedido)
  const off = document.createElement('canvas');
  off.width = SIZE; off.height = SIZE;

  const shadowPlugin = {
    id: 'donutShadow',
    beforeDatasetDraw(chart){
      const ctx = chart.ctx;
      ctx.save();
      ctx.shadowColor = 'rgba(0,0,0,.30)';
      ctx.shadowBlur = 22;
      ctx.shadowOffsetX = 0;
      ctx.shadowOffsetY = 8;
    },
    afterDatasetDraw(chart){ chart.ctx.restore(); },
  };
  const centerTextPlugin = {
    id: 'centerText',
    afterDraw(chart){
      const { ctx, chartArea } = chart;
      if (!chartArea) return;
      const cx = (chartArea.left + chartArea.right) / 2;
      const cy = (chartArea.top + chartArea.bottom) / 2;
      ctx.save();
      ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
      ctx.fillStyle = '#111827';
      ctx.font = 'bold 46px Helvetica, Arial, sans-serif';
      ctx.fillText(totalTexto, cx, cy - 16);
      ctx.fillStyle = '#64748b';
      ctx.font = '24px Helvetica, Arial, sans-serif';
      ctx.fillText('Total gastos', cx, cy + 28);
      ctx.restore();
    },
  };

  const chart = new Chart(off, {
    type:'doughnut',
    data:{
      labels: catLabels,
      datasets:[{
        data: catData,
        backgroundColor: hasData ? catLabels.map((_,i)=>DOUGHNUT_PALETTE[i%DOUGHNUT_PALETTE.length]) : ['#d8d8d8'],
        borderColor:'#ffffff',
        borderWidth:4,
      }],
    },
    options:{
      responsive:false,
      animation:false,
      devicePixelRatio:1,
      cutout:'55%',
      layout:{ padding:24 },
      plugins:{ legend:{ display:false }, tooltip:{ enabled:false } },
    },
    plugins: [shadowPlugin, centerTextPlugin],
  });

  // Con animation:false, Chart.js ya pintó de forma síncrona. Se usa setTimeout (no rAF)
  // porque rAF nunca se dispara si la pestaña está en segundo plano al generar el PDF.
  await new Promise(r => setTimeout(r, 0));
  const dataUrl = off.toDataURL('image/png');
  chart.destroy();
  return dataUrl;
}

/* leyenda nativa del PDF: cuadrito de color + nombre + porcentaje + monto, texto real (no imagen).
   `x0` permite dibujarla a la derecha de la dona en vez de a todo el ancho. */
function dibujarLeyendaCategorias(doc, W, gy, catLabels, catData, hasData, x0, x1){
  x0 = x0 ?? 40; x1 = x1 ?? (W - 40);
  if (!hasData){
    doc.setFont('helvetica','normal'); doc.setFontSize(10); doc.setTextColor(...PDF.notes);
    doc.text('Sin gastos registrados este mes.', x0, gy + 14);
    return gy + 26;
  }
  const total = catData.reduce((a,b)=>a+b, 0) || 1;
  const rowH = 24;
  catLabels.forEach((catLabel, i) => {
    const y = gy + i*rowH;
    doc.setFillColor(...hexToRgb(DOUGHNUT_PALETTE[i % DOUGHNUT_PALETTE.length]));
    doc.roundedRect(x0, y, 12, 12, 3, 3, 'F');
    doc.setFont('helvetica','bold'); doc.setFontSize(10.5); doc.setTextColor(...PDF.text);
    doc.text(catLabel, x0 + 18, y + 10);
    const pct = Math.round(catData[i] / total * 100);
    doc.setFont('courier','bold'); doc.setFontSize(9.5); doc.setTextColor(...PDF.secondary);
    doc.text(`${pct}% · ${money(catData[i])}`, x1, y + 10, { align:'right' });
  });
  return gy + catLabels.length*rowH + 12;
}

/* indicador de salud financiera: barra proporción gastos/ingresos + línea de lectura */
function dibujarSaludFinanciera(doc, W, gy, cobrado, gastos){
  const x0 = PDF.MARGIN, x1 = W - PDF.MARGIN, barW = x1 - x0, barH = 8;
  if (!(cobrado > 0)){
    doc.setFont('helvetica','normal'); doc.setFontSize(9); doc.setTextColor(...PDF.notes);
    doc.text('Sin datos suficientes para el indicador de salud financiera este mes.', x0, gy + 10);
    return gy + 24;
  }
  const pct = Math.min(gastos / cobrado, 1);
  const color = pct < 0.5 ? PDF.green : pct < 0.8 ? PDF.gold : PDF.red;
  doc.setFillColor(...PDF.grid);
  doc.roundedRect(x0, gy, barW, barH, 4, 4, 'F');
  doc.setFillColor(...color);
  doc.roundedRect(x0, gy, Math.max(barW*pct, barH), barH, 4, 4, 'F');
  doc.setFont('helvetica','normal'); doc.setFontSize(9.5); doc.setTextColor(...PDF.secondary);
  const pctTxt = Math.round(pct*100);
  doc.text(`Los gastos representan el ${pctTxt}% de lo recaudado este mes.`, x0, gy + barH + 14);
  return gy + barH + 28;
}

/* -------- filtros (100% client-side sobre finCache) -------- */
// Las 8 categorías fijas siempre visibles en el filtro (mismo orden que el <select> de registro).
const CATEGORIAS_FIJAS = ['Cuota','Multa','Mantenimiento','Seguridad','Limpieza','Mejoras','Servicios','Otro'];
function populateFiltros(){
  const selCat = $('#filtroCategoria');
  const curCat = selCat.value;
  // Fijas primero; si algún movimiento viejo trae una categoría fuera de la lista, se agrega al final.
  const extras = [...new Set(finTodos.map(m=>m.categoria||'Otro'))].filter(c=>!CATEGORIAS_FIJAS.includes(c)).sort();
  const cats = [...CATEGORIAS_FIJAS, ...extras];
  selCat.innerHTML = '<option value="">Todas las categorías</option>' + cats.map(c=>`<option value="${esc(c)}">${esc(c)}</option>`).join('');
  selCat.value = cats.includes(curCat) ? curCat : '';

  const selMes = $('#filtroMes');
  const curMes = selMes.value;
  selMes.innerHTML = '<option value="">Todos los meses</option>' + finMonths.slice().reverse().map(m=>`<option value="${m.key}">${esc(m.label)}</option>`).join('');
  selMes.value = finMonths.some(m=>m.key===curMes) ? curMes : '';
}
function filterAndRenderMovs(){
  const cat = $('#filtroCategoria').value;
  const mes = $('#filtroMes').value;
  let list = finTodos;   // la lista muestra también los cancelados (tachados)
  if (cat) list = list.filter(m => (m.categoria||'Otro') === cat);
  if (mes) list = list.filter(m => monthKey(m.ts) === mes);
  renderMovs(list);
}
$('#filtroCategoria').addEventListener('change', filterAndRenderMovs);
$('#filtroMes').addEventListener('change', filterAndRenderMovs);

/* ====================== FINANZAS PROTEGIDAS (front) ======================
   Un movimiento NUNCA se borra: se CANCELA con motivo (sigue visible, tachado, y no suma) o se
   CORRIGE (cancela el original y crea el corregido, ligados). Reactivar: solo master. Todo lo
   decide el Worker (permisos, ventana de meses, límite 5/hora); aquí solo se muestran u ocultan
   los botones — si el Worker dice que no, se enseña su mensaje tal cual. */
function esCanceladoMov(m){ return m && m.estado === 'cancelado'; }
// Referencia humana: el folio del recibo o, en gastos (sin folio), #ABC123. Mismo criterio que el Worker.
function refMov(m){ return (m && m.folioRecibo) || ('#' + String(m?.id || '').slice(0, 6).toUpperCase()); }
function refMovPorId(id){
  const m = finTodos.find(x => x.id === id);
  return m ? refMov(m) : ('#' + String(id || '').slice(0, 6).toUpperCase());
}
function mesesAtras(ts){
  const d = tsADate(ts), n = new Date();
  return (n.getFullYear() * 12 + n.getMonth()) - (d.getFullYear() * 12 + d.getMonth());
}
// Cosmético (el Worker revalida): staff cancela/corrige mes actual y anterior; master, cualquiera.
function puedeCancelarMov(m){
  if (!enModoStaff() || esCanceladoMov(m)) return false;
  return ME.rol === 'master' || mesesAtras(m.ts) <= 1;
}
function puedeReactivarMov(m){ return ME.rol === 'master' && esCanceladoMov(m); }

function renderMovs(movs){
  const list = $('#movList');
  if (!movs.length){ list.innerHTML = '<div class="empty">Sin movimientos</div>'; return; }
  list.innerHTML = '';
  movs.forEach(m => {
    const ing = m.tipo==='ingreso';
    const canc = esCanceladoMov(m);
    const row = document.createElement('div'); row.className = 'row' + (canc ? ' cancelado' : '');
    const folioLinea = (ing && m.folioRecibo) ? `<div class="mov-folio">${esc(m.folioRecibo)}${m.casa ? ' · '+esc(m.casa) : ''}</div>` : '';
    const ligas = (m.corrigeAId ? `<div class="mov-liga">Corrige a ${esc(refMovPorId(m.corrigeAId))}</div>` : '')
      + (m.corregidoPorId ? `<div class="mov-liga">Corregido por ${esc(refMovPorId(m.corregidoPorId))}</div>` : '');
    const cancLinea = canc
      ? `<div class="mov-liga bad">Cancelado: ${esc(m.motivoCancelacion || '')}${m.canceladoNombre ? ' · ' + esc(m.canceladoNombre) : ''}</div>` : '';
    row.innerHTML = `
      <div class="ri"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">${ing?'<path d="M12 19V5 M5 12l7-7 7 7"/>':'<path d="M12 5v14 M19 12l-7 7-7-7"/>'}</svg></div>
      <div class="rt"><div class="a">${esc(m.concepto||m.categoria)}${canc ? ' <span class="tag out">CANCELADO</span>' : ''}</div><div class="b">${esc(m.categoria)} · ${fmtTime(m.ts)}</div>${folioLinea}${ligas}${cancLinea}</div>
      <span class="mov-amt ${ing?'ok':'bad'}">${ing?'+':'−'}${money(m.monto)}</span>`;
    if (ing && m.folioRecibo){
      const act = document.createElement('button');
      act.className = 'row-act recibo'; act.textContent = 'Recibo';
      act.addEventListener('click', () => abrirReciboSheet(m));
      row.appendChild(act);
    }
    // Acciones (Corregir / Cancelar / Reactivar / historial del movimiento): solo staff.
    if (enModoStaff()){
      const more = document.createElement('button');
      more.className = 'row-act'; more.textContent = '⋯'; more.title = 'Acciones';
      more.setAttribute('aria-label', 'Acciones del movimiento');
      more.addEventListener('click', () => abrirMovAcciones(m));
      row.appendChild(more);
    }
    list.appendChild(row);
  });
}

/* -------- hoja de acciones de un movimiento -------- */
let movAccActual = null;
function abrirMovAcciones(m){
  movAccActual = m;
  const ing = m.tipo === 'ingreso';
  const canc = esCanceladoMov(m);
  $('#movAccTitle').textContent = `Movimiento ${refMov(m)}`;
  $('#movAccInfo').innerHTML =
    `<b>${ing?'+':'−'}${money(m.monto)}</b> · ${esc(m.categoria || 'Otro')} · ${esc(m.concepto || '')}<br>`
    + `${m.casa ? esc(m.casa) + ' · ' : ''}${fmtTime(m.ts)} · registró ${esc(m.creadoNombre || '—')}`
    + (canc ? `<br><span style="color:var(--bad)">CANCELADO · ${esc(m.motivoCancelacion || '')}${m.canceladoNombre ? ' · ' + esc(m.canceladoNombre) : ''}${m.canceladoTs ? ' · ' + fmtTime(m.canceladoTs) : ''}</span>` : '')
    + (m.corrigeAId ? `<br>Corrige a ${esc(refMovPorId(m.corrigeAId))}` : '')
    + (m.corregidoPorId ? `<br>Corregido por ${esc(refMovPorId(m.corregidoPorId))}` : '');
  const puede = puedeCancelarMov(m);
  $('#movAccCorregir').classList.toggle('hidden', !puede);
  $('#movAccCancelar').classList.toggle('hidden', !puede);
  $('#movAccReactivar').classList.toggle('hidden', !puedeReactivarMov(m));
  $('#movAccNota').textContent = (!canc && !puede && enModoStaff())
    ? 'Este movimiento es de hace más de un mes: solo el master puede cancelarlo o corregirlo.' : '';
  $('#movAccErr').textContent = '';
  $('#movAccHist').innerHTML = '<div class="empty">Cargando historial…</div>';
  openSheet('#movAccOverlay');
  cargarHistorialMov(m.id);
}
$('#movAccOverlay')?.addEventListener('click', e => { if (e.target.id==='movAccOverlay') closeSheet('#movAccOverlay'); });
$('#movAccCerrar')?.addEventListener('click', () => closeSheet('#movAccOverlay'));
$('#movAccCancelar')?.addEventListener('click', () => { closeSheet('#movAccOverlay'); abrirMovMotivo(movAccActual, 'cancelar'); });
$('#movAccReactivar')?.addEventListener('click', () => { closeSheet('#movAccOverlay'); abrirMovMotivo(movAccActual, 'reactivar'); });
$('#movAccCorregir')?.addEventListener('click', () => { closeSheet('#movAccOverlay'); abrirCorreccion(movAccActual); });

/* -------- hoja de motivo (cancelar / reactivar) — modal, no prompt nativo -------- */
let movMotivoCtx = null;   // { m, modo }
function abrirMovMotivo(m, modo){
  if (!m) return;
  movMotivoCtx = { m, modo };
  const cancelar = modo === 'cancelar';
  $('#movMotivoTitle').textContent = cancelar ? 'Cancelar movimiento' : 'Reactivar movimiento';
  $('#movMotivoInfo').innerHTML = `<b>${esc(refMov(m))}</b> · ${m.tipo==='ingreso'?'+':'−'}${money(m.monto)} · ${esc(m.concepto || m.categoria || '')}`;
  $('#movMotivoNota').textContent = cancelar
    ? 'No se borra: queda visible como CANCELADO (con su folio y este motivo) y deja de contar en la caja.'
    : 'Vuelve a contar en la caja. Queda registrado en el historial.';
  $('#movMotivoTxt').value = '';
  $('#movMotivoErr').textContent = '';
  $('#movMotivoConfirm').textContent = cancelar ? 'Sí, cancelar movimiento' : 'Sí, reactivar';
  openSheet('#movMotivoOverlay');
}
$('#movMotivoOverlay')?.addEventListener('click', e => { if (e.target.id==='movMotivoOverlay') closeSheet('#movMotivoOverlay'); });
$('#movMotivoCancel')?.addEventListener('click', () => closeSheet('#movMotivoOverlay'));
$('#movMotivoConfirm')?.addEventListener('click', async () => {
  if (!movMotivoCtx) return;
  const { m, modo } = movMotivoCtx;
  const motivo = $('#movMotivoTxt').value.trim();
  $('#movMotivoErr').textContent = '';
  if (motivo.length < 5){ $('#movMotivoErr').textContent = 'Escribe el motivo (mínimo 5 caracteres)'; return; }
  const btn = $('#movMotivoConfirm'); const original = btn.textContent;
  btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>';
  try {
    await authedFetch(modo === 'cancelar' ? '/finanzas/cancelar' : '/finanzas/reactivar', { id: m.id, motivo });
    toast(modo === 'cancelar' ? 'Movimiento cancelado' : 'Movimiento reactivado', modo === 'cancelar' ? 'bad' : 'ok');
    closeSheet('#movMotivoOverlay');
    // La lista se actualiza sola por el onSnapshot de finanzas.
  } catch(e){
    $('#movMotivoErr').textContent = e.message || 'No se pudo completar';
  } finally { btn.disabled = false; btn.textContent = original; }
});

/* -------- historial (finanzas_log): del movimiento (hoja de acciones) y general -------- */
const ACCION_LOG = { crear:'Registró', cancelar:'Canceló', corregir:'Corrigió', reactivar:'Reactivó',
  'marcar-recibo':'Recibo', limite:'⚠️ Bloqueo por límite', borrar:'Borró (sistema anterior)' };
function filaLog(l){
  const quien = `${l.nombre || l.uid || '—'}${l.rol ? ' (' + l.rol + ')' : ''}`;
  return `<div class="row"><div class="rt">`
    + `<div class="a">${esc(ACCION_LOG[l.accion] || l.accion)} · ${esc(quien)}</div>`
    + `<div class="b">${fmtTime(l.ts)}${l.migrado ? ' · migrado' : ''}</div>`
    + `<div class="mov-liga">${esc(l.resumen || '')}</div>`
    + (l.motivo ? `<div class="mov-liga">Motivo: ${esc(l.motivo)}</div>` : '')
    + `</div></div>`;
}
async function cargarHistorialMov(id){
  const box = $('#movAccHist');
  try {
    // Dos consultas de un solo campo (sin índice compuesto): entradas del movimiento y las que lo
    // mencionan como relacionado (la corrección se registra en el original, con el nuevo ligado).
    const [a, b] = await Promise.all([
      db.collection('finanzas_log').where('movId','==',id).get(),
      db.collection('finanzas_log').where('relacionadoId','==',id).get(),
    ]);
    const vistos = new Set(); const items = [];
    [...a.docs, ...b.docs].forEach(d => { if (!vistos.has(d.id)){ vistos.add(d.id); items.push(d.data()); } });
    items.sort((x, y) => tsADate(y.ts) - tsADate(x.ts));
    if (movAccActual?.id !== id) return;   // el usuario ya abrió otro movimiento
    box.innerHTML = items.length ? items.map(filaLog).join('')
      : '<div class="empty">Sin cambios registrados (anterior a la bitácora).</div>';
  } catch(e){
    console.error('historialMov', e);
    box.innerHTML = '<div class="empty">No se pudo cargar el historial.</div>';
  }
}
let finLogAbierto = false;
async function cargarHistorialFinanzas(){
  const box = $('#finLogList');
  box.innerHTML = '<div class="empty">Cargando…</div>';
  try {
    const snap = await db.collection('finanzas_log').orderBy('ts','desc').limit(100).get();
    box.innerHTML = snap.empty ? '<div class="empty">Sin cambios registrados todavía.</div>'
      : snap.docs.map(d => filaLog(d.data())).join('');
  } catch(e){
    console.error('historialFinanzas', e);
    box.innerHTML = '<div class="empty">No se pudo cargar el historial.</div>';
  }
}
$('#finLogToggle')?.addEventListener('click', () => {
  finLogAbierto = !finLogAbierto;
  $('#finLogList').classList.toggle('hidden', !finLogAbierto);
  $('#finLogToggle').classList.toggle('abierto', finLogAbierto);
  if (finLogAbierto) cargarHistorialFinanzas();
});

/* registrar movimiento (solo staff) — la misma hoja sirve para CORREGIR uno existente */
let movCorrigiendo = null;   // null = alta normal; movimiento original = modo corrección
/* FASE 4.5: casa obligatoria en TODO ingreso — cada recibo queda amarrado a una casa. */
function casaRequerida(){ return movType==='ingreso'; }
/* FASE 6.5: el campo Domicilio es un dropdown con TODAS las casas del padrón (jefes, activos
   y suspendidos, marcados "(suspendido)"; ya no números 1..N ni texto libre) — el Worker
   revalida contra el padrón. Las suspendidas van incluidas a propósito: un moroso que llega a
   pagar tiene que poder pagar, y ese pago de Cuota dispara la reactivación automática (solo
   si la suspensión fue por mora; una manual no se quita sola). */
function poblarCasaSelect(){
  const sel = $('#movCasa');
  const fuente = jefes();
  const activos = fuente.slice().sort((a,b)=>a.domicilio.localeCompare(b.domicilio,'es',{numeric:true}));
  const prev = sel.value;
  sel.innerHTML = '';
  if (!activos.length){
    sel.appendChild(new Option('Da de alta casas primero',''));
    sel.disabled = true; return;
  }
  sel.disabled = false;
  sel.appendChild(new Option('Selecciona el domicilio…',''));
  activos.forEach(v => sel.appendChild(new Option(
    v.estado === 'suspendido' ? v.domicilio + ' (suspendido)' : v.domicilio, v.domicilio)));
  if (prev) sel.value = prev;   // conserva selección si sigue en el padrón
}
function updateCasaField(){
  const req = casaRequerida();
  $('#movCasaField').classList.toggle('hidden', !req);
  if (req) poblarCasaSelect();
}
function setMovType(t){
  movType = t;
  $$('#movTypeSeg button').forEach(x => x.classList.toggle('sel', x.dataset.t === t));
}
/* Pone la hoja en modo alta o corrección (título, motivo, texto del botón). */
function modoFormMov(m){
  movCorrigiendo = m || null;
  $('#movSheetTitle').textContent = m ? `Corregir movimiento ${refMov(m)}` : 'Registrar movimiento';
  $('#movMotivoField').classList.toggle('hidden', !m);
  $('#movCorrigeNota').classList.toggle('hidden', !m);
  $('#saveMovBtn').textContent = m ? 'Guardar corrección' : 'Guardar movimiento';
  $('#movMotivo').value = '';
  $('#movErr').textContent = '';
}
$('#newMovBtn').addEventListener('click', ()=>{
  // Si lo último fue una corrección, se limpia para no arrastrar sus datos a un alta nueva.
  if (movCorrigiendo){ $('#movConcept').value = $('#movAmount').value = ''; $('#movCat').value = 'Cuota'; $('#movCasa').value = ''; setMovType('ingreso'); }
  modoFormMov(null); updateCasaField(); openSheet('#movOverlay');
});
/* "Corregir": abre la hoja con los datos del original; al guardar, el Worker cancela el original
   y crea el corregido en UNA transacción (y folio nuevo si es ingreso). */
function abrirCorreccion(m){
  if (!m) return;
  modoFormMov(m);
  setMovType(m.tipo === 'egreso' ? 'egreso' : 'ingreso');
  $('#movConcept').value = m.concepto || '';
  $('#movCat').value = m.categoria || 'Otro';
  if (!$('#movCat').value) $('#movCat').value = 'Otro';   // categoría vieja fuera de la lista
  $('#movAmount').value = m.monto != null ? String(m.monto) : '';
  $('#movCasa').value = '';
  updateCasaField();
  if (m.casa) $('#movCasa').value = m.casa;
  $('#movCorrigeNota').textContent = m.folioRecibo
    ? `El original (${m.folioRecibo}) quedará CANCELADO con su folio; el corregido llevará folio nuevo.`
    : 'El original quedará CANCELADO; el corregido lo reemplaza.';
  openSheet('#movOverlay');
}
$('#movOverlay').addEventListener('click', e => { if(e.target.id==='movOverlay') closeSheet('#movOverlay'); });
$('#movTypeSeg').addEventListener('click', e => {
  const b = e.target.closest('button'); if(!b) return;
  setMovType(b.dataset.t);
  updateCasaField();
});
$('#movCat').addEventListener('change', updateCasaField);
$('#saveMovBtn').addEventListener('click', saveMov);

async function saveMov(){
  const concepto = $('#movConcept').value.trim();
  const categoria = $('#movCat').value.trim() || 'Otro';
  const monto = parseFloat($('#movAmount').value);
  const casa = $('#movCasa').value;  // FASE 4.6: dropdown numérico → "1".."totalCasas" o ""
  const orig = movCorrigiendo;
  const motivo = $('#movMotivo').value.trim();
  $('#movErr').textContent = '';
  if (!concepto || !(monto > 0)){ $('#movErr').textContent = 'Falta concepto o monto válido'; return; }
  if (casaRequerida() && !casa){ $('#movErr').textContent = 'Selecciona la casa (obligatorio en ingresos)'; return; }
  if (orig && motivo.length < 5){ $('#movErr').textContent = 'Escribe el motivo de la corrección (mínimo 5 caracteres)'; return; }
  const btn = $('#saveMovBtn'); btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>';
  try {
    // El movimiento lo escribe el Worker tras verificar rol master/admin.
    // En ingresos el Worker además asigna el folio consecutivo del recibo.
    const r = orig
      ? await authedFetch('/finanzas/corregir', { id: orig.id, motivo, tipo: movType, concepto, categoria, monto, casa })
      : await authedFetch('/finanzas/registrar', { tipo: movType, concepto, categoria, monto, casa });
    toast(orig ? 'Corrección guardada · el original quedó cancelado' : 'Movimiento registrado', 'ok');
    closeSheet('#movOverlay');
    $('#movConcept').value = $('#movCat').value = $('#movAmount').value = $('#movCasa').value = '';
    modoFormMov(null);
    if (r && r.folioRecibo){
      abrirReciboSheet({
        id: orig ? r.nuevoId : r.id, folioRecibo: r.folioRecibo,
        tipo: movType, concepto, categoria, monto, casa,
        creadoNombre: ME.nombre || '', ts: orig ? orig.ts : new Date(),
        ...(orig ? { corrigeAId: orig.id } : {}),
      });
    }
  } catch(e){ $('#movErr').textContent = e.message || 'No se pudo guardar'; }
  finally { btn.disabled = false; btn.textContent = movCorrigiendo ? 'Guardar corrección' : 'Guardar movimiento'; }
}

/* reporte PDF para el grupo de residentes */
$('#pdfBtn').addEventListener('click', generarPDF);

/* construye el PDF premium (FASE 0) y devuelve {doc, filename} sin descargar ni compartir —
   generarPDF() y compartirReportePDF() comparten esta misma construcción. */
async function construirReportePDF(){
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF({ unit:'pt', format:'letter' });
    const W = doc.internal.pageSize.getWidth();
    const H = doc.internal.pageSize.getHeight();
    const M = PDF.MARGIN;
    const { label } = monthRange();

    // finCache trae 6 meses; el reporte PDF es mensual, así que se filtra al mes en curso.
    const curKey = finMonths.length ? finMonths[finMonths.length-1].key : monthKey(new Date());
    const prevKey = finMonths.length > 1 ? finMonths[finMonths.length-2].key : null;
    const monthMovs = finCache.filter(m => monthKey(m.ts) === curKey);

    let cobrado = 0, gastos = 0;
    monthMovs.forEach(m => m.tipo==='ingreso' ? cobrado += m.monto : gastos += m.monto);
    const saldo = cobrado - gastos;

    const byMonth = groupByMonth();
    const prevMonth = prevKey ? byMonth[prevKey] : null;
    const cmpPct = (cur, prevVal) => (prevVal > 0) ? Math.round(((cur - prevVal) / prevVal) * 100) : null;
    const cmpCobrado = prevMonth ? cmpPct(cobrado, prevMonth.ingreso) : null;
    const cmpGastos = prevMonth ? cmpPct(gastos, prevMonth.gasto) : null;
    const prevSaldo = prevMonth ? (prevMonth.ingreso - prevMonth.gasto) : null;
    const cmpSaldo = (prevMonth && prevSaldo !== 0) ? Math.round(((saldo - prevSaldo) / Math.abs(prevSaldo)) * 100) : null;

    const folio = folioDelMes(curKey, cobrado, gastos);
    const generadoEl = new Date().toLocaleString('es-MX', { day:'2-digit', month:'2-digit', year:'numeric', hour:'2-digit', minute:'2-digit' });

    /* ===== 1. Filete dorado + encabezado ===== */
    doc.setFillColor(...PDF.gold); doc.rect(0, 0, W, 4, 'F');

    let y = M - 10;
    doc.setFont('helvetica','normal'); doc.setFontSize(9); doc.setTextColor(...PDF.secondary);
    doc.text('E S T A D O   D E   C U E N T A   R E S I D E N C I A L', M, y + 14);

    doc.setFont('helvetica','bold'); doc.setFontSize(26); doc.setTextColor(...PDF.text);
    doc.text('Cerrada Mojave', M, y + 42);

    doc.setFont('helvetica','normal'); doc.setFontSize(9); doc.setTextColor(...PDF.secondary);
    doc.text(`Periodo: ${label}`, W - M, y + 10, { align:'right' });
    doc.setTextColor(...PDF.notes);
    doc.text(`Generado: ${generadoEl}`, W - M, y + 22, { align:'right' });
    doc.text(`Folio: ${folio}`, W - M, y + 34, { align:'right' });

    y += 58;
    doc.setDrawColor(...PDF.grid);
    doc.line(M, y, W - M, y);
    y += 24;

    /* ===== 2. Tres cajas de balance ===== */
    const boxGap = 14, boxW = (W - 2*M - 2*boxGap) / 3, boxH = 68;
    const boxes = [
      { label:'TOTAL COBRADO', value: cobrado, color: PDF.green, cmp: cmpCobrado, higherIsBetter:true },
      { label:'GASTOS', value: gastos, color: PDF.red, cmp: cmpGastos, higherIsBetter:false },
      { label:'SALDO EN CAJA', value: saldo, color: PDF.navy, cmp: cmpSaldo, higherIsBetter:true },
    ];
    boxes.forEach((b, i) => {
      const x = M + i*(boxW + boxGap);
      doc.setDrawColor(...PDF.grid); doc.setFillColor(255,255,255);
      doc.roundedRect(x, y, boxW, boxH, 6, 6, 'FD');
      doc.setFont('helvetica','bold'); doc.setFontSize(8.5); doc.setTextColor(...PDF.secondary);
      doc.text(b.label, x + 14, y + 20);
      doc.setFont('courier','bold'); doc.setFontSize(16); doc.setTextColor(...b.color);
      doc.text(money(b.value), x + boxW - 14, y + 44, { align:'right' });
      if (b.cmp !== null){
        const up = b.cmp >= 0;
        const good = b.higherIsBetter ? up : !up;
        doc.setFont('helvetica','bold'); doc.setFontSize(8);
        doc.setTextColor(...(good ? PDF.green : PDF.red));
        // ▲▼ evitados a propósito: los fuentes estándar de jsPDF (Helvetica WinAnsi) no
        // los soportan y corrompen la codificación del texto completo. +/- sí es seguro.
        doc.text(`${up?'+':'-'}${Math.abs(b.cmp)}% vs mes anterior`, x + 14, y + 58);
      } else {
        doc.setFont('helvetica','normal'); doc.setFontSize(8); doc.setTextColor(...PDF.notes);
        doc.text('Sin datos del mes anterior', x + 14, y + 58);
      }
    });
    y += boxH + 22;

    /* ===== 3. Indicador de salud financiera ===== */
    y = dibujarSaludFinanciera(doc, W, y, cobrado, gastos);
    y += 10;

    const tituloSeccion = (txt) => {
      doc.setFont('helvetica','bold'); doc.setFontSize(12); doc.setTextColor(...PDF.text);
      doc.text(txt, M, y + 12);
      y += 20;
    };

    /* ===== 4. Barras Ingresos vs Gastos — solo meses con movimientos ===== */
    tituloSeccion('Ingresos vs Gastos');
    const { labels: barLabels, ingresos: barIngresos, gastos: barGastos } = mesesConMovimientos(byMonth);
    const barImg = await renderBarrasHiRes(barLabels, barIngresos, barGastos);
    const barBoxW = W - 2*M, barImgH = 140;
    doc.setDrawColor(...PDF.grid); doc.setFillColor(255,255,255);
    doc.roundedRect(M, y, barBoxW, barImgH + 16, 6, 6, 'FD');
    doc.addImage(barImg, 'PNG', M + 8, y + 8, barBoxW - 16, barImgH);
    y += barImgH + 16 + 12;
    y = dibujarLeyendaSeries(doc, W, y, [{ label:'Ingresos', color:'#0f766e' }, { label:'Gastos', color:'#991b1b' }]);
    y += 14;

    /* ===== 5. Dona por categoría (izquierda) + desglose nativo (derecha), mayor a menor ===== */
    tituloSeccion('Distribución de gastos por categoría');
    const catRaw = categoriasDelMes(curKey);
    const order = catRaw.labels.map((l,i)=>i).sort((a,b)=>catRaw.data[b]-catRaw.data[a]);
    const pdfCatLabels = order.map(i=>catRaw.labels[i]);
    const pdfCatData = order.map(i=>catRaw.data[i]);
    const pdfCatHasData = catRaw.hasData;
    const pastelImg = await renderPastelDoughnutHiRes(pdfCatLabels, pdfCatData, pdfCatHasData, money(gastos));
    const donutSize = 150, donutX = M, donutY = y;
    doc.addImage(pastelImg, 'PNG', donutX, donutY, donutSize, donutSize);
    const legendX0 = donutX + donutSize + 24, legendX1 = W - M;
    const legendEnd = dibujarLeyendaCategorias(doc, W, donutY + 6, pdfCatLabels, pdfCatData, pdfCatHasData, legendX0, legendX1);
    y = Math.max(donutY + donutSize + 14, legendEnd) + 10;

    /* ===== 6. Tabla "03 · Historial de transacciones" ===== */
    doc.setFillColor(...PDF.gold); doc.rect(M, y, 20, 3, 'F');
    doc.setFont('helvetica','bold'); doc.setFontSize(12); doc.setTextColor(...PDF.text);
    doc.text('03 · Historial de transacciones', M + 28, y + 6);
    y += 20;

    const rows = monthMovs.map(m => ({
      fecha: fmtTime(m.ts), tipo: m.tipo, categoria: m.categoria || 'Otro', concepto: m.concepto || '', monto: m.monto,
    }));

    doc.autoTable({
      startY: y,
      head: [['Fecha','Categoría','Concepto','Monto']],
      body: rows.length
        // "-" ASCII normal, no "−" (U+2212): ese signo no existe en WinAnsi/Helvetica estándar
        // de jsPDF y corrompe toda la celda (mismo bug que las flechas ▲▼ de las cajas).
        ? rows.map(r => [r.fecha, r.categoria, r.concepto, (r.tipo==='ingreso'?'+':'-') + money(r.monto)])
        : [['—','—','Sin movimientos','—']],
      foot: rows.length ? [['', '', 'Saldo del periodo', (saldo>=0?'+':'-') + money(Math.abs(saldo))]] : [],
      theme:'plain',
      styles:{ font:'helvetica', fontSize:9, textColor: PDF.text, cellPadding:6, lineColor: PDF.grid, lineWidth:0.5 },
      headStyles:{ fillColor:[255,255,255], textColor: PDF.secondary, fontStyle:'bold', fontSize:8.5, lineColor: PDF.text },
      alternateRowStyles:{ fillColor: PDF.zebra },
      columnStyles:{ 3:{ halign:'right', font:'courier', fontStyle:'bold' } },
      margin:{ left:M, right:M, bottom: 50 },
      didParseCell(data){
        if (data.section === 'body' && data.column.index === 1 && rows[data.row.index]){
          data.cell.text = [''];
        }
        if (data.section === 'body' && data.column.index === 3 && rows[data.row.index]){
          data.cell.styles.textColor = rows[data.row.index].tipo === 'ingreso' ? PDF.green : PDF.red;
        }
        if (data.section === 'foot'){
          data.cell.styles.fontStyle = 'bold';
          data.cell.styles.textColor = PDF.text;
          if (data.column.index === 3){ data.cell.styles.font = 'courier'; data.cell.styles.halign = 'right'; }
        }
      },
      didDrawCell(data){
        if (data.section === 'body' && data.column.index === 1 && rows[data.row.index]){
          const r = rows[data.row.index];
          const ing = r.tipo === 'ingreso';
          doc.setFont('helvetica','bold'); doc.setFontSize(8);
          const textW = doc.getTextWidth(r.categoria);
          const padX = 6, badgeW = textW + padX*2, badgeH = 14;
          const bx = data.cell.x + 4, by = data.cell.y + (data.cell.height - badgeH) / 2;
          doc.setFillColor(...(ing ? PDF.badgeGreenBg : PDF.badgeRedBg));
          doc.roundedRect(bx, by, badgeW, badgeH, 3, 3, 'F');
          doc.setTextColor(...(ing ? PDF.badgeGreenFg : PDF.badgeRedFg));
          doc.text(r.categoria, bx + padX, by + badgeH/2 + 3);
        }
        if (data.section === 'foot' && data.row.index === 0 && data.column.index === 0){
          doc.setDrawColor(...PDF.text); doc.setLineWidth(0.6);
          doc.line(M, data.cell.y, W - M, data.cell.y);
          doc.line(M, data.cell.y + 2, W - M, data.cell.y + 2);
        }
      },
    });

    /* ===== 7. Pie en todas las páginas =====
       Folio + página van juntos a la derecha (no centrados) para no traslaparse con el texto
       de la izquierda — con folio+fecha+"Reporte financiero oficial..." los tres textos
       independientes no cabían en el ancho de la página. */
    const totalPages = doc.internal.getNumberOfPages();
    for (let p = 1; p <= totalPages; p++){
      doc.setPage(p);
      doc.setFont('helvetica','normal'); doc.setFontSize(7); doc.setTextColor(...PDF.notes);
      doc.text('Reporte financiero oficial · Cerrada Mojave · Transparencia vecinal', M, H - 24);
      doc.text(`${folio} · Página ${p} de ${totalPages}`, W - M, H - 24, { align:'right' });
    }

    return { doc, filename: `Finanzas-Mojave-${label.replace(' ','-')}.pdf` };
}

/* botón "Reporte PDF": solo descarga */
async function generarPDF(){
  const btn = $('#pdfBtn'); const btnLabel = btn.textContent;
  btn.disabled = true; btn.textContent = 'Generando…';
  try {
    const { doc, filename } = await construirReportePDF();
    doc.save(filename);
  } catch(e){
    console.error('generarPDF', e);
    toast('No se pudo generar el PDF', 'bad');
  } finally {
    btn.disabled = false; btn.textContent = btnLabel;
  }
}

/* botón "Compartir reporte": Web Share API nivel 2 (con archivo) para elegir WhatsApp directo
   desde el panel nativo del celular; en escritorio o sin soporte, descarga y avisa.
   Nada de awaits innecesarios entre terminar el PDF y llamar a navigator.share(): algunos
   navegadores móviles invalidan el "gesto de usuario" si se demora demasiado o se anida mal. */
async function compartirReportePDF(){
  const btn = $('#waBtn'); const original = btn.textContent;
  btn.disabled = true; btn.textContent = 'Generando…';
  try {
    const { doc, filename } = await construirReportePDF();
    const blob = doc.output('blob');
    const file = new File([blob], filename, { type: 'application/pdf' });

    if (navigator.canShare && navigator.canShare({ files: [file] })){
      await navigator.share({ files: [file], title: 'Reporte financiero · Cerrada Mojave' });
      toast('Reporte compartido', 'ok');
    } else {
      doc.save(filename);
      toast('PDF descargado — adjúntalo en WhatsApp', 'ok');
    }
  } catch(e){
    if (e && e.name === 'AbortError'){
      // el usuario cerró el panel de compartir sin elegir nada; no es un error real.
    } else {
      console.error('compartirReportePDF', e);
      toast('No se pudo generar el reporte', 'bad');
    }
  } finally {
    btn.disabled = false; btn.textContent = original;
  }
}
$('#waBtn').addEventListener('click', compartirReportePDF);

/* ====================== FASE 4.5 · RECIBOS DE PAGO ====================== */
function tsADate(ts){ return ts && ts.toDate ? ts.toDate() : new Date(ts); }

/* Recibo individual, una página carta, misma identidad tipográfica de FASE 0
   (filete dorado, eyebrow espaciado, folio a la derecha, montos en courier). */
function construirReciboPDF(mov){
  const { jsPDF } = window.jspdf;
  const doc = new jsPDF({ unit:'pt', format:'letter' });
  const W = doc.internal.pageSize.getWidth();
  const H = doc.internal.pageSize.getHeight();
  const M = PDF.MARGIN;
  const fecha = tsADate(mov.ts).toLocaleString('es-MX', { day:'2-digit', month:'long', year:'numeric', hour:'2-digit', minute:'2-digit' });

  doc.setFillColor(...PDF.gold); doc.rect(0, 0, W, 4, 'F');

  // Banner del logo (assets/logo-mojave.jpg, 662x300 original), centrado, proporción intacta
  // (ancho fijo, alto derivado del ratio real — nunca se deforma). Si logoMojaveDataUrl
  // todavía no cargó, se omite y el encabezado cae al arranque de siempre (y = M - 10):
  // el recibo nunca depende de que el logo esté listo.
  const LOGO_W = 220, LOGO_H = LOGO_W * (300 / 662);
  let y;
  if (logoMojaveDataUrl) {
    const logoY = 4 + 16;
    doc.addImage(logoMojaveDataUrl, 'JPEG', (W - LOGO_W) / 2, logoY, LOGO_W, LOGO_H);
    y = logoY + LOGO_H + 16;
  } else {
    y = M - 10;
  }
  doc.setFont('helvetica','normal'); doc.setFontSize(9); doc.setTextColor(...PDF.secondary);
  doc.text('R E C I B O   D E   P A G O', M, y + 14);
  doc.setFont('helvetica','bold'); doc.setFontSize(26); doc.setTextColor(...PDF.text);
  doc.text('Cerrada Mojave', M, y + 42);
  doc.setFont('helvetica','normal'); doc.setFontSize(9); doc.setTextColor(...PDF.secondary);
  doc.text(`Folio: ${mov.folioRecibo}`, W - M, y + 10, { align:'right' });
  doc.setTextColor(...PDF.notes);
  doc.text(`Emitido: ${fecha}`, W - M, y + 22, { align:'right' });

  y += 58; doc.setDrawColor(...PDF.grid); doc.line(M, y, W - M, y); y += 30;

  const boxH = 88;
  doc.setDrawColor(...PDF.grid); doc.setFillColor(255,255,255);
  doc.roundedRect(M, y, W - 2*M, boxH, 8, 8, 'FD');
  doc.setFont('helvetica','bold'); doc.setFontSize(9); doc.setTextColor(...PDF.secondary);
  doc.text('MONTO RECIBIDO', M + 18, y + 24);
  doc.setFont('courier','bold'); doc.setFontSize(30); doc.setTextColor(...PDF.green);
  doc.text(money(mov.monto), W - M - 18, y + 58, { align:'right' });
  y += boxH + 34;

  const cancelado = esCanceladoMov(mov);
  const filas = [
    ['CASA', mov.casa || '—'],
    ['CONCEPTO', mov.concepto || '—'],
    ['CATEGORÍA', mov.categoria || 'Otro'],
    ['FECHA Y HORA', fecha],
    ['REGISTRÓ', mov.creadoNombre || '—'],
    ...(mov.corrigeAId ? [['CORRIGE A', `Recibo ${refMovPorId(mov.corrigeAId)} (cancelado)`]] : []),
    ...(cancelado ? [
      ['ESTADO', 'CANCELADO — este recibo NO es válido'],
      ['MOTIVO', mov.motivoCancelacion || '—'],
      ...(mov.corregidoPorId ? [['SUSTITUIDO POR', `Recibo ${refMovPorId(mov.corregidoPorId)}`]] : []),
    ] : []),
  ];
  filas.forEach(([k, v]) => {
    doc.setFont('helvetica','bold'); doc.setFontSize(9); doc.setTextColor(...PDF.secondary);
    doc.text(k, M, y);
    doc.setFont('helvetica','normal'); doc.setFontSize(11); doc.setTextColor(...PDF.text);
    doc.text(String(v).slice(0, 90), M + 140, y);
    doc.setDrawColor(...PDF.grid); doc.setLineWidth(0.5);
    doc.line(M, y + 8, W - M, y + 8);
    y += 28;
  });

  doc.setFont('helvetica','normal'); doc.setFontSize(7); doc.setTextColor(...PDF.notes);
  doc.text(cancelado ? 'Recibo CANCELADO · sin validez · Cerrada Mojave' : 'Recibo oficial · Cerrada Mojave · Transparencia vecinal', M, H - 24);
  doc.text(`${mov.folioRecibo} · Página 1 de 1`, W - M, H - 24, { align:'right' });

  // Marca de agua CANCELADO, encima de todo: diagonal, roja y semitransparente para que el
  // contenido se siga leyendo (el folio y los datos originales se conservan a propósito).
  if (cancelado){
    doc.saveGraphicsState();
    try { doc.setGState(new doc.GState({ opacity: 0.22 })); } catch(_){}
    doc.setFont('helvetica','bold'); doc.setFontSize(80); doc.setTextColor(...PDF.red);
    // Con ángulo, jsPDF ignora align:'center': se centra a mano con el ancho real del texto.
    const ANG = 35, rad = ANG * Math.PI / 180, tw = doc.getTextWidth('CANCELADO');
    doc.text('CANCELADO', W / 2 - (tw / 2) * Math.cos(rad), H / 2 + (tw / 2) * Math.sin(rad), { angle: ANG });
    doc.restoreGraphicsState();
  }

  return { doc, filename: `Recibo-${mov.folioRecibo}${cancelado ? '-CANCELADO' : ''}.pdf` };
}

let reciboActual = null;
function abrirReciboSheet(mov){
  reciboActual = mov;
  cargarLogoMojave();   // reintento silencioso por si la precarga de enterApp() falló
  const cancelado = esCanceladoMov(mov);
  $('#reciboTitle').textContent = `Recibo ${mov.folioRecibo}${cancelado ? ' · CANCELADO' : ''}`;
  $('#reciboErr').textContent = '';
  $('#reciboDatos').innerHTML =
    `<b>${esc(mov.casa || '—')}</b> · ${esc(mov.concepto || '')}<br>` +
    `${esc(mov.categoria || 'Otro')} · ${money(mov.monto)} · ${fmtTime(mov.ts)}` +
    (mov.corrigeAId ? `<br>Corrige a ${esc(refMovPorId(mov.corrigeAId))}` : '') +
    (cancelado ? `<br><span style="color:var(--bad)">CANCELADO: ${esc(mov.motivoCancelacion || '')} — el PDF sale con la marca CANCELADO.</span>` : '');
  openSheet('#reciboOverlay');
}
$('#reciboOverlay').addEventListener('click', e => { if (e.target.id==='reciboOverlay') closeSheet('#reciboOverlay'); });

/* Marca envío/descarga en el movimiento (vía Worker). Si falla no bloquea:
   el recibo ya salió; solo se avisa que la marca no quedó registrada. */
async function marcarReciboEnviado(id, accion){
  try { await authedFetch('/finanzas/marcar-recibo', { id, accion }); }
  catch(e){ console.error('marcarRecibo', e); toast('Recibo ok, pero no se registró el envío', 'bad'); }
}

/* Compartir por WhatsApp: Web Share nivel 2, mismo patrón FASE 1 — sin awaits entre
   generar el PDF y navigator.share() para no perder el gesto de usuario en móviles. */
$('#reciboWaBtn').addEventListener('click', async () => {
  const mov = reciboActual; if (!mov) return;
  const btn = $('#reciboWaBtn'); const original = btn.textContent;
  btn.disabled = true; btn.textContent = 'Generando…';
  try {
    const { doc, filename } = construirReciboPDF(mov);
    const file = new File([doc.output('blob')], filename, { type:'application/pdf' });
    if (navigator.canShare && navigator.canShare({ files:[file] })){
      await navigator.share({ files:[file], title:`Recibo ${mov.folioRecibo} · Cerrada Mojave` });
      toast('Recibo compartido', 'ok');
      await marcarReciboEnviado(mov.id, 'compartido');
    } else {
      doc.save(filename);
      toast('PDF descargado — adjúntalo en WhatsApp', 'ok');
      await marcarReciboEnviado(mov.id, 'descargado');
    }
  } catch(e){
    if (e && e.name === 'AbortError'){
      // el usuario cerró el panel de compartir; no es un error real.
    } else {
      console.error('compartirRecibo', e);
      $('#reciboErr').textContent = 'No se pudo generar el recibo';
    }
  } finally { btn.disabled = false; btn.textContent = original; }
});

/* Plan B siempre visible: descarga directa (Web Share falla a veces en iOS). */
$('#reciboDlBtn').addEventListener('click', async () => {
  const mov = reciboActual; if (!mov) return;
  const btn = $('#reciboDlBtn'); const original = btn.textContent;
  btn.disabled = true; btn.textContent = 'Generando…';
  try {
    const { doc, filename } = construirReciboPDF(mov);
    doc.save(filename);
    toast('Recibo descargado', 'ok');
    await marcarReciboEnviado(mov.id, 'descargado');
  } catch(e){
    console.error('descargarRecibo', e);
    $('#reciboErr').textContent = 'No se pudo generar el recibo';
  } finally { btn.disabled = false; btn.textContent = original; }
});

/* ====================== FASE 4.5 · REPORTE POR CASA (FASE 6.5: desde el padrón) ====================== */
$('#casaRepBtn').addEventListener('click', () => {
  const casas = jefes().slice()   // todas las casas (activas y suspendidas) para poder reportar cualquiera
    .sort((a,b) => a.domicilio.localeCompare(b.domicilio, 'es', { numeric:true }))
    .map(v => v.domicilio);
  const sel = $('#casaRepSel');
  sel.innerHTML = '';
  if (!casas.length){ sel.appendChild(new Option('Sin casas en el padrón','')); }
  else { sel.appendChild(new Option('Elige un domicilio…','')); casas.forEach(c => sel.appendChild(new Option(c, c))); }
  $('#casaRepCustomField').classList.add('hidden');   // ya no hay texto libre: el padrón es la fuente
  $('#casaRepErr').textContent = '';
  openSheet('#casaRepOverlay');
});
$('#casaRepOverlay').addEventListener('click', e => { if (e.target.id==='casaRepOverlay') closeSheet('#casaRepOverlay'); });

$('#casaRepGo').addEventListener('click', async () => {
  const casa = $('#casaRepSel').value;
  if (!casa){ $('#casaRepErr').textContent = 'Elige un domicilio'; return; }
  const btn = $('#casaRepGo'); btn.disabled = true; btn.textContent = 'Generando…';
  try {
    // Historial completo de la casa (no solo los 6 meses del cache). Sin orderBy
    // encadenado al where para no requerir índice compuesto — se ordena aquí.
    const snap = await db.collection('finanzas').where('casa','==',casa).get();
    const movs = snap.docs.map(d => ({ id: d.id, ...d.data() }))
      .filter(m => m.tipo === 'ingreso' && !esCanceladoMov(m))   // un pago cancelado no es un pago
      .sort((a,b) => tsADate(b.ts) - tsADate(a.ts));
    if (!movs.length){ $('#casaRepErr').textContent = `Sin pagos registrados para "${casa}"`; return; }
    const { doc, filename } = construirReporteCasaPDF(casa, movs);
    doc.save(filename);
    toast('Reporte descargado', 'ok');
    closeSheet('#casaRepOverlay');
  } catch(e){
    console.error('reporteCasa', e);
    $('#casaRepErr').textContent = 'No se pudo generar el reporte';
  } finally { btn.disabled = false; btn.textContent = 'Generar PDF'; }
});

/* Historial de pagos de una casa, identidad FASE 0. Cada pago referencia su folio
   de recibo y la fecha de envío/descarga — el soporte para aclaraciones. */
function construirReporteCasaPDF(casa, movs){
  const { jsPDF } = window.jspdf;
  const doc = new jsPDF({ unit:'pt', format:'letter' });
  const W = doc.internal.pageSize.getWidth();
  const H = doc.internal.pageSize.getHeight();
  const M = PDF.MARGIN;
  const generadoEl = new Date().toLocaleString('es-MX', { day:'2-digit', month:'2-digit', year:'numeric', hour:'2-digit', minute:'2-digit' });
  const total = movs.reduce((a,m) => a + (m.monto || 0), 0);

  doc.setFillColor(...PDF.gold); doc.rect(0, 0, W, 4, 'F');
  let y = M - 10;
  doc.setFont('helvetica','normal'); doc.setFontSize(9); doc.setTextColor(...PDF.secondary);
  doc.text('H I S T O R I A L   D E   P A G O S', M, y + 14);
  doc.setFont('helvetica','bold'); doc.setFontSize(26); doc.setTextColor(...PDF.text);
  doc.text('Cerrada Mojave', M, y + 42);
  doc.setFont('helvetica','normal'); doc.setFontSize(9); doc.setTextColor(...PDF.secondary);
  doc.text(`Casa: ${casa}`, W - M, y + 10, { align:'right' });
  doc.setTextColor(...PDF.notes);
  doc.text(`Generado: ${generadoEl}`, W - M, y + 22, { align:'right' });
  doc.text(`${movs.length} pago(s)`, W - M, y + 34, { align:'right' });

  y += 58; doc.setDrawColor(...PDF.grid); doc.line(M, y, W - M, y); y += 24;

  const fmtEnvio = m => {
    const ts = m.reciboCompartidoTs || m.reciboDescargadoTs;
    if (!ts) return '—';
    const cuando = tsADate(ts).toLocaleString('es-MX', { day:'2-digit', month:'short', year:'2-digit', hour:'2-digit', minute:'2-digit' });
    return (m.reciboCompartidoTs ? 'Enviado ' : 'Descargado ') + cuando;
  };

  doc.autoTable({
    startY: y,
    head: [['Fecha','Concepto','Categoría','Folio recibo','Recibo enviado','Monto']],
    body: movs.map(m => [
      fmtTime(m.ts),
      (m.concepto || '—').slice(0, 40),
      m.categoria || 'Otro',
      m.folioRecibo || '—',
      fmtEnvio(m),
      '+' + money(m.monto),
    ]),
    foot: [['', '', '', '', 'Total pagado', '+' + money(total)]],
    theme:'plain',
    styles:{ font:'helvetica', fontSize:8.5, textColor: PDF.text, cellPadding:6, lineColor: PDF.grid, lineWidth:0.5 },
    headStyles:{ fillColor:[255,255,255], textColor: PDF.secondary, fontStyle:'bold', fontSize:8, lineColor: PDF.text },
    alternateRowStyles:{ fillColor: PDF.zebra },
    columnStyles:{ 3:{ font:'courier' }, 5:{ halign:'right', font:'courier', fontStyle:'bold', textColor: PDF.green } },
    margin:{ left:M, right:M, bottom: 50 },
    didParseCell(data){
      if (data.section === 'foot'){
        data.cell.styles.fontStyle = 'bold';
        data.cell.styles.textColor = PDF.text;
        if (data.column.index === 5){ data.cell.styles.font = 'courier'; data.cell.styles.halign = 'right'; }
      }
    },
    didDrawCell(data){
      if (data.section === 'foot' && data.row.index === 0 && data.column.index === 0){
        doc.setDrawColor(...PDF.text); doc.setLineWidth(0.6);
        doc.line(M, data.cell.y, W - M, data.cell.y);
        doc.line(M, data.cell.y + 2, W - M, data.cell.y + 2);
      }
    },
  });

  const totalPages = doc.internal.getNumberOfPages();
  for (let p = 1; p <= totalPages; p++){
    doc.setPage(p);
    doc.setFont('helvetica','normal'); doc.setFontSize(7); doc.setTextColor(...PDF.notes);
    doc.text('Historial de pagos oficial · Cerrada Mojave · Transparencia vecinal', M, H - 24);
    doc.text(`${casa} · Página ${p} de ${totalPages}`, W - M, H - 24, { align:'right' });
  }

  return { doc, filename: `Pagos-${casa.replace(/\s+/g,'-')}-Mojave.pdf` };
}

function openSheet(sel){ $(sel).classList.add('open'); }
function closeSheet(sel){ $(sel).classList.remove('open'); }

/* ====================== PUSH (FCM) ====================== */
async function registerPush(){
  // Residentes reciben push (de sus esclavos/visitantes). El master también: el Worker le avisa
  // si una cuenta choca con el límite de cancelaciones/correcciones de Finanzas.
  if (ME.rol!=='residente' && ME.rol!=='master') return;
  try {
    if (!('serviceWorker' in navigator) || !firebase.messaging.isSupported()) return;
    const perm = await Notification.requestPermission();
    if (perm !== 'granted') return;
    // Scope PROPIO para el worker de push. Solo puede haber un service worker por scope: antes
    // se registraba con el scope por defecto ('./', el mismo de sw.js) y, al aceptar
    // notificaciones, REEMPLAZABA a sw.js — adiós caché offline y auto-actualización. Este es
    // el mismo scope que usa el SDK de Firebase cuando lo registra él solo; ninguna página vive
    // bajo esa ruta, así que este worker nunca controla la app, solo recibe los push.
    const reg = await navigator.serviceWorker.register('firebase-messaging-sw.js',
      { scope: './firebase-cloud-messaging-push-scope', updateViaCache: 'none' });
    // Limpieza de la versión anterior: la suscripción push vieja quedó colgada del registro
    // principal (el de sw.js, que no sabe mostrar notificaciones). Se da de baja para que FCM
    // no siga mandando a un token que ya nadie atiende; el token nuevo se guarda abajo.
    try {
      const principal = await navigator.serviceWorker.getRegistration('./');
      if (principal && principal !== reg){
        const subVieja = await principal.pushManager.getSubscription();
        if (subVieja) await subVieja.unsubscribe();
      }
    } catch(_){}
    const messaging = firebase.messaging();
    const token = await messaging.getToken({ vapidKey: CONFIG.vapidKey, serviceWorkerRegistration: reg });
    if (token){
      await db.collection('usuarios').doc(ME.uid).set({ fcmToken: token }, { merge:true });
    }
    messaging.onMessage(p => toast(p.notification?.body || 'Movimiento en tu hogar'));
  } catch(e){ console.warn('Push no disponible', e); }
}

/* ====================== VOTACIONES (FASE V3) ======================
   El front SOLO consume los 7 endpoints + un listener de Firestore sobre el doc
   PÚBLICO votaciones/{id} (permitido por reglas) para el marcador en vivo. No valida
   roles ni permisos: si un endpoint devuelve 403, se muestra el mensaje tal cual. El
   mostrar/ocultar controles de admin es cosmético; el Worker es el que manda. */
let votData = null;        // respuesta de /votaciones/estado: { activa, yo }
let votUnsub = null;       // listener de Firestore del marcador en vivo
let votSeg = 'actual';     // 'actual' | 'anteriores'
let votChanging = false;   // el jefe está cambiando su voto
let votSel = null;         // opción seleccionada (id) al votar/cambiar
let votNominalCache = null;// última lista nominal cargada (para conservarla en throttle)

function votEsc(s){ return String(s==null?'':s).replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function votErr(e){
  const m = (e && e.message) || '';
  if (/failed to fetch|networkerror|load failed|network request failed/i.test(m)) return 'Sin conexión. Revisa tu internet.';
  if (/token/i.test(m)) return 'Tu sesión expiró. Vuelve a iniciar sesión.';
  return m || 'Algo salió mal';
}
function votOpTexto(v, id){ const o=(v.opciones||[]).find(x=>x.id===id); return o?o.texto:''; }
function votGanadora(v){ let best=null; for(const o of (v.opciones||[])){ const n=(v.conteo||{})[o.id]||0; if(!best||n>best.n) best={id:o.id,texto:o.texto,n}; } return best&&best.n>0?best:null; }
function votFecha(iso){ if(!iso) return ''; const d=new Date(iso); if(isNaN(d)) return ''; return d.toLocaleDateString('es-MX',{day:'numeric',month:'short'})+', '+d.toLocaleTimeString('es-MX',{hour:'numeric',minute:'2-digit'}); }
function votFechaDia(iso){ if(!iso) return ''; const d=new Date(iso); if(isNaN(d)) return ''; return d.toLocaleDateString('es-MX',{day:'numeric',month:'long',year:'numeric'}); }
function votBaja(v){ return v.totalCasas>0 && v.participaronCount < v.totalCasas/2; }

function loadVotaciones(){ votSwitchSeg(votSeg || 'actual'); }
function votSwitchSeg(seg){
  votSeg = seg;
  $$('#votSeg button').forEach(b => b.classList.toggle('sel', b.dataset.seg===seg));
  $('#votActual').classList.toggle('hidden', seg!=='actual');
  $('#votHist').classList.toggle('hidden', seg!=='anteriores');
  if (seg==='actual') votCargarActual();
  else { if (votUnsub){ votUnsub(); votUnsub=null; } votCargarHistorial(); }
}

/* ---- Actual: votación activa (o su ausencia) ---- */
async function votCargarActual(){
  const c = $('#votActual');
  if (!votData) c.innerHTML = '<div class="empty">Cargando votación…</div>';
  try {
    votChanging = false; votSel = null;
    votData = await authedFetch('/votaciones/estado', {});
    votRenderActual();
    if (votData.activa) votAttachListener(votData.activa.id);
    else if (votUnsub){ votUnsub(); votUnsub=null; }
  } catch(e){
    c.innerHTML = `<div class="empty">${votEsc(votErr(e))}<br><button class="btn-ghost" id="vReintentar" style="margin-top:12px">Reintentar</button></div>`;
    const b=$('#vReintentar'); if(b) b.onclick = votCargarActual;
  }
}

function votAttachListener(id){
  if (votUnsub){ votUnsub(); votUnsub=null; }
  votUnsub = db.collection('votaciones').doc(id).onSnapshot(snap => {
    const d = snap.data();
    if (!d || !votData || !votData.activa || votData.activa.id!==id) return;
    // Si un admin la cerró (archivó), recargamos: /estado devolverá activa:null.
    if (d.estado==='cerrada' && votData.activa.estado!=='cerrada'){ votCargarActual(); return; }
    votData.activa.conteo = d.conteo || null;
    votData.activa.conteoOculto = !d.conteo;
    votData.activa.participaronCount = d.participaronCount || 0;
    votRenderMarcador();
  }, ()=>{});
}

function votRenderActual(){
  const c = $('#votActual');
  const puedeGestionar = enModoStaff() && ME.rol!=='master';   // cosmético; el Worker revalida
  const staffLee = enModoStaff();                              // ve lista nominal (incluye master)

  if (!votData || !votData.activa){
    let h = '<div class="empty">No hay ninguna votación en curso.<br><span style="font-size:12px;color:var(--muted-2)">Cuando la administración abra una votación, aparecerá aquí.</span></div>';
    if (puedeGestionar) h += '<button class="btn-primary" id="vcCrearBtn" style="margin-top:6px">Crear votación</button>';
    h += '<button class="btn-ghost" id="vIrHist" style="width:100%;margin-top:10px">Ver votaciones anteriores</button>';
    c.innerHTML = h; return;
  }

  const v = votData.activa, yo = votData.yo || {};
  const cerrada = v.estado==='cerrada', congelada = v.estado==='congelada';
  let h = `<div class="vhead"><div class="q">${votEsc(v.titulo)}</div>`;
  if (v.descripcion) h += `<div class="d">${votEsc(v.descripcion)}</div>`;
  const chip = cerrada ? {cls:'', t:'Votación cerrada · resultado final'}
             : congelada ? {cls:'warn', t:'Cierra '+votFecha(v.cierraAt)}
             : {cls:'abierta', t:'Abierta · cierra '+votFecha(v.cierraAt)};
  h += `<span class="vchip ${chip.cls}">${chip.t}</span></div>`;

  if (congelada) h += `<div class="vbanner"><b>Los votos ya no se pueden cambiar.</b><br>Falta menos de un día para el cierre. Para que el resultado sea firme, los votos quedaron fijos.</div>`;

  // Tarjeta de voto: solo el jefe con casa (yo.esJefe lo dice el Worker), y si no está cerrada.
  if (yo.esJefe && !cerrada){
    if (votChanging && yo.yaVotaste){
      h += `<div class="vopts">`+v.opciones.map(o=>`<button class="vopt ${votSel===o.id?'sel':''}" data-op="${o.id}"><span class="dot"></span><span class="ot">${votEsc(o.texto)}</span></button>`).join('')+`</div>`;
      h += `<button class="btn-primary" id="vEnviar">Guardar cambio</button>`;
      h += `<button class="btn-ghost" id="vCancelarCambio" style="width:100%;margin-top:10px">Cancelar</button>`;
    } else if (yo.yaVotaste){
      if (congelada){
        h += `<div class="vfrozen">Tu voto quedó registrado y cuenta para el resultado.<p class="vnote" style="margin-top:6px">Por privacidad, cuando los votos se fijan dejamos de mostrar qué elegiste.</p></div>`;
      } else {
        h += `<div class="vmine">Ya votaste ✓${yo.miOpcionActual?` · Tu voto: <b>${votEsc(votOpTexto(v,yo.miOpcionActual))}</b>`:''}</div>`;
        h += `<button class="btn-ghost" id="vCambiar" style="width:100%;margin-top:12px">Cambiar mi voto</button>`;
      }
    } else {
      h += `<div class="vopts">`+v.opciones.map(o=>`<button class="vopt ${votSel===o.id?'sel':''}" data-op="${o.id}"><span class="dot"></span><span class="ot">${votEsc(o.texto)}</span></button>`).join('')+`</div>`;
      if (congelada) h += `<p class="vnote" style="margin:0 0 12px 2px">Puedes votar, pero ya no podrás cambiarlo.</p>`;
      h += `<button class="btn-primary" id="vEnviar"${votSel?'':' disabled'}>Enviar mi voto</button>`;
    }
  } else if (yo.esJefe===false && !staffLee){
    h += `<p class="vnote" style="margin:14px 2px">El voto de tu casa lo emite el jefe de familia.</p>`;
  }

  h += `<div class="section-title">Resultados en vivo</div><div id="votMarcador"></div>`;

  if (staffLee){
    h += `<div class="vadmin"><div class="section-title" style="margin-top:0">Quién ha votado</div>`;
    h += `<p class="vnote" style="margin:0 0 10px 2px">Para proteger el voto secreto, los nombres se revelan de 5 en 5. Los últimos aparecen cuando se acumulan 5 votos más.</p>`;
    h += `<button class="btn-ghost" id="vVerNominal" style="width:100%">Ver quién ha votado</button><div id="votNominal"></div>`;
    if (puedeGestionar) h += `<button class="btn-ghost" id="vCerrar" style="width:100%;margin-top:14px;color:var(--bad);border-color:rgba(248,113,113,.4)">Cerrar votación</button>`;
    h += `</div>`;
  }

  c.innerHTML = h;
  votRenderMarcador();
}

function votRenderMarcador(){
  const el = $('#votMarcador'); if (!el || !votData || !votData.activa) return;
  const v = votData.activa;
  if (!v.conteo || v.conteoOculto){
    el.innerHTML = `<div class="vlocked"><div class="big">Los resultados se mostrarán cuando voten al menos ${v.umbralConteo||5} casas.</div>Van ${v.participaronCount||0}.</div>`;
    return;
  }
  const total = Object.values(v.conteo).reduce((a,b)=>a+b,0);
  const maxN = Math.max(0, ...Object.values(v.conteo));
  const mine = (votData.yo && votData.yo.miOpcionActual) || null;
  const bars = (v.opciones||[]).map(o=>{
    const n=v.conteo[o.id]||0, pct=total?Math.round(n*100/total):0, win=n>0&&n===maxN;
    return `<div class="vbar ${win?'win':''}"><div class="top"><span>${votEsc(o.texto)}${mine===o.id?' ●':''}</span><span class="n">${n} · ${pct}%</span></div><div class="track"><div class="fill" style="width:${pct}%"></div></div></div>`;
  }).join('');
  el.innerHTML = `<div class="vbars">${bars}</div><p class="vnote" style="margin-top:10px">Han votado ${v.participaronCount||0} de ${v.totalCasas||0} casas.</p>`;
}

/* Delegación de clicks en #votActual (sobrevive a los re-render de innerHTML) */
$('#votActual')?.addEventListener('click', e => {
  const opt = e.target.closest('.vopt');
  if (opt){ votSelectOpt(opt.dataset.op); return; }
  const id = e.target.closest('button') && e.target.closest('button').id;
  if (id==='vEnviar') votEnviar();
  else if (id==='vCambiar'){ votChanging=true; votSel = (votData.yo && votData.yo.miOpcionActual) || null; votRenderActual(); }
  else if (id==='vCancelarCambio'){ votChanging=false; votSel=null; votRenderActual(); }
  else if (id==='vVerNominal') votCargarNominal(e.target.closest('button'));
  else if (id==='vCerrar') openSheet('#votCerrarOverlay');
  else if (id==='vcCrearBtn') votAbrirCrear();
  else if (id==='vIrHist') votSwitchSeg('anteriores');
});
function votSelectOpt(op){
  votSel = op;
  $$('#votActual .vopt').forEach(b => b.classList.toggle('sel', b.dataset.op===op));
  const env = $('#vEnviar'); if (env) env.disabled = false;
}
async function votEnviar(){
  if (!votSel) return;
  const cambio = votData && votData.yo && votData.yo.yaVotaste;
  const env = $('#vEnviar'); if (env){ env.disabled=true; env.innerHTML='<span class="spinner"></span>'; }
  try {
    await authedFetch('/votaciones/votar', { opcion: votSel });
    toast(cambio ? 'Voto actualizado' : 'Voto registrado', 'ok');
    votChanging=false; votSel=null; await votCargarActual();
  } catch(e){ toast(votErr(e), 'bad'); await votCargarActual(); }
}

/* ---- Lista nominal (staff, con los candados en el Worker) ---- */
async function votCargarNominal(btn){
  const id = votData && votData.activa && votData.activa.id; if (!id) return;
  btn.disabled=true; btn.innerHTML='<span class="spinner"></span>';
  try {
    votNominalCache = await authedFetch('/votaciones/participacion', { votacionId: id });
    votRenderNominal(votNominalCache, '');
  } catch(e){
    votRenderNominal(votNominalCache, votErr(e));   // conserva la última lista (throttle)
  } finally { btn.disabled=false; btn.textContent='Actualizar lista'; }
}
function votRenderNominal(r, msg){
  const el = $('#votNominal'); if (!el) return;
  let h = '';
  if (msg) h += `<p class="vnote" style="color:var(--warn);margin:10px 2px">${votEsc(msg)} El límite de una vez por hora también cuida el anonimato.</p>`;
  if (r){
    h += r.nombres.length
      ? '<div class="list" style="margin-top:10px">'+r.nombres.map(p=>`<div class="row"><div class="rt"><div class="a">${votEsc(p.casa)}</div><div class="b">${votEsc(p.nombre)}</div></div></div>`).join('')+'</div>'
      : '<p class="vnote" style="margin:10px 2px">Aún no hay nombres para mostrar.</p>';
    if (r.pendientesSinDesglosar>0) h += `<p class="vnote" style="margin:8px 2px">Hay ${r.pendientesSinDesglosar} voto(s) más que todavía no se pueden mostrar por nombre.</p>`;
  }
  el.innerHTML = h;
}

/* ---- Crear votación (admin/jefe-admin) ---- */
function votAbrirCrear(){
  $('#vcTitulo').value=''; $('#vcDesc').value=''; $('#vcErr').textContent='';
  const box=$('#vcOpciones'); box.innerHTML=''; votAddOptInput(); votAddOptInput();
  const cierre=$('#vcCierre'); cierre.value='';
  const min=new Date(Date.now()+24*3600e3);
  cierre.min=new Date(min.getTime()-min.getTimezoneOffset()*60000).toISOString().slice(0,16);
  openSheet('#votCrearOverlay');
}
function votAddOptInput(){
  const box=$('#vcOpciones');
  const d=document.createElement('div');
  d.className='field vc-optrow'; d.style.display='flex'; d.style.gap='8px'; d.style.alignItems='center';
  d.innerHTML=`<input class="vc-opt" placeholder="Opción ${box.children.length+1}" style="flex:1"><button type="button" class="opt-del" title="Quitar">×</button>`;
  box.appendChild(d);
}
async function votGuardar(){
  const titulo=$('#vcTitulo').value.trim(), desc=$('#vcDesc').value.trim();
  const opciones=[...document.querySelectorAll('#vcOpciones .vc-opt')].map(i=>i.value.trim()).filter(Boolean);
  const cierreLocal=$('#vcCierre').value; $('#vcErr').textContent='';
  if (titulo.length<3){ $('#vcErr').textContent='Escribe la pregunta (mínimo 3 letras).'; return; }
  if (opciones.length<2){ $('#vcErr').textContent='Agrega al menos 2 opciones.'; return; }
  if (!cierreLocal){ $('#vcErr').textContent='Elige la fecha y hora de cierre.'; return; }
  const btn=$('#vcGuardar'); btn.disabled=true; btn.innerHTML='<span class="spinner"></span>';
  try {
    await authedFetch('/votaciones/crear', { titulo, descripcion:desc, opciones, cierraAt:new Date(cierreLocal).toISOString() });
    closeSheet('#votCrearOverlay'); toast('Votación abierta', 'ok'); votSwitchSeg('actual');
  } catch(e){ $('#vcErr').textContent=votErr(e); }
  finally { btn.disabled=false; btn.textContent='Abrir votación'; }
}
async function votCerrarConfirmar(){
  const id = votData && votData.activa && votData.activa.id; if (!id) return;
  const btn=$('#vcerrarConfirm'); btn.disabled=true; btn.innerHTML='<span class="spinner"></span>'; $('#vcerrarErr').textContent='';
  try {
    await authedFetch('/votaciones/cerrar', { votacionId:id });
    closeSheet('#votCerrarOverlay'); toast('Votación cerrada y archivada', 'ok'); votSwitchSeg('anteriores');
  } catch(e){ $('#vcerrarErr').textContent=votErr(e); }
  finally { btn.disabled=false; btn.textContent='Sí, cerrar y archivar'; }
}

/* ---- Historial (todos los residentes): lista y detalle de un acta ---- */
async function votCargarHistorial(){
  const c=$('#votHist'); c.innerHTML='<div class="empty">Cargando historial…</div>';
  try {
    const r = await authedFetch('/votaciones/historial', {});
    if (!r.votaciones || !r.votaciones.length){
      c.innerHTML='<div class="empty">Todavía no hay votaciones anteriores.<br><span style="font-size:12px;color:var(--muted-2)">Aquí quedará el acta de cada votación cerrada.</span></div>'; return;
    }
    c.innerHTML='<div class="section-title">Votaciones anteriores</div><div class="list" id="votHistList"></div>';
    const list=$('#votHistList');
    r.votaciones.forEach(v=>{
      const win=votGanadora(v), baja=votBaja(v);
      const el=document.createElement('button');
      el.className='row'; el.style.width='100%'; el.style.textAlign='left';
      el.innerHTML=`<div class="rt"><div class="a">${votEsc(v.titulo)}</div><div class="b">Cerrada ${votFechaDia(v.cerradaAt)}${win?' · '+votEsc(win.texto):''} · ${v.participaronCount} de ${v.totalCasas}</div></div>${baja?'<span class="tag susp">Participación baja</span>':''}`;
      el.onclick=()=>votAbrirActa(v);
      list.appendChild(el);
    });
  } catch(e){
    c.innerHTML=`<div class="empty">${votEsc(votErr(e))}<br><button class="btn-ghost" id="vHistReintentar" style="margin-top:12px">Reintentar</button></div>`;
    const b=$('#vHistReintentar'); if(b) b.onclick=votCargarHistorial;
  }
}
async function votAbrirActa(v){
  const c=$('#votHist'); c.innerHTML='<div class="empty">Cargando acta…</div>';
  try {
    const r = await authedFetch('/votaciones/participantes', { votacionId:v.id });
    votRenderActa(v, r.nombres||[]);
  } catch(e){
    c.innerHTML=`<div class="empty">${votEsc(votErr(e))}<br><button class="btn-ghost" id="vActaBack" style="margin-top:12px">← Volver</button></div>`;
    const b=$('#vActaBack'); if(b) b.onclick=votCargarHistorial;
  }
}
function votRenderActa(v, nombres){
  const total=Object.values(v.conteo||{}).reduce((a,b)=>a+b,0), win=votGanadora(v), baja=votBaja(v);
  let h=`<button class="vback" id="vActaBack">← Volver al historial</button>`;
  h+=`<div class="vhead"><div class="q">${votEsc(v.titulo)}</div>`;
  if (v.descripcion) h+=`<div class="d">${votEsc(v.descripcion)}</div>`;
  h+=`<div class="vnote" style="margin-top:8px">Cerrada ${votFechaDia(v.cerradaAt)}</div>`;
  if (baja) h+=`<span class="vchip warn">Participación baja · votaron ${v.participaronCount} de ${v.totalCasas} casas</span>`;
  h+=`</div>`;
  h+=`<div class="section-title">Resultado final</div><div class="vbars">`+(v.opciones||[]).map(o=>{
    const n=(v.conteo||{})[o.id]||0, pct=total?Math.round(n*100/total):0, wn=win&&win.id===o.id;
    return `<div class="vbar ${wn?'win':''}"><div class="top"><span>${votEsc(o.texto)}</span><span class="n">${n} · ${pct}%</span></div><div class="track"><div class="fill" style="width:${pct}%"></div></div></div>`;
  }).join('')+`</div>`;
  h+=`<p class="vnote" style="margin:10px 2px">Votaron ${v.participaronCount} de ${v.totalCasas} casas.</p>`;
  h+=`<div class="section-title">Casas que votaron</div><p class="vnote" style="margin:0 0 10px 2px">Esta lista muestra quiénes votaron, nunca qué votó cada quien.</p>`;
  h+= nombres.length ? '<div class="list">'+nombres.map(p=>`<div class="row"><div class="rt"><div class="a">${votEsc(p.casa)}</div><div class="b">${votEsc(p.nombre)}</div></div></div>`).join('')+'</div>' : '<div class="empty">Sin participantes registrados.</div>';
  $('#votHist').innerHTML=h;
  $('#vActaBack').onclick=votCargarHistorial;
}

/* ---- Wiring (una sola vez, los elementos existen en index.html) ---- */
$('#votSeg')?.addEventListener('click', e => { const b=e.target.closest('button'); if(b) votSwitchSeg(b.dataset.seg); });
$('#vcAddOpt')?.addEventListener('click', votAddOptInput);
$('#vcOpciones')?.addEventListener('click', e => { if (e.target.classList.contains('opt-del')){ const rows=$$('#vcOpciones .vc-optrow'); if (rows.length>2) e.target.closest('.vc-optrow').remove(); }});
$('#vcGuardar')?.addEventListener('click', votGuardar);
$('#votCrearOverlay')?.addEventListener('click', e => { if (e.target.id==='votCrearOverlay') closeSheet('#votCrearOverlay'); });
$('#vcerrarConfirm')?.addEventListener('click', votCerrarConfirmar);
$('#vcerrarCancel')?.addEventListener('click', () => closeSheet('#votCerrarOverlay'));
$('#votCerrarOverlay')?.addEventListener('click', e => { if (e.target.id==='votCerrarOverlay') closeSheet('#votCerrarOverlay'); });

/* ====================== Versión visible (Puertas y Gestión) ======================
   MANTENER EN SYNC con el número de sw.js (const CACHE = 'mojave-vN') cada vez que se
   publique una versión — es un literal a propósito, no se calcula solo.
   Se muestra YA, de forma síncrona, sin esperar nada del service worker: si dependiera solo
   del postMessage de abajo, en la carga que hace la transición de una versión a otra el primer
   intento le pregunta al worker VIEJO (que en versiones anteriores a v8 ni siquiera entendía
   "GET_VERSION") y el segundo intento compite contra el location.reload() de la misma función
   — carrera que se pierde casi siempre, dejando el campo vacío. Este literal nunca fallará.
   Si el service worker activo responde con una versión DISTINTA (ver mostrarVersionSW más
   abajo), la reemplaza — eso solo pasa si ESTE dispositivo aún no terminó de actualizar. */
const APP_VERSION = 'v2';
/* Se pinta en todos los .app-version: al final de Puertas (todos) y en Gestión (staff). */
function pintarVersion(v){
  document.querySelectorAll('.app-version').forEach(el => el.textContent = 'Versión ' + v);
}
pintarVersion(APP_VERSION);

/* ====================== Service worker (PWA) — auto-actualización ======================
   Objetivo: que un residente nunca tenga que borrar caché ni reinstalar para ver una mejora.
   - updateViaCache:'none' — el navegador jamás sirve sw.js desde su caché HTTP al comparar
     versiones: siempre revisa el archivo real del servidor.
   - Se revisa si hay versión nueva: al cargar, al volver a primer plano (visibilitychange), al
     regresar el foco a la ventana (en PC cambiar de ventana NO dispara visibilitychange) y cada
     30 min mientras la app está visible (una pestaña de PC abierta todo el día nunca se oculta).
     reg.update() fuerza esa comparación ya mismo, sin esperar lo que el navegador revisa por su
     cuenta (hasta 24h). Máximo una revisión por minuto.
   - Cuando una versión nueva toma control (evento controllerchange) se recarga la página UNA
     sola vez para que se vea sin que el residente haga nada — EXCEPTO: (a) si es la primerísima
     vez que un service worker controla la página (nada que "actualizar" ahí, sería un reload
     inútil en la primera visita), o (b) si está ESCRIBIENDO en un campo de texto, hay una
     hoja/modal abierta, o se está abriendo una puerta. En ese caso queda pendiente y se
     reintenta al salir del campo, al volver a primer plano y cada 15 s — así nunca se queda
     pendiente para siempre en una pestaña que no se oculta. Un <select>, casilla o botón con
     foco NO bloquea: en PC conservan el foco después de usarlos y no hay texto que perder.
     `reloaded` evita que se dispare más de una vez por carga (sin ciclos).
   - Diagnóstico visible en Gestión (#appDiag): SW activo / en espera / última revisión /
     recarga pendiente y por qué. */
if ('serviceWorker' in navigator){
  // Primera visita: el primer controllerchange (el SW recién instalado toma control) no es una
  // actualización y no recarga; cualquier controllerchange POSTERIOR en esta misma carga sí.
  let yaHabiaControl = !!navigator.serviceWorker.controller;
  let swReg = null;
  let reloaded = false;
  let reloadPendiente = false;
  let ultimaRevision = null;          // Date de la última reg.update() terminada
  let ultimaRevisionFallo = false;
  let revisandoDesde = 0;             // throttle: ms de la última revisión lanzada
  const swVer = { activo: null, espera: null };   // lo que responde cada worker ('mojave-vN')

  const TIPOS_SIN_TEXTO = ['checkbox','radio','button','submit','reset','range','color','file','image'];
  function motivoNoRecargar(){
    const a = document.activeElement;
    const escribiendo = !!a && !a.readOnly && !a.disabled && (
      a.tagName === 'TEXTAREA' || a.isContentEditable ||
      (a.tagName === 'INPUT' && !TIPOS_SIN_TEXTO.includes((a.type || '').toLowerCase())));
    if (escribiendo) return 'escribiendo en un campo';
    if (document.querySelector('.overlay.open')) return 'hay una hoja abierta';
    if (opening) return 'abriendo una puerta';
    return '';
  }

  function intentarRecargar(){
    if (reloaded || !reloadPendiente) return;
    if (motivoNoRecargar()){ pintarDiag(); return; }
    reloaded = true;
    location.reload();
  }

  function pedirVersiones(){
    navigator.serviceWorker.controller?.postMessage({ type:'GET_VERSION' });
    swReg?.waiting?.postMessage({ type:'GET_VERSION' });
  }

  const verCorta = n => { const m = /-v(\d+)$/i.exec(n || ''); return m ? ('v' + m[1]) : (n || ''); };
  function mostrarVersionSW(cacheName){
    pintarVersion(verCorta(cacheName));
  }

  function pintarDiag(){
    const el = document.getElementById('appDiag');
    if (!el) return;
    const ctrl = navigator.serviceWorker.controller;
    let activo = ctrl ? (swVer.activo ? verCorta(swVer.activo) : '…') : 'ninguno';
    // Salvaguarda: la página SIEMPRE debe estar controlada por sw.js; si otro worker se
    // quedara con el scope (el bug del push), se ve aquí de inmediato.
    if (ctrl && !/\/sw\.js$/.test(new URL(ctrl.scriptURL).pathname)) activo += ' ⚠ (no es sw.js)';
    const espera = swReg?.waiting ? (swVer.espera ? verCorta(swVer.espera) : '…')
                 : swReg?.installing ? 'instalando…' : 'ninguno';
    const revision = ultimaRevision
      ? ultimaRevision.toLocaleTimeString('es-MX', { hour:'2-digit', minute:'2-digit', second:'2-digit' }) + (ultimaRevisionFallo ? ' (sin conexión)' : '')
      : (ultimaRevisionFallo ? 'falló' : '—');
    const motivo = reloadPendiente ? (motivoNoRecargar() || 'en cuanto se pueda') : '';
    el.textContent = `SW activo: ${activo} · SW en espera: ${espera} · Última revisión: ${revision} · `
      + `Recarga pendiente: ${reloadPendiente ? 'sí (' + motivo + ')' : 'no'}`;
  }

  async function revisar(forzar){
    if (!swReg) return;
    const ahora = Date.now();
    if (!forzar && ahora - revisandoDesde < 60 * 1000) return;
    revisandoDesde = ahora;
    try { await swReg.update(); ultimaRevisionFallo = false; }
    catch(_){ ultimaRevisionFallo = true; }
    ultimaRevision = new Date();
    pedirVersiones();
    pintarDiag();
  }

  navigator.serviceWorker.addEventListener('controllerchange', () => {
    swVer.activo = null;
    if (yaHabiaControl) reloadPendiente = true;
    yaHabiaControl = true;
    intentarRecargar();
    pedirVersiones();
    pintarDiag();
  });

  navigator.serviceWorker.addEventListener('message', e => {
    if (e.data?.type !== 'VERSION') return;
    if (e.source && e.source === swReg?.waiting) swVer.espera = e.data.version;
    else { swVer.activo = e.data.version; mostrarVersionSW(e.data.version); }
    pintarDiag();
  });

  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState !== 'visible') return;
    revisar();
    intentarRecargar();
  });
  window.addEventListener('focus', () => { revisar(); intentarRecargar(); });
  // Al salir de un campo se reintenta ya; el setTimeout deja que el foco llegue a su destino.
  document.addEventListener('focusout', () => setTimeout(intentarRecargar, 300));
  setInterval(() => { intentarRecargar(); pintarDiag(); }, 15 * 1000);
  setInterval(() => { if (document.visibilityState === 'visible') revisar(); }, 30 * 60 * 1000);

  window.addEventListener('load', async () => {
    try {
      swReg = await navigator.serviceWorker.register('sw.js', { updateViaCache: 'none' });
      swReg.addEventListener('updatefound', () => {
        swVer.espera = null;
        swReg.installing?.addEventListener('statechange', () => { pedirVersiones(); pintarDiag(); });
        pintarDiag();
      });
      await revisar(true);
    } catch(e){ ultimaRevisionFallo = true; pintarDiag(); }
  });
  pintarDiag();
}
