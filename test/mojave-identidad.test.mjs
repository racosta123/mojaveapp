// Pruebas propias de Mojave (credenciales GOOGLE_CREDENTIALS, puertas sin dispositivo, cobranza sin cobro, identidad). Ejecutar:  node test/mojave-identidad.test.mjs
// Worker REAL + Firestore EN MEMORIA + FCM SIMULADO (sin red ni llaves reales).
import assert from 'node:assert/strict';
import { execSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createSign } from 'node:crypto';
import worker from '../worker.js';

const dir = mkdtempSync(join(tmpdir(), 'mqr-')); const sh = c => execSync(c, { cwd: dir, stdio: 'pipe' });
sh('openssl genrsa -out k.pem 2048'); sh('openssl pkcs8 -topk8 -nocrypt -in k.pem -out k8.pem'); sh('openssl req -new -x509 -key k.pem -out cert.pem -days 2 -subj "/CN=t"');
const KEY8 = readFileSync(join(dir, 'k8.pem'), 'utf8'), CERT = readFileSync(join(dir, 'cert.pem'), 'utf8');
const PROJ = 'proyecto-prueba';
const RealNow = Date.now.bind(Date); let fakeNow = null;
Date.now = () => fakeNow ?? RealNow();
const b64u = b => Buffer.from(b).toString('base64url');
const idToken = uid => {
  const h = b64u(JSON.stringify({ alg: 'RS256', kid: 'k1', typ: 'JWT' }));
  const p = b64u(JSON.stringify({ aud: PROJ, iss: `https://securetoken.google.com/${PROJ}`, sub: uid, user_id: uid, exp: Math.floor(RealNow() / 1000) + 3e7 }));
  return `${h}.${p}.${createSign('RSA-SHA256').update(`${h}.${p}`).sign(KEY8, 'base64url')}`;
};

const store = new Map(); let fcm = []; let fcmStatus = 200;
const fv = v => v === null ? { nullValue: null } : typeof v === 'string' ? { stringValue: v } : typeof v === 'boolean' ? { booleanValue: v }
  : typeof v === 'number' ? { integerValue: String(v) } : { timestampValue: v.__ts };
const put = (path, o) => store.set(path, Object.fromEntries(Object.entries(o).map(([k, v]) => [k, fv(v)])));
const base = `/v1/projects/${PROJ}/databases/(default)/documents`;
const docOut = (path, fields) => ({ name: `projects/${PROJ}/databases/(default)/documents/${path}`, fields });
globalThis.fetch = async (url, opts = {}) => {
  const u = new URL(String(url)); const m = opts.method || 'GET';
  const R = (body, status = 200, headers = {}) => new Response(JSON.stringify(body), { status, headers });
  if (u.hostname === 'oauth2.googleapis.com') return R({ access_token: 'tok' });
  if (u.hostname === 'www.googleapis.com') return R({ k1: CERT }, 200, { 'cache-control': 'max-age=3600' });
  if (u.hostname === 'fcm.googleapis.com') { const b = JSON.parse(opts.body).message; fcm.push({ token: b.token, body: b.notification.body }); return R({}, fcmStatus); }
  if (u.hostname !== 'firestore.googleapis.com') throw new Error('red inesperada: ' + u.hostname);
  if (u.pathname.endsWith(':commit')) {
    for (const w of JSON.parse(opts.body).writes) {
      const p = w.update.name.split('/documents/')[1];
      if (w.currentDocument?.exists === false && store.has(p)) return R({ error: { status: 'ALREADY_EXISTS' } }, 409);
      store.set(p, w.update.fields);
    }
    return R({});
  }
  const path = decodeURIComponent(u.pathname.slice(base.length + 1));
  if (m === 'GET') {
    if (path.includes('/')) { const f = store.get(path); return f ? R(docOut(path, f)) : R({}, 404); }
    return R({ documents: [...store].filter(([k]) => k.startsWith(path + '/') && !k.slice(path.length + 1).includes('/')).map(([k, f]) => docOut(k, f)) });
  }
  if (m === 'DELETE') { store.delete(path); return R({}); }
  if (m === 'PATCH') {
    const body = JSON.parse(opts.body); const mask = u.searchParams.getAll('updateMask.fieldPaths');
    if (u.searchParams.get('currentDocument.exists') === 'true' && !store.has(path)) return R({}, 404);
    if (mask.length) { const cur = { ...(store.get(path) || {}) }; mask.forEach(k => { if (body.fields[k]) cur[k] = body.fields[k]; }); store.set(path, cur); }
    else store.set(path, body.fields);
    return R({});
  }
  if (m === 'POST') { store.set(`${path}/auto${store.size}`, JSON.parse(opts.body).fields); return R({}); }
  throw new Error('método ' + m);
};
console.error = () => {};
const env = { FIREBASE_PROJECT: PROJ, SA_EMAIL: 'sa@test', SA_PRIVATE_KEY: KEY8, ALLOWED_ORIGIN: 'https://x' };
const call = async (ruta, uid, body = {}) => {
  const headers = { 'Content-Type': 'application/json' }; if (uid) headers.Authorization = 'Bearer ' + idToken(uid);
  const r = await worker.fetch(new Request('https://w' + ruta, { method: 'POST', headers, body: JSON.stringify(body) }), env);
  return { status: r.status, body: await r.json().catch(() => ({})) };
};
// El cron real: 16:00 UTC del día dado (9:00 Hermosillo). Corre scheduled() completo (suspensión + recordatorio).
const cron = async (fecha) => {
  fakeNow = Date.parse(fecha + 'T16:00:00Z'); const ps = [];
  await worker.scheduled({}, env, { waitUntil: p => ps.push(p) }); await Promise.all(ps);
};

// ---------- Pruebas propias de Mojave ----------
import { readdirSync, statSync } from 'node:fs';
let pass = 0; const t = async (n, fn) => { store.clear(); fcm = []; fcmStatus = 200; fakeNow = null; await fn(); pass++; console.log('  ok -', n); };
const baseUsuarios = () => {
  put('usuarios/uM', { nombre: 'Master Mojave', rol: 'master', estado: 'activo' });
  put('usuarios/u1', { nombre: 'Uno', rol: 'residente', estado: 'activo', casa: 'Casa 1', fcmToken: 'tok1' });
  put('personas/p1', { nombre: 'Uno', rol: 'residente', estado: 'activo', uid: 'u1', domicilio: 'Casa 1', domicilioNorm: 'CASA 1', jefeId: null, creadoEn: { __ts: '2026-10-01T00:00:00Z' } });
};

console.log('\n[M1] credenciales: solo GOOGLE_CREDENTIALS (sin SA_EMAIL/SA_PRIVATE_KEY)');
const envGC = { FIREBASE_PROJECT: PROJ, GOOGLE_CREDENTIALS: JSON.stringify({ client_email: 'sa@test', private_key: KEY8 }), ALLOWED_ORIGIN: 'https://x' };
const callGC = async (ruta, uid, body = {}) => {
  const headers = { 'Content-Type': 'application/json' }; if (uid) headers.Authorization = 'Bearer ' + idToken(uid);
  const r = await worker.fetch(new Request('https://w' + ruta, { method: 'POST', headers, body: JSON.stringify(body) }), envGC);
  return { status: r.status, body: await r.json().catch(() => ({})) };
};
await t('el Worker autentica contra Google y lee Firestore con el JSON de GOOGLE_CREDENTIALS', async () => {
  baseUsuarios(); const r = await callGC('/config/cobranza', 'u1'); assert.equal(r.status, 200); assert.equal(r.body.ok, true);
});
await t('con SA_EMAIL/SA_PRIVATE_KEY sigue funcionando igual (prioridad)', async () => {
  baseUsuarios(); const r = await call('/config/cobranza', 'u1'); assert.equal(r.status, 200);
});

console.log('\n[M2] puertas sin dispositivo y cobranza "sin cobro"');
await t('/abrir sin SHELLY_DEVICES: 503 "Puerta sin dispositivo configurado", sin tocar Shelly Cloud', async () => {
  baseUsuarios(); for (const p of ['residentes', 'visitantes', 'peatones', 'salida']) {
    const r = await call('/abrir', 'uM', { puerta: p }); assert.equal(r.status, 503); assert.match(r.body.error, /sin dispositivo configurado/i);
  }
});
await t('/abrir sin token: 401 "Falta token"; token inválido: 401 "Token malformado"', async () => {
  const a = await call('/abrir', null, { puerta: 'residentes' }); assert.equal(a.status, 401); assert.equal(a.body.error, 'Falta token');
  const r = await worker.fetch(new Request('https://w/abrir', { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer abc' }, body: '{}' }), env);
  assert.equal(r.status, 401); assert.equal((await r.json()).error, 'Token malformado');
});
await t('sin config/cobranza: cuota 0 y fecha 2099 (sin cobro); el doc se siembra con esos valores', async () => {
  baseUsuarios(); const r = await call('/config/cobranza', 'u1');
  assert.equal(r.body.cuotaMensual, 0); assert.ok(r.body.fechaInicioCobro.startsWith('2099-01-01'));
});
await t('con valores "sin cobro" nadie recibe recordatorio ni aviso, ni se suspende, aunque no haya pagos', async () => {
  baseUsuarios(); put('config/cobranza', { cuotaMensual: 0, fechaInicioCobro: { __ts: '2099-01-01T00:00:00.000Z' } });
  for (const f of ['2026-12-01', '2026-12-03', '2027-01-01', '2027-01-03']) {
    fakeNow = Date.parse(f + 'T16:00:00Z'); const ps = []; await worker.scheduled({}, env, { waitUntil: p => ps.push(p) }); await Promise.all(ps);
  }
  assert.equal(fcm.length, 0);
  fakeNow = Date.parse('2026-12-02T16:00:00Z'); assert.equal((await call('/cobranza/aviso-pago', 'u1')).body.mostrar, false);
  fakeNow = Date.parse('2026-12-10T16:00:00Z'); const ps = []; await worker.scheduled({}, env, { waitUntil: p => ps.push(p) }); await Promise.all(ps);
  assert.equal(store.get('personas/p1').estado.stringValue, 'activo');
});

console.log('\n[M3] identidad: sin residuos de otros proyectos ni del Mojave anterior');
const PROHIBIDAS = [/c[oó]rdoba/i, /marquesa/i, /cerradaapp/i, /MASTER2025/, /e4b063eb85a4/i, /jsonbin/i, /shelly-258/i, /7179e/, /481439052062/, /571836457514/, /67754183430/,
  /AIzaSyBwRW891/, /AIzaSyDdaoq/, /AIzaSyChuftP/, /solana/i, /cerrada-cordoba/, /cerrada-la-marquesa/, /la-marquesa-proxy/, /cordoba-proxy/];
const recorre = (d, out = []) => { for (const n of readdirSync(d)) { if (['.git', 'node_modules', 'vendor', '.wrangler'].includes(n)) continue; const p = join(d, n); statSync(p).isDirectory() ? recorre(p, out) : out.push(p); } return out; };
await t('ningún archivo del repo (código, config, tests, docs) contiene las marcas prohibidas', async () => {
  const raiz = join(import.meta.dirname, '..'); const malos = [];
  for (const f of recorre(raiz)) {
    if (/\.(png|jpg|jpeg|webp|ico|gif|woff2?|pdf)$/i.test(f) || f.endsWith('mojave-identidad.test.mjs') || /ChatGPT/.test(f)) continue;
    const txt = readFileSync(f, 'utf8'); for (const re of PROHIBIDAS) if (re.test(txt)) malos.push(f.replace(raiz, '') + ' ~ ' + re);
  }
  assert.deepEqual(malos, []);
});
await t('identidad presente: nombre, URL, Worker y Firebase de Mojave', async () => {
  const raiz = join(import.meta.dirname, '..'); const r = f => readFileSync(join(raiz, f), 'utf8');
  assert.match(r('config.js'), /mojaveapp-12b25/); assert.match(r('config.js'), /mojave-proxy\.acosta4770\.workers\.dev/);
  assert.match(r('app.js'), /racosta123\.github\.io\/mojaveapp\//); assert.match(r('manifest.json'), /Cerrada Mojave/);
  assert.match(r('wrangler.toml'), /name = "mojave-proxy"/); assert.match(r('sw.js'), /mojave-v/);
});

console.log(`\n${pass} pruebas OK`);
