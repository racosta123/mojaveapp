// Pruebas del recordatorio de pago por push. Ejecutar:  node test/recordatorio-pago.test.mjs
// Worker REAL + Firestore EN MEMORIA + FCM SIMULADO (host ficticio, sin red ni llaves reales).
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
const jefe = (id, nom, dom, uid, extra = {}) => put(`personas/${id}`, { nombre: nom, rol: 'residente', estado: 'activo', uid, domicilio: dom, domicilioNorm: dom.toUpperCase(), jefeId: null, creadoEn: { __ts: '2026-10-01T00:00:00Z' }, ...extra });
const pago = (id, dom, monto = 350) => put(`finanzas/${id}`, { tipo: 'ingreso', categoria: 'Cuota', casa: dom, monto, ts: { __ts: '2026-11-20T18:00:00Z' } });
const reset = (inicio = '2026-11-01T07:00:00.000Z') => {
  store.clear(); fcm = []; fcmStatus = 200; fakeNow = null;
  put('config/cobranza', { cuotaMensual: 350, fechaInicioCobro: { __ts: inicio } });
  put('usuarios/uM', { nombre: 'McRub', rol: 'master', estado: 'activo' });
  put('usuarios/uA', { nombre: 'Miguel', rol: 'admin', estado: 'activo' });
  put('usuarios/uJA', { nombre: 'Jefa Admin', rol: 'residente', esAdmin: true, estado: 'activo', casa: 'Casa 9' });
  put('usuarios/uR', { nombre: 'Rosa', rol: 'residente', estado: 'activo', casa: 'Casa 1' });
  // Casa 1: debe, con push · Casa 2: al corriente, con push · Casa 3: debe, SIN push · Casa 4: suspendida
  // Casa 5: debe, alta el 4 de nov (el día 5 ya cuenta un mes completo; el 1 todavía no con el reloj "de hoy")
  put('usuarios/u1', { nombre: 'Uno', rol: 'residente', estado: 'activo', casa: 'Casa 1', fcmToken: 'tok1' });
  put('usuarios/u2', { nombre: 'Dos', rol: 'residente', estado: 'activo', casa: 'Casa 2', fcmToken: 'tok2' });
  put('usuarios/u3', { nombre: 'Tres', rol: 'residente', estado: 'activo', casa: 'Casa 3' });
  put('usuarios/u4', { nombre: 'Cuatro', rol: 'residente', estado: 'suspendido', casa: 'Casa 4', fcmToken: 'tok4' });
  put('usuarios/u5', { nombre: 'Cinco', rol: 'residente', estado: 'activo', casa: 'Casa 5', fcmToken: 'tok5' });
  jefe('p1', 'Uno', 'Casa 1', 'u1'); jefe('p2', 'Dos', 'Casa 2', 'u2'); jefe('p3', 'Tres', 'Casa 3', 'u3');
  jefe('p4', 'Cuatro', 'Casa 4', 'u4', { estado: 'suspendido' });
  jefe('p5', 'Cinco', 'Casa 5', 'u5', { creadoEn: { __ts: '2026-11-04T18:00:00Z' } });
  put('personas/pf1', { nombre: 'Hijo de Uno', rol: 'residente', estado: 'activo', uid: 'uF', domicilio: '', jefeId: 'p1', creadoEn: { __ts: '2026-10-01T00:00:00Z' } });
  put('usuarios/uF', { nombre: 'Hijo de Uno', rol: 'residente', estado: 'activo', casa: 'Casa 1', fcmToken: 'tokF' });
  pago('f2', 'Casa 2');
};
let pass = 0; const t = async (n, fn) => { reset(); await fn(); pass++; console.log('  ok -', n); };
const toks = () => fcm.map(f => f.token).sort();
const marcas = () => [...store.keys()].filter(k => k.startsWith('recordatorios_pago/'));

console.log('\n[1] envío por el cron');
await t('día 1: avisa al jefe con adeudo y push (texto con el mes); no a familiar, al corriente, suspendida ni sin push', async () => {
  await cron('2026-12-01');
  assert.deepEqual(toks(), ['tok1', 'tok5']);      // tok5: alta el 4 -> el día 5 ya sería suspendida (mismo criterio que el corte)
  assert.equal(fcm[0].body, 'Ya puedes pagar tu cuota de diciembre. Págala antes del día 5 para evitar la suspensión.');
});
await t('día 3: texto de "2 días"', async () => {
  await cron('2026-12-03');
  assert.deepEqual(toks(), ['tok1', 'tok5']);
  assert.equal(fcm[0].body, 'Te quedan 2 días para pagar tu cuota y evitar la suspensión del acceso vehicular.');
});
await t('otros días (2, 4, 5, 15, 30): no envía nada', async () => {
  for (const d of ['02', '04', '05', '15', '30']) await cron('2026-12-' + d);
  assert.equal(fcm.length, 0);
});
await t('casa al corriente: no recibe nada ni siquiera el día 1', async () => {
  await cron('2026-12-01'); assert.ok(!toks().includes('tok2'));
});
await t('al pagar la cuota deja de recibir (día 3 ya sin aviso)', async () => {
  pago('f1', 'Casa 1'); await cron('2026-12-03'); assert.ok(!toks().includes('tok1')); assert.ok(toks().includes('tok5'));
});
await t('antes de fechaInicioCobro: no envía (inicio 2027-01-01, hoy 1-dic-2026)', async () => {
  reset('2027-01-01T07:00:00.000Z'); await cron('2026-12-01'); assert.equal(fcm.length, 0);
});
await t('el 1-nov-2026 (primer día de cobro): nadie debe aún -> no envía', async () => {
  await cron('2026-11-01'); assert.equal(fcm.length, 0);
});
await t('octubre (antes del inicio de cobro): no envía', async () => {
  await cron('2026-10-01'); await cron('2026-10-03'); assert.equal(fcm.length, 0);
});

console.log('\n[2] cron repetido y fallos');
await t('el cron corre varias veces el mismo día: una sola notificación por casa', async () => {
  await cron('2026-12-01'); await cron('2026-12-01'); await cron('2026-12-01');
  assert.deepEqual(toks(), ['tok1', 'tok5']);
  assert.deepEqual(marcas().sort(), ['recordatorios_pago/p1_2026-12-01', 'recordatorios_pago/p5_2026-12-01']);
});
await t('el día 1 y el día 3 son avisos distintos (una marca por casa y día)', async () => {
  await cron('2026-12-01'); await cron('2026-12-03'); assert.equal(fcm.length, 4);
});
await t('FCM caído: el cron no falla, no deja marca y un reintento el mismo día sí envía', async () => {
  fcmStatus = 500; await cron('2026-12-01'); assert.equal(marcas().length, 0);
  fcmStatus = 200; fcm = []; await cron('2026-12-01'); assert.deepEqual(toks(), ['tok1', 'tok5']);
});
await t('sin push activado: no pasa nada, sin marca, y la suspensión del día 5 sigue corriendo', async () => {
  await cron('2026-12-01'); assert.ok(!marcas().some(m => m.includes('p3')));
  await cron('2026-12-05');
  assert.equal(store.get('personas/p3').estado.stringValue, 'suspendido');
});
await t('si el recordatorio revienta (lectura de finanzas rota) el cron no lanza', async () => {
  const orig = globalThis.fetch;
  globalThis.fetch = async (u, o) => String(u).includes('/finanzas') ? new Response('{}', { status: 500 }) : orig(u, o);
  try { await cron('2026-12-01'); } finally { globalThis.fetch = orig; }
});

console.log('\n[3] mismo criterio que la suspensión del día 5');
await t('a quien se avisa el día 1 = a quien suspende el cron el día 5 (entre quienes tienen push)', async () => {
  await cron('2026-12-01');
  const avisadas = marcas().map(m => m.split('/')[1].split('_')[0]).sort();
  await cron('2026-12-05');
  const suspendidasCronConPush = ['p1', 'p2', 'p5'].filter(id => store.get('personas/' + id).estado.stringValue === 'suspendido');
  assert.deepEqual(avisadas, suspendidasCronConPush);
  assert.equal(store.get('personas/p2').estado.stringValue, 'activo');
});

console.log('\n[4] simulación (/admin/simular-recordatorio-pago)');
for (const [rol, uid] of [['master', 'uM'], ['admin', 'uA']]) await t(`${rol}: ve casas y texto, sin enviar ni escribir nada`, async () => {
  fakeNow = Date.parse('2026-12-01T16:00:00Z'); const antes = store.size;
  const r = await call('/admin/simular-recordatorio-pago', uid);
  assert.equal(r.status, 200);
  assert.equal(r.body.texto, 'Ya puedes pagar tu cuota de diciembre. Págala antes del día 5 para evitar la suspensión.');
  assert.deepEqual(r.body.casas.map(c => c.id).sort(), ['p1', 'p3', 'p5']);
  assert.equal(r.body.casas.find(c => c.id === 'p3').push, false);
  assert.ok(!JSON.stringify(r.body).includes('tok'), 'no expone tokens');
  assert.equal(fcm.length, 0); assert.equal(store.size, antes);
});
await t('simula con fecha explícita y marca "ya enviado" si ya salió', async () => {
  const r = await call('/admin/simular-recordatorio-pago', 'uM', { fecha: '2026-12-03' })
  assert.equal(r.body.dia, 3); assert.equal(r.body.casas.length, 3); assert.ok(r.body.casas.every(c => !c.yaEnviado));
  await cron('2026-12-03'); fakeNow = null;
  const r2 = await call('/admin/simular-recordatorio-pago', 'uM', { fecha: '2026-12-03' });
  assert.equal(r2.body.casas.find(c => c.id === 'p1').yaEnviado, true);
});
await t('día sin recordatorio: texto null y sin casas · fecha mala: 400', async () => {
  const r = await call('/admin/simular-recordatorio-pago', 'uM', { fecha: '2026-12-02' });
  assert.equal(r.body.texto, null); assert.equal(r.body.casas.length, 0);
  assert.equal((await call('/admin/simular-recordatorio-pago', 'uM', { fecha: '2026-02-31' })).status, 400);
  assert.equal((await call('/admin/simular-recordatorio-pago', 'uM', { fecha: 'mañana' })).status, 400);
});
await t('roles: jefe-admin 403, residente 403, sin token 401', async () => {
  assert.equal((await call('/admin/simular-recordatorio-pago', 'uJA')).status, 403);
  assert.equal((await call('/admin/simular-recordatorio-pago', 'uR')).status, 403);
  assert.equal((await call('/admin/simular-recordatorio-pago', null)).status, 401);
});

console.log('\n[5] aviso dentro de la app (/cobranza/aviso-pago)');
const aviso = (uid, dia, body = {}) => { fakeNow = Date.parse(dia + 'T16:00:00Z'); return call('/cobranza/aviso-pago', uid, body); };
await t('días 1 al 4 con adeudo: muestra (jefe) con el mes', async () => {
  for (const d of ['01', '02', '03', '04']) { const r = await aviso('u1', '2026-12-' + d); assert.equal(r.status, 200); assert.equal(r.body.mostrar, true); assert.equal(r.body.mes, 'diciembre'); }
});
await t('día 5 en adelante: no muestra', async () => {
  for (const d of ['05', '06', '15', '31']) assert.equal((await aviso('u1', '2026-12-' + d)).body.mostrar, false);
});
await t('casa al corriente: no muestra', async () => { assert.equal((await aviso('u2', '2026-12-01')).body.mostrar, false); });
await t('antes de fechaInicioCobro: no muestra', async () => {
  reset('2027-01-01T07:00:00.000Z'); assert.equal((await aviso('u1', '2026-12-01')).body.mostrar, false);
  reset(); assert.equal((await aviso('u1', '2026-10-02')).body.mostrar, false);
  assert.equal((await aviso('u1', '2026-11-01')).body.mostrar, false);
});
await t('un familiar ve el aviso de SU casa', async () => {
  assert.equal((await aviso('uF', '2026-12-02')).body.mostrar, true);
});
await t('intentar leer otra casa: 403; sin casa (master): 403; sin token: 401; su propia casa en el cuerpo: ok', async () => {
  assert.equal((await aviso('u1', '2026-12-01', { casa: 'Casa 2' })).status, 403);
  assert.equal((await aviso('uF', '2026-12-01', { casa: 'casa  5' })).status, 403);
  assert.equal((await aviso('u1', '2026-12-01', { casa: 'casa 1' })).status, 200);
  assert.equal((await aviso('uM', '2026-12-01')).status, 403);
  assert.equal((await call('/cobranza/aviso-pago', null)).status, 401);
});
await t('no expone datos de otras casas (solo ok, mostrar y mes)', async () => {
  const r = await aviso('u1', '2026-12-01'); assert.deepEqual(Object.keys(r.body).sort(), ['mes', 'mostrar', 'ok']);
});
await t('casa suspendida: no muestra', async () => { assert.equal((await aviso('u4', '2026-12-01')).body.mostrar, false); });
await t('consulta caída (Firestore falla): el endpoint falla y se recupera después; nada más se afecta', async () => {
  const orig = globalThis.fetch; fakeNow = Date.parse('2026-12-02T16:00:00Z');
  globalThis.fetch = async (u, o) => String(u).includes('/finanzas') ? new Response('{}', { status: 500 }) : orig(u, o);
  try { assert.equal((await call('/cobranza/aviso-pago', 'u1')).status >= 500, true); } finally { globalThis.fetch = orig; }
  assert.equal((await aviso('u1', '2026-12-02')).body.mostrar, true);
});
await t('pago el día 2 que salda: el aviso se apaga YA para jefe y familiar, y el push del día 3 no sale', async () => {
  assert.equal((await aviso('u1', '2026-12-02')).body.mostrar, true);
  pago('f1', 'Casa 1');
  assert.equal((await aviso('u1', '2026-12-02')).body.mostrar, false);
  assert.equal((await aviso('uF', '2026-12-02')).body.mostrar, false);
  await cron('2026-12-03'); assert.ok(!toks().includes('tok1')); assert.ok(toks().includes('tok5'));
});
await t('pago parcial que no salda: el aviso sigue (jefe y familiar) y el push del día 3 también sale', async () => {
  pago('f1', 'Casa 1', 100);
  assert.equal((await aviso('u1', '2026-12-02')).body.mostrar, true);
  assert.equal((await aviso('uF', '2026-12-02')).body.mostrar, true);
  await cron('2026-12-03'); assert.ok(toks().includes('tok1'));
});
await t('solo lectura: la consulta no escribe nada ni envía push', async () => {
  const antes = JSON.stringify([...store]); await aviso('u1', '2026-12-01'); await aviso('uF', '2026-12-03');
  assert.equal(JSON.stringify([...store]), antes); assert.equal(fcm.length, 0);
});

console.log(`\n${pass} pruebas OK`);
