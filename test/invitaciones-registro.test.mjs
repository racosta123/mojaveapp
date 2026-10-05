// Pruebas de las invitaciones de registro: motivo de cada fallo, token limpiado, intentos fallidos y estado de cada invitación.
// Ejecutar: node test/invitaciones-registro.test.mjs  (Worker real, Firestore en memoria, sin red)
// Importa el Worker REAL con fetch simulado: Firestore es un almacén EN MEMORIA, Google Auth se
// firma con llaves RSA generadas aquí (openssl, solo para la prueba). No toca la red, no usa
// ninguna llave real ni de producción.
import assert from 'node:assert/strict';
import { execSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import worker from '../worker.js';

// ---------- llaves de prueba ----------
const dir = mkdtempSync(join(tmpdir(), 'mq-'));
const sh = c => execSync(c, { cwd: dir, stdio: 'pipe' });
sh('openssl genrsa -out k.pem 2048');
sh('openssl pkcs8 -topk8 -nocrypt -in k.pem -out k8.pem');
sh('openssl req -new -x509 -key k.pem -out cert.pem -days 2 -subj "/CN=test"');
const KEY8 = readFileSync(join(dir, 'k8.pem'), 'utf8');
const CERT = readFileSync(join(dir, 'cert.pem'), 'utf8');
const { createSign } = await import('node:crypto');
const b64u = b => Buffer.from(b).toString('base64url');
const PROJ = 'proyecto-prueba';
const idToken = uid => {
  const h = b64u(JSON.stringify({ alg: 'RS256', kid: 'k1', typ: 'JWT' }));
  const p = b64u(JSON.stringify({ aud: PROJ, iss: `https://securetoken.google.com/${PROJ}`, sub: uid, user_id: uid, exp: Math.floor(Date.now() / 1000) + 600 }));
  const sig = createSign('RSA-SHA256').update(`${h}.${p}`).sign(KEY8, 'base64url');
  return `${h}.${p}.${sig}`;
};

// ---------- Firestore en memoria ----------
const store = new Map();   // 'coleccion/id' -> fields
const fv = v => v === null ? { nullValue: null } : typeof v === 'string' ? { stringValue: v }
  : typeof v === 'boolean' ? { booleanValue: v } : typeof v === 'number' ? { integerValue: String(v) }
  : v.__ts ? { timestampValue: v.__ts } : (() => { throw new Error('tipo'); })();
const F = o => Object.fromEntries(Object.entries(o).map(([k, v]) => [k, fv(v)]));
const put = (path, o) => store.set(path, F(o));
const base = `/v1/projects/${PROJ}/databases/(default)/documents`;
const docOut = (path, fields) => ({ name: `projects/${PROJ}/databases/(default)/documents/${path}`, fields });
globalThis.fetch = async (url, opts = {}) => {
  const u = new URL(String(url)); const m = opts.method || 'GET';
  const R = (body, status = 200, headers = {}) => new Response(JSON.stringify(body), { status, headers });
  if (u.hostname === 'oauth2.googleapis.com') return R({ access_token: 'tok' });
  if (u.hostname === 'www.googleapis.com') return R({ k1: CERT }, 200, { 'cache-control': 'max-age=3600' });
  if (u.hostname === 'fcm.googleapis.com') return R({});
  if (u.hostname === 'identitytoolkit.googleapis.com') { authCalls.push({ path: u.pathname.split('/').pop(), body: JSON.parse(opts.body || '{}') }); return R({}); }
  if (u.hostname !== 'firestore.googleapis.com') throw new Error('red inesperada: ' + u.hostname);
  const path = decodeURIComponent(u.pathname.slice(base.length + 1));
  if (m === 'GET') {
    if (path.includes('/')) { const f = store.get(path); return f ? R(docOut(path, f)) : R({}, 404); }
    const documents = [...store].filter(([k]) => k.startsWith(path + '/') && !k.slice(path.length + 1).includes('/')).map(([k, f]) => docOut(k, f));
    return R({ documents });
  }
  if (m === 'POST') { const id = 'auto' + store.size + Math.random().toString(36).slice(2, 7); store.set(`${path}/${id}`, JSON.parse(opts.body).fields); return R({}); }
  if (m === 'DELETE') { store.delete(path); return R({}); }
  if (m === 'PATCH') {
    const body = JSON.parse(opts.body); const mask = u.searchParams.getAll('updateMask.fieldPaths');
    if (u.searchParams.get('currentDocument.exists') === 'true' && !store.has(path)) return R({}, 404);
    if (mask.length) { const cur = { ...(store.get(path) || {}) }; mask.forEach(k => { if (body.fields[k]) cur[k] = body.fields[k]; }); store.set(path, cur); }
    else store.set(path, body.fields);
    return R({});
  }
  throw new Error('método ' + m);
};
let authCalls = [];
const quietLog = console.error; console.error = () => {};

const env = { FIREBASE_PROJECT: PROJ, SA_EMAIL: 'sa@test', SA_PRIVATE_KEY: KEY8, ALLOWED_ORIGIN: 'https://x' };
const call = async (ruta, uid, body = {}) => {
  const headers = { 'Content-Type': 'application/json' }; if (uid) headers.Authorization = 'Bearer ' + idToken(uid);
  const r = await worker.fetch(new Request('https://w' + ruta, { method: 'POST', headers, body: JSON.stringify(body) }), env);
  return { status: r.status, body: await r.json().catch(() => ({})) };
};
const ahora = Date.now(), iso = ms => new Date(ahora + ms).toISOString();

const { createHash } = await import('node:crypto');
const hashDe = tok => createHash('sha256').update(tok).digest('base64url');
const validar = async (token, ip = '203.0.113.77') => {
  const r = await worker.fetch(new Request('https://w/invitaciones/validar', { method: 'POST', headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': ip }, body: JSON.stringify({ token }) }), env);
  return { status: r.status, body: await r.json().catch(() => ({})) };
};
const sembrar = (tok, extra = {}) => put(`registro_invitaciones/${hashDe(tok)}`, { hashToken: hashDe(tok), personaId: 'pNorma-0000001', domicilio: 'Casa 2', nombre: 'Norma', usado: false, creadoPor: 'uA', creadoEn: { __ts: iso(-1000) }, expiraEn: { __ts: iso(24 * 3600e3) }, ...extra });
const TOK = 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-aBcDe';
let pass = 0;
const reset = () => {
  store.clear(); authCalls = [];
  put('usuarios/uA', { nombre: 'Miguel Ojeda', rol: 'admin', estado: 'activo' });
  put('personas/pAdmin-000001', { nombre: 'Miguel Ojeda', rol: 'admin', estado: 'activo', uid: 'uA', jefeId: null });
  put('personas/pNorma-0000001', { nombre: 'Norma', rol: 'residente', estado: 'activo', uid: null, telefono: '6621112222', domicilio: 'Casa 2', domicilioNorm: 'CASA 2', jefeId: null, creadoPor: 'uA', creadoEn: { __ts: iso(-3600e3) } });
};
const t = async (name, fn) => { reset(); await fn(); pass++; console.log('  ok -', name); };

await t('vigente: valida y devuelve nombre y domicilio; se puede abrir varias veces', async () => {
  sembrar(TOK);
  for (let i = 0; i < 3; i++) { const r = await validar(TOK); assert.equal(r.status, 200); assert.equal(r.body.domicilio, 'Casa 2'); }
  assert.equal([...store.keys()].filter(k => k.startsWith('registro_intentos/')).length, 0, 'un éxito no se registra como intento fallido');
});
await t('cada motivo da su código y su mensaje (sin datos de la persona)', async () => {
  sembrar(TOK, { usado: true }); let r = await validar(TOK);
  assert.deepEqual([r.status, r.body.motivo], [400, 'usada']); assert.match(r.body.error, /ya se usó/);
  sembrar(TOK, { reemplazada: true }); r = await validar(TOK);
  assert.deepEqual([r.status, r.body.motivo], [400, 'reemplazada']); assert.match(r.body.error, /reemplazada/);
  sembrar(TOK, { expiraEn: { __ts: iso(-1000) } }); r = await validar(TOK);
  assert.deepEqual([r.status, r.body.motivo], [400, 'vencida']); assert.match(r.body.error, /venció/);
  r = await validar(TOK.slice(0, -1)); assert.deepEqual([r.status, r.body.motivo], [400, 'invalida']);
  r = await validar(''); assert.deepEqual([r.status, r.body.motivo], [400, 'sin_codigo']);
  for (const x of [r.body, (await validar(TOK)).body]) assert.ok(!/Norma|Casa 2/.test(JSON.stringify(x)), 'no revela datos de la persona');
});
await t('el token se limpia: espacios, saltos y puntuación no lo rompen; las mayúsculas sí cuentan', async () => {
  sembrar(TOK);
  for (const x of [TOK + '\n', ' ' + TOK, TOK + '.', '#' + TOK + ' ', encodeURIComponent(TOK)]) assert.equal((await validar(x)).status, 200, JSON.stringify(x));
  assert.equal((await validar(TOK.toUpperCase())).body.motivo, 'invalida');
});
await t('intentos fallidos: se registran motivo, día e IP truncada con contador; NUNCA el token', async () => {
  sembrar(TOK, { usado: true });
  await validar(TOK); await validar(TOK); await validar('inexistente123', '2001:db8:abcd:1234::9');
  const docs = [...store].filter(([k]) => k.startsWith('registro_intentos/'));
  assert.equal(docs.length, 2);
  const u = docs.find(([k]) => k.endsWith('_usada'))[1];
  assert.equal(u.ip.stringValue, '203.0.113.0'); assert.equal(u.intentos.integerValue, '2'); assert.equal(u.motivo.stringValue, 'usada');
  const v6 = docs.find(([k]) => k.endsWith('_invalida'))[1];
  assert.equal(v6.ip.stringValue, '2001:db8:abcd::');
  const todo = JSON.stringify(docs);
  for (const s of [TOK, hashDe(TOK), 'inexistente123', '203.0.113.77']) assert.ok(!todo.includes(s), 'no debe quedar ' + s);
});
await t('un fallo al registrar el intento no cambia la respuesta', async () => {
  const f = globalThis.fetch;
  globalThis.fetch = async (u, o = {}) => { if (String(u).includes('registro_intentos')) throw new Error('caído'); return f(u, o); };
  try { const r = await validar('nada'); assert.deepEqual([r.status, r.body.motivo], [400, 'invalida']); } finally { globalThis.fetch = f; }
});
await t('reenviar: la anterior queda "reemplazada" (no se borra), la nueva sirve, y completar rechaza la vieja', async () => {
  const a = await call('/invitaciones/crear', 'uA', { personaId: 'pNorma-0000001' }); assert.equal(a.status, 200);
  const b = await call('/invitaciones/crear', 'uA', { personaId: 'pNorma-0000001' }); assert.equal(b.status, 200);
  assert.equal((await validar(a.body.token)).body.motivo, 'reemplazada');
  assert.equal((await validar(b.body.token)).status, 200);
  assert.ok(store.has(`registro_invitaciones/${hashDe(a.body.token)}`), 'la anterior se conserva');
  const c = await call('/invitaciones/completar', null, { token: a.body.token, email: 'x@y.com', password: 'abcdefgh1' });
  assert.equal(c.status, 400); assert.equal(authCalls.length, 0, 'no se creó ninguna cuenta con una liga reemplazada');
  const p = (await call('/personas/pendientes', 'uA')).body.pendientes.find(x => x.id === 'pNorma-0000001');
  assert.equal(p.liga.estado, 'viva');
  assert.deepEqual(p.historial.map(h => h.estado).sort(), ['reemplazada', 'vigente']);
});
await t('pendientes: historial con vigente, usada, vencida y reemplazada', async () => {
  put('registro_invitaciones/h1', { hashToken: 'h1', personaId: 'pNorma-0000001', usado: true, creadoEn: { __ts: iso(-4000) }, expiraEn: { __ts: iso(1e7) } });
  put('registro_invitaciones/h2', { hashToken: 'h2', personaId: 'pNorma-0000001', usado: false, reemplazada: true, creadoEn: { __ts: iso(-3000) }, expiraEn: { __ts: iso(1e7) } });
  put('registro_invitaciones/h3', { hashToken: 'h3', personaId: 'pNorma-0000001', usado: false, creadoEn: { __ts: iso(-2000) }, expiraEn: { __ts: iso(-100) } });
  put('registro_invitaciones/h4', { hashToken: 'h4', personaId: 'pNorma-0000001', usado: false, creadoEn: { __ts: iso(-1000) }, expiraEn: { __ts: iso(1e7) } });
  const p = (await call('/personas/pendientes', 'uA')).body.pendientes.find(x => x.id === 'pNorma-0000001');
  assert.deepEqual(p.historial.map(h => h.estado), ['vigente', 'vencida', 'reemplazada', 'usada']);
  assert.equal(p.liga.estado, 'viva');
});
console.error = quietLog;
console.log(`\n${pass} pruebas de invitaciones OK`);
