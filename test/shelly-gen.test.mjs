// Pruebas del selector Gen1/Gen3 y de triggerShelly. Ejecutar:  node test/shelly-gen.test.mjs
// Importa el código REAL (shelly-core.js / worker.js) con fetch simulado: no toca la red ni usa
// secrets reales (todos los valores de abajo son de prueba). El Worker de producción NO importa
// este archivo.
import assert from 'node:assert/strict';
import { resolveShellyDevice, triggerShelly, callShellyOnce } from '../shelly-core.js';
import { ShellyGate } from '../worker.js';

let calls = [];
let respond = () => ({ ok: true, status: 200, text: 'ok' });
globalThis.fetch = async (url, opts = {}) => {
  calls.push({ url: String(url), opts });
  const r = respond();
  return { ok: r.ok, status: r.status, async text() { return r.text; } };
};
const realLog = console.log, realWarn = console.warn;
let mute = 0;   // contador: seguro con llamadas concurrentes (ráfagas)
const quiet = (fn) => async (...a) => { mute++; console.log = console.warn = () => {}; try { return await fn(...a); } finally { if (--mute === 0) { console.log = realLog; console.warn = realWarn; } } };

const DEVICES = {
  visitantes: { id: 'aaaaaaaaaaaa', gen: 3 },
  residentes: { id: 'bbbbbbbbbbbb', gen: 1 },
  peatones:   'PEATONES_TEST_ID',   // sin cambios: forma clásica (string = Gen1)
  // salida: ausente => 503
};
const base = { SHELLY_HOST: 'https://host.test', SHELLY_AUTH_KEY: 'LLAVE_TEST' };
const envDirecto = { ...base, SHELLY_GATE_ENABLED: '0', SHELLY_DEVICES: JSON.stringify(DEVICES) };

let pass = 0;
const t = async (name, fn) => { calls = []; respond = () => ({ ok: true, status: 200, text: 'ok' }); await fn(); pass++; console.log('  ok -', name); };
const rejects = async (p, status, msg) => { try { await p; } catch (e) { assert.equal(e.status, status); if (msg) assert.equal(e.message, msg); return e; } assert.fail('debía rechazar'); };

console.log('\n[1] resolveShellyDevice');
await t('visitantes = Gen3 offSec 2',  () => assert.deepEqual(resolveShellyDevice(envDirecto, 'visitantes'), { id: 'aaaaaaaaaaaa', gen: 3, offSec: 2 }));
await t('residentes = Gen1 offSec 0',  () => assert.deepEqual(resolveShellyDevice(envDirecto, 'residentes'), { id: 'bbbbbbbbbbbb', gen: 1, offSec: 0 }));
await t('peatones string = Gen1',      () => assert.deepEqual(resolveShellyDevice(envDirecto, 'peatones'), { id: 'PEATONES_TEST_ID', gen: 1, offSec: 0 }));
await t('salida ausente = null',       () => assert.equal(resolveShellyDevice(envDirecto, 'salida'), null));
await t('JSON roto / ausente = null',  () => { assert.equal(resolveShellyDevice({ SHELLY_DEVICES: '{x' }, 'visitantes'), null); assert.equal(resolveShellyDevice({}, 'visitantes'), null); });
await t('gen inválido => Gen1',        () => assert.deepEqual(resolveShellyDevice({ SHELLY_DEVICES: JSON.stringify({ p: { id: 'x', gen: 99 } }) }, 'p'), { id: 'x', gen: 1, offSec: 0 }));
await t('objeto sin id = null',        () => assert.equal(resolveShellyDevice({ SHELLY_DEVICES: JSON.stringify({ p: { gen: 3 } }) }, 'p'), null));
await t('formato VIEJO del secret (todo strings) => todo Gen1 (orden de despliegue seguro)', () => {
  const viejo = { SHELLY_DEVICES: JSON.stringify({ visitantes: 'ID_VIEJO_V', residentes: 'ID_VIEJO_R', peatones: 'P' }) };
  for (const p of ['visitantes', 'residentes', 'peatones']) assert.equal(resolveShellyDevice(viejo, p).gen, 1);
});

console.log('\n[2] MODO DIRECTO (SHELLY_GATE_ENABLED="0", camino real de producción) vía triggerShelly');
await t('visitantes (Gen3): POST v2 JSON, on:true, toggle_after:2, auth_key en query', async () => {
  await quiet(triggerShelly)(envDirecto, 'visitantes');
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, 'https://host.test/v2/devices/api/set/switch?auth_key=LLAVE_TEST');
  assert.equal(calls[0].opts.method, 'POST');
  assert.equal(calls[0].opts.headers['Content-Type'], 'application/json');
  assert.deepEqual(JSON.parse(calls[0].opts.body), { id: 'aaaaaaaaaaaa', channel: 0, on: true, toggle_after: 2 });
});
await t('residentes (Gen1): endpoint clásico idéntico a hoy, sin toggle_after', async () => {
  await quiet(triggerShelly)(envDirecto, 'residentes');
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, 'https://host.test/device/relay/control');
  assert.equal(calls[0].opts.method, 'POST');
  assert.equal(calls[0].opts.headers['Content-Type'], 'application/x-www-form-urlencoded');
  const p = new URLSearchParams(calls[0].opts.body);
  assert.deepEqual([...p.keys()].sort(), ['auth_key', 'channel', 'id', 'turn']);   // exactamente los 4 campos de hoy
  assert.equal(p.get('id'), 'bbbbbbbbbbbb'); assert.equal(p.get('channel'), '0'); assert.equal(p.get('turn'), 'on'); assert.equal(p.get('auth_key'), 'LLAVE_TEST');
});
await t('peatones: igual que hoy (Gen1 clásico)', async () => {
  await quiet(triggerShelly)(envDirecto, 'peatones');
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, 'https://host.test/device/relay/control');
  const p = new URLSearchParams(calls[0].opts.body);
  assert.deepEqual([...p.keys()].sort(), ['auth_key', 'channel', 'id', 'turn']);
  assert.equal(p.get('id'), 'PEATONES_TEST_ID'); assert.equal(p.get('turn'), 'on');
});
await t('salida (sin dispositivo): 503 inmediato, SIN llamar a Shelly', async () => {
  const t0 = Date.now();
  await rejects(triggerShelly(envDirecto, 'salida'), 503, 'Puerta sin dispositivo configurado');
  assert.equal(calls.length, 0);
  assert.ok(Date.now() - t0 < 50, 'debe ser rápido');
});
await t('secret roto: 503 genérico, sin llamar a Shelly', async () => {
  await rejects(triggerShelly({ ...envDirecto, SHELLY_DEVICES: '{roto' }, 'visitantes'), 503, 'Puerta sin dispositivo configurado');
  assert.equal(calls.length, 0);
});
await t('error de Shelly (500 con cuerpo crudo) => 502 genérico, sin filtrar id/host/cuerpo', async () => {
  respond = () => ({ ok: false, status: 500, text: 'DEVICE_OFFLINE id=aaaaaaaaaaaa host.test LLAVE_TEST' });
  const e = await rejects(quiet(triggerShelly)(envDirecto, 'visitantes'), 502, 'La cerradura no respondió');
  for (const s of ['aaaaaaaaaaaa', 'host.test', 'LLAVE_TEST', 'DEVICE_OFFLINE']) assert.ok(!e.message.includes(s));
});
await t('modo directo con ráfaga: cada tap = una llamada, todas v2 para Gen3 (sin cola)', async () => {
  await Promise.all([1, 2, 3].map(() => quiet(triggerShelly)(envDirecto, 'visitantes')));
  assert.equal(calls.length, 3);
  assert.ok(calls.every(c => c.url.includes('/v2/devices/api/set/switch')));
});

console.log('\n[3] Logs: no filtran id, host ni llave');
await t('logs de apertura sin datos sensibles (Gen3 y Gen1)', async () => {
  const lines = [];
  console.log = (...a) => lines.push(a.join(' ')); console.warn = (...a) => lines.push(a.join(' '));
  try { await triggerShelly(envDirecto, 'visitantes'); await triggerShelly(envDirecto, 'residentes'); } finally { console.log = realLog; console.warn = realWarn; }
  assert.ok(lines.length > 0);
  for (const s of ['aaaaaaaaaaaa', 'bbbbbbbbbbbb', 'host.test', 'LLAVE_TEST']) assert.ok(!lines.join('\n').includes(s), `log filtra ${s}`);
});

console.log('\n[4] Modo portero (referencia): dedupe y método por generación');
await t('ráfaga Gen3 por el portero: menos llamadas que taps, todas v2', async () => {
  const gate = new ShellyGate({}, { ...envDirecto, SHELLY_MIN_SPACING_MS: '0' });
  const dev = resolveShellyDevice(envDirecto, 'visitantes');
  const res = await quiet(() => Promise.all([1, 2, 3].map(() => gate.enqueue(dev.id, 'visitantes', dev.gen, dev.offSec))))();
  assert.ok(res.every(r => r.ok));
  assert.ok(calls.length < 3);
  assert.ok(calls.every(c => c.url.includes('/v2/devices/api/set/switch')));
});

console.log(`\nTODAS LAS PRUEBAS PASARON (${pass})`);
