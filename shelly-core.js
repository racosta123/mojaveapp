/* ===========================================================
   shelly-core.js — lógica de Shelly Cloud (selector Gen1/Gen2+, llamada, triggerShelly).
   Vive aparte de worker.js para que worker.js NO exporte nada extra a Cloudflare y esta
   lógica se pueda probar en local (test/shelly-gen.test.mjs). Sin secrets: todo llega por env.
   =========================================================== */

/* Único punto de salida hacia Shelly Cloud (lo usan /abrir y consumirInvitacion). NO llama a
   Shelly directamente: entrega la orden al Durable Object "shelly-gate" (una sola instancia
   global), que serializa y espacia TODAS las llamadas de la cuenta (el límite de Shelly Cloud
   es ~1 req/s por Cloud Key, compartido por todas las puertas). Mismo contrato de errores que
   antes: falla => httpErr(status, mensaje) => {error} con ese status. */
/* Lee el secret SHELLY_DEVICES y devuelve el dispositivo de esa puerta como
   { id, gen, offSec }, o null si el secret falta, está mal formado, o esa puerta no tiene
   entrada (sin hardware asignado todavía — hoy: salida). Nunca lanza ni loguea el contenido
   del secret ni el motivo exacto de un JSON roto: solo null, para que triggerShelly responda
   el mismo error genérico en ambos casos ("puerta sin dispositivo configurado").

   Dos formas aceptadas por entrada (conviven en el mismo JSON y la misma cuenta de Shelly):
     "residentes": "aaaaaaaaaaaa"                    -> Gen1 (forma clásica, DEFAULT SEGURO)
     "visitantes": { "id": "bbbbbbbbbbbb", "gen": 3 } -> Gen2+/Gen3 (API de nube v2)
   Un string pelado, o un objeto sin "gen" (o con gen != 2/3), se trata como Gen1: así las
   puertas que NO cambian conservan exactamente el comportamiento de hoy aunque su entrada no
   se toque. "gen" solo activa la API v2 cuando vale 2 o 3, nunca por accidente.
     offSec: auto-off (segundos) que se manda EN la petición. Solo aplica a Gen2+ (toggle_after);
     en Gen1 siempre 0 => no se manda apagado, se respeta el auto-off físico del propio Shelly
     (comportamiento de hoy, intacto). Default Gen2+ = 2 s; se puede fijar por entrada con offSec. */
export function resolveShellyDevice(env, puerta) {
  if (!env.SHELLY_DEVICES) return null;
  let mapa;
  try { mapa = JSON.parse(env.SHELLY_DEVICES); } catch (e) { return null; }
  if (!mapa || typeof mapa !== 'object' || Array.isArray(mapa)) return null;
  const entry = mapa[puerta];
  // Forma clásica: string = deviceId Gen1 (default seguro, sin apagado explícito).
  if (typeof entry === 'string' && entry) return { id: entry, gen: 1, offSec: 0 };
  // Forma nueva: objeto { id, gen, offSec? }.
  if (entry && typeof entry === 'object' && !Array.isArray(entry) && typeof entry.id === 'string' && entry.id) {
    const gen = (entry.gen === 2 || entry.gen === 3) ? entry.gen : 1;  // cualquier otra cosa => Gen1
    const offSec = gen >= 2
      ? (Number.isFinite(entry.offSec) && entry.offSec > 0 ? entry.offSec : 2)  // Gen2+: default 2 s
      : 0;                                                                       // Gen1: nunca (auto-off físico)
    return { id: entry.id, gen, offSec };
  }
  return null;
}

export async function triggerShelly(env, puerta, mapaVigente) {
  // Resuelto y validado ANTES de tocar el portero de fila: una puerta sin Shelly asignado (o un
  // secret SHELLY_DEVICES roto) falla YA, rápido y con mensaje genérico — nunca entra a la cola
  // del Durable Object ni intenta una llamada real a Shelly, en ningún modo.
  // mapaVigente (opcional, JSON como SHELLY_DEVICES) viene de config/dispositivos (módulo Dispositivos). Si falta, no
  // trae esta puerta o no sirve, se usa EXACTAMENTE el secret de siempre: el respaldo nunca deja de funcionar.
  const device = (mapaVigente && resolveShellyDevice({ SHELLY_DEVICES: mapaVigente }, puerta)) || resolveShellyDevice(env, puerta);
  if (!device) throw httpErr(503, 'Puerta sin dispositivo configurado');

  // "0" exacto = modo directo (bypass del portero, solo para el A/B de tiempos). Cualquier otro
  // valor, vacío o ausente = portero (modo seguro por defecto) — ver SHELLY_GATE_ENABLED arriba.
  const directo = env.SHELLY_GATE_ENABLED === '0';
  const t0 = Date.now();
  let out = null;

  if (directo) {
    // Llamada directa a Shelly Cloud: misma función (callShellyOnce), mismo timeout, mismos
    // secrets — SIN pasar por la cola/espaciado/dedupe del Durable Object.
    try { out = await callShellyOnce(env, device, puerta); }
    catch (e) { /* callShellyOnce no debería lanzar, pero por si acaso: mismo error genérico */ }
  } else {
    if (!env.SHELLY_GATE) throw httpErr(500, 'Portero de fila no configurado');
    try {
      const stub = env.SHELLY_GATE.get(env.SHELLY_GATE.idFromName(SHELLY_GATE_NAME));
      const r = await stub.fetch('https://shelly-gate/abrir', {
        method: 'POST',
        body: JSON.stringify({ deviceId: device.id, label: puerta, gen: device.gen, offSec: device.offSec }),
      });
      out = await r.json();
    } catch (e) { /* DO inalcanzable o respuesta ilegible => mismo error que "no respondió" */ }
  }

  // Log de tiempo por apertura, en ambos modos — nunca deviceId, host, ni llave, solo el nombre
  // de la puerta (igual que el resto de logs de este archivo).
  const ms = Date.now() - t0;
  const ok = !!(out && out.ok === true);
  console.log(`[shelly] modo=${directo ? 'directo' : 'portero'}, puerta=${puerta}, ms=${ms}, resultado=${ok ? 'ok' : 'error'}${out?.limitado ? ', max_req=si' : ''}`);

  if (!ok) throw httpErr(out?.status || 502, out?.error || 'La cerradura no respondió');
}

export const SHELLY_GATE_NAME = 'shelly-gate';
const SHELLY_DEFAULTS = {
  SHELLY_MIN_SPACING_MS:    1200,   // separación mínima entre llamadas reales a Shelly
  SHELLY_RETRY_DELAY_MS:    1500,   // pausa antes del único reintento por max_req / 429
  SHELLY_CALL_TIMEOUT_MS:   8000,   // tope de UNA llamada a Shelly; al vencer se aborta => 502
  SHELLY_MAX_QUEUE_WAIT_MS: 20000,  // tope de espera en fila antes de responder "reintenta"
  SHELLY_DEDUPE_WINDOW_MS:  2000,   // ventana para juntar el mismo "abrir" a la misma puerta
};
export const shellySleep = ms => new Promise(r => setTimeout(r, ms));

export function shellyCfg(env, name) {
  const v = Number(env[name]);
  return Number.isFinite(v) && v >= 0 ? v : SHELLY_DEFAULTS[name];
}

/* Única llamada real a Shelly Cloud (turn=on), con el mismo timeout (SHELLY_CALL_TIMEOUT_MS) y
   el mismo reintento por max_req/429 (SHELLY_RETRY_DELAY_MS) en ambos modos — ShellyGate.callShelly
   de abajo delega aquí, no es una copia. Lo único que decide "portero" vs "directo" (ver
   SHELLY_GATE_ENABLED / triggerShelly) es si esta llamada pasa antes por la cola/espaciado/dedupe
   del Durable Object o no; el pulso a Shelly en sí es idéntico. Nunca loguea deviceId, host, ni
   la auth key — mismo criterio que el resto del archivo. limitado:true si CUALQUIER intento de
   esta llamada topó con max_req/429 (haya terminado en éxito tras reintentar, o en fallo). */
export async function callShellyOnce(env, device, label) {
  const deviceId = device && device.id;
  const gen = (device && device.gen) || 1;
  const offSec = (device && device.offSec) || 0;
  let sawLimitado = false;
  const fail = () => ({ ok:false, status:502, error:'La cerradura no respondió', limitado: sawLimitado });
  for (let attempt = 1; attempt <= 2; attempt++) {
    if (attempt === 2) await shellySleep(shellyCfg(env, 'SHELLY_RETRY_DELAY_MS'));
    const ctrl = new AbortController();
    const timeoutMs = shellyCfg(env, 'SHELLY_CALL_TIMEOUT_MS');
    const timer = timeoutMs > 0 ? setTimeout(() => ctrl.abort(), timeoutMs) : null;
    let r, txt = '';
    try {
      if (gen >= 2) {
        // Gen2+/Gen3 (p.ej. Shelly 1 Gen3 S3SW-001X16EU): Shelly Cloud Control API v2.
        //   POST {host}/v2/devices/api/set/switch?auth_key=...   body JSON  { id, channel, on, toggle_after? }
        // El auth_key viaja en el query porque así lo exige la API v2; esta URL NUNCA se loguea
        // (los logs de este archivo solo llevan el nombre de la puerta, jamás host/id/llave).
        // toggle_after = apagado automático PEDIDO EN la petición: el propio dispositivo agenda
        // el OFF, así el pulso se cierra aunque se pierda la respuesta de la nube.
        const payload = { id: deviceId, channel: 0, on: true };
        if (offSec > 0) payload.toggle_after = offSec;
        r = await fetch(`${env.SHELLY_HOST}/v2/devices/api/set/switch?auth_key=${encodeURIComponent(env.SHELLY_AUTH_KEY)}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
          signal: ctrl.signal,
        });
      } else {
        // Gen1 (SHSW-1): API de nube clásica — IDÉNTICA a como estaba. Un solo turn=on, sin
        // apagado explícito: lo cierra el auto-off configurado FÍSICAMENTE en el propio Shelly.
        const body = new URLSearchParams({
          id: deviceId,
          channel: '0',
          turn: 'on',
          auth_key: env.SHELLY_AUTH_KEY,
        });
        r = await fetch(`${env.SHELLY_HOST}/device/relay/control`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body,
          signal: ctrl.signal,
        });
      }
      txt = await r.text().catch(() => '');
    } catch (e) {
      if (ctrl.signal.aborted) console.warn(`[shelly] TIMEOUT de llamada puerta=${label} intento=${attempt} tras ${timeoutMs}ms`);
      else console.warn(`[shelly] error de red puerta=${label} intento=${attempt}`);
      return fail();
    } finally {
      clearTimeout(timer);
    }
    const limitado = r.status === 429 || /max_req/i.test(txt);
    if (limitado) sawLimitado = true;
    if (r.ok && !limitado) return { ok:true, limitado: sawLimitado };
    if (limitado && attempt === 1) {
      console.warn(`[shelly] max_req/429 puerta=${label} status=${r.status}; reintento en ${shellyCfg(env, 'SHELLY_RETRY_DELAY_MS')}ms`);
      continue;
    }
    console.warn(`[shelly] Shelly falló puerta=${label} status=${r.status} intento=${attempt}`);
    return fail();
  }
  return fail();
}


// Mismo contrato que httpErr de worker.js (Error con .status).
function httpErr(status, msg){ const e=new Error(msg); e.status=status; return e; }
