/* ===========================================================
   dispositivos-core.js — lógica PURA del módulo "Dispositivos" (cambiar un Shelly sin tocar secrets).
   Sin Firestore y sin secrets propios: todo llega por parámetros. Vive aparte (igual que
   shelly-core.js) para probarlo en local y para que worker.js no exporte nada extra.

   Modelo: config/dispositivos (Firestore, SOLO el Worker lo escribe) guarda, por puerta,
     <puerta>_id (string)  <puerta>_gen (1|2|3)  [<puerta>_offSec]
   más `historial` (JSON string, tope 100) y `version`. El secret SHELLY_DEVICES SIGUE siendo
   el respaldo: cualquier puerta cuyo dato falte, venga corrupto o no se pueda leer usa el secret.
   =========================================================== */

export const PUERTAS_DISP = ['visitantes', 'residentes', 'peatones', 'salida'];
export const ID_SHELLY_RE = /^[0-9a-fA-F]{6,16}$/;   // id de Shelly Cloud = MAC (o sus últimos bytes), hexadecimal
export const HISTORIAL_MAX = 100;

export const idShellyValido = id => typeof id === 'string' && ID_SHELLY_RE.test(id);
export const genValida = g => g === 1 || g === 2 || g === 3;

/* Convierte los campos ya leídos (readDoc) de config/dispositivos en { puertas, historial, version }.
   Tolerante a TODO: un campo ausente, de tipo raro o con un id mal formado descarta ESA puerta
   (cae al secret), jamás lanza. */
export function parsearDispositivos(d) {
  const out = { puertas: {}, historial: [], version: 0 };
  if (!d || typeof d !== 'object') return out;
  for (const p of PUERTAS_DISP) {
    const id = d[`${p}_id`], gen = d[`${p}_gen`];
    if (!idShellyValido(id) || !genValida(gen)) continue;
    const e = { id, gen };
    const off = d[`${p}_offSec`];
    if (gen >= 2 && Number.isFinite(off) && off > 0 && off <= 30) e.offSec = off;
    out.puertas[p] = e;
  }
  try {
    const h = JSON.parse(d.historial || '[]');
    if (Array.isArray(h)) out.historial = h.filter(x => x && typeof x === 'object' && PUERTAS_DISP.includes(x.puerta)).slice(-HISTORIAL_MAX);
  } catch (e) { /* historial ilegible: se ignora, no afecta las aperturas */ }
  out.version = Number.isFinite(d.version) ? d.version : 0;
  return out;
}

/* JSON en la forma que ya entiende resolveShellyDevice (shelly-core.js), o null si no hay nada válido. */
export function mapaParaTrigger(parsed) {
  const claves = Object.keys(parsed?.puertas || {});
  if (!claves.length) return null;
  const mapa = {};
  for (const p of claves) {
    const { id, gen, offSec } = parsed.puertas[p];
    mapa[p] = gen === 1 ? id : (offSec ? { id, gen, offSec } : { id, gen });
  }
  return JSON.stringify(mapa);
}

/* Dispositivo efectivo de una puerta: documento válido, si no el secret SHELLY_DEVICES (misma forma que
   shelly-core). Devuelve { id, gen, origen } o null si no hay ninguno. */
export function dispositivoEfectivo(parsed, secretJson, puerta) {
  const d = parsed?.puertas?.[puerta];
  if (d) return { id: d.id, gen: d.gen, origen: 'documento' };
  try {
    const m = JSON.parse(secretJson || 'null');
    const e = m && m[puerta];
    if (typeof e === 'string' && e) return { id: e, gen: 1, origen: 'secreto' };
    if (e && typeof e === 'object' && typeof e.id === 'string' && e.id) return { id: e.id, gen: (e.gen === 2 || e.gen === 3) ? e.gen : 1, origen: 'secreto' };
  } catch (e) { /* secret roto: sin dispositivo */ }
  return null;
}

/* ---- Consulta a Shelly Cloud (SOLO LECTURA: estado del dispositivo; nunca enciende nada) ----
   Cloud Control API: POST {host}/device/status (form id + auth_key) -> { isok, data:{ online, _dev_info:{gen} } }.
   Todos los comparativos son tolerantes; si no se puede determinar algo, se dice (nunca se inventa). El
   límite de Shelly Cloud (~1 req/s por cuenta) se respeta con una separación mínima entre consultas. */
let ultimaConsulta = 0;
const dormir = ms => new Promise(r => setTimeout(r, ms));
const ESPACIO_DEF_MS = 1300;   // env.SHELLY_STATUS_SPACING_MS lo cambia (las pruebas locales lo ponen en 0)

export function genDesdeInfo(info) {
  const g = info && (info.gen ?? info.generation);
  if (g === 1 || g === '1' || g === 'G1') return 1;
  if (g === 2 || g === '2' || g === 'G2') return 2;
  if (g === 3 || g === '3' || g === 'G3') return 3;
  if (g === 4 || g === '4' || g === 'G4') return 4;
  return null;
}

/* -> { existe, online, gen, error } ; nunca lanza. */
export async function consultarShelly(env, id, { timeoutMs = 6000 } = {}) {
  if (!idShellyValido(id)) return { existe: false, online: false, gen: null, error: 'formato' };
  if (!env.SHELLY_HOST || !env.SHELLY_AUTH_KEY) return { existe: false, online: false, gen: null, error: 'sin-credenciales' };
  const espera = ultimaConsulta + Number(env.SHELLY_STATUS_SPACING_MS ?? ESPACIO_DEF_MS) - Date.now();
  if (espera > 0) await dormir(espera);
  ultimaConsulta = Date.now();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const r = await fetch(`${env.SHELLY_HOST}/device/status`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ id, auth_key: env.SHELLY_AUTH_KEY }),
      signal: ctrl.signal,
    });
    const txt = await r.text().catch(() => '');
    if (r.status === 429 || /max_req/i.test(txt)) return { existe: false, online: false, gen: null, error: 'limite' };
    let j = null; try { j = JSON.parse(txt); } catch (e) { /* no JSON */ }
    if (!r.ok || !j) return { existe: false, online: false, gen: null, error: 'respuesta' };
    if (j.isok === false) return { existe: false, online: false, gen: null, error: 'no-existe' };
    const data = j.data || {};
    const online = data.online === true || data.online === 1;
    const gen = genDesdeInfo(data._dev_info) ?? genDesdeInfo(data.device_status && data.device_status._dev_info) ?? genDesdeInfo(data);
    return { existe: true, online, gen, error: null };
  } catch (e) {
    return { existe: false, online: false, gen: null, error: ctrl.signal.aborted ? 'timeout' : 'red' };
  } finally { clearTimeout(timer); }
}

/* ---- Lista de dispositivos de la cuenta (SOLO LECTURA) — para elegir el repuesto sin teclear su ID ----
   Dos consultas de lectura, manuales y espaciadas (el límite de Shelly Cloud es ~1 req/s por cuenta):
     1) POST {SHELLY_HOST}/device/all_status  (form: auth_key, show_info=true) — Cloud Control API v1: TODOS los
        dispositivos de la cuenta y su estado. NO trae el nombre que el usuario le puso en la app de Shelly.
     2) POST {SHELLY_HOST}/v2/devices/api/get?auth_key=...  (Cloud Control API v2, documentada; máx. 10 ids por petición)
        con body { ids:[...], select:["settings"], pick:{ settings:["name"] } } — devuelve, por id: id, type, code,
        gen ("G1"/"G2"/"G3"), online (0|1) y settings.name (el nombre de la app). Si esta consulta falla o un id no
        aparece (p. ej. un Gen1 que la v2 no cubra), se muestra ID + generación, sin inventar el nombre.
   La forma EXACTA de las respuestas reales se valida con diagnostico:true (campos y tipos, sin valores/IDs/llaves). */
const ALL_STATUS_PATH = '/device/all_status';
const objOrNull = o => (o && typeof o === 'object' && !Array.isArray(o)) ? o : null;

/* Generación por la FORMA del estado (cuando no la informa ningún campo): Gen1 trae wifi_sta/update/inputs;
   Gen2+ trae sys / "switch:0" / wifi. Gen2 y Gen3 se tratan igual en la nube (API v2): 3 si el modelo es "S3…". */
export function genPorForma(st, modelo) {
  const s = objOrNull(st) || {};
  const gen2 = 'sys' in s || 'switch:0' in s || (objOrNull(s.wifi) && !('wifi_sta' in s));
  const gen1 = 'wifi_sta' in s || 'inputs' in s || ('update' in s && !('sys' in s));
  if (gen2 && !gen1) return /^S3/i.test(String(modelo || '')) ? 3 : 2;
  if (gen1 && !gen2) return 1;
  return null;
}

/* Generación por MODELO (campo "code"). La API v2 reporta "G2" también para los Gen3 (comparten API), así que para MOSTRAR manda
   el prefijo: SH… = Gen1, SN… = Gen2, S3… = Gen3, S4… = Gen4. La OPERACIÓN no cambia: Gen2+ se opera igual (API v2 de la nube),
   por eso lo guardado/operativo se limita a 1|2|3 (genOperativa) y la etiqueta (genEtiqueta) es solo para mostrar. */
export function genPorModelo(code) {
  const c = String(code || '');
  if (/^SH/i.test(c)) return 1;
  if (/^SN/i.test(c)) return 2;
  const m = /^S(\d)/i.exec(c);
  return m ? +m[1] : null;
}
export const genOperativa = g => (g >= 3 ? 3 : g);

/* Nombre que el usuario le puso en la app de Shelly, desde el objeto settings de la API v2. Gen2+/Gen3: settings.sys.device.name;
   Gen1: settings.name (o settings.device.name). Devuelve { nombre, ruta } o null. NUNCA el nombre de un canal/relé. */
export function nombreDeSettings(settings) {
  const s = objOrNull(settings); if (!s) return null;
  const cand = [['settings.sys.device.name', s.sys && s.sys.device && s.sys.device.name], ['settings.name', s.name], ['settings.device.name', s.device && s.device.name]];
  for (const [ruta, v] of cand) if (typeof v === 'string' && v.trim()) return { nombre: v.trim(), ruta };
  return null;
}

/* ¿En línea?, con el criterio usado (para el diagnóstico). Prioridad:
   1) online de la API v2 (0|1) — autoritativo; 2) _dev_info.online / online — autoritativos;
   3) PISTAS cloud.connected (Gen1/Gen2) y ws.connected (Gen2+/Gen3): NO autoritativas (la nube devuelve el último estado
      conocido aunque el aparato ya esté apagado) => el Worker las confirma con la consulta por dispositivo.
   wifi_sta.connected / wifi.status / mqtt.connected NO cuentan: WiFi o MQTT sin nube no se puede controlar.
   Forma REAL observada de all_status (cuenta de Shelly Cloud, 2026-10-02): Gen1 = _updated, uptime, update, inputs[], mac, wifi_sta…;
   Gen3 = code, serial, ws, wifi, switch:0, sys, input:0… (sin _dev_info, sin nombre). */
export const criterioAutoritativo = c => c === 'v2.online' || c === '_dev_info.online' || c === 'online';
export function enLinea(st, inf, v2) {
  if (v2 && (v2.online === 0 || v2.online === 1 || typeof v2.online === 'boolean')) return { online: v2.online === 1 || v2.online === true, criterio: 'v2.online' };
  const di = objOrNull(st && st._dev_info) || objOrNull(inf && inf._dev_info) || {};
  for (const [c, v] of [['_dev_info.online', di.online], ['online', st && st.online], ['online', inf && inf.online]]) if (v !== undefined) return { online: v === true || v === 1, criterio: c };
  // PISTAS (no autoritativas): all_status devuelve el ÚLTIMO estado conocido aunque el Shelly ya esté apagado. El Worker
  // confirma con la consulta por dispositivo antes de ofrecer cualquier repuesto cuyo estado venga solo de una pista.
  const cc = objOrNull(st && st.cloud), ws = objOrNull(st && st.ws);
  if (cc && cc.connected !== undefined) return { online: cc.connected === true || cc.connected === 1, criterio: 'pista:cloud.connected' };
  if (ws && ws.connected !== undefined) return { online: ws.connected === true || ws.connected === 1, criterio: 'pista:ws.connected' };
  return { online: false, criterio: 'sin-dato' };
}

export function parsearListaShelly(j) {
  const root = objOrNull(j && j.data) || objOrNull(j) || {};
  const estados = objOrNull(root.devices_status) || {};
  let infos = root.devices;
  const mapaInfos = {};
  if (Array.isArray(infos)) infos.forEach(x => { if (x && typeof x.id === 'string') mapaInfos[x.id] = x; });
  else if (objOrNull(infos)) Object.assign(mapaInfos, infos);
  const ids = new Set([...Object.keys(estados), ...Object.keys(mapaInfos)]);
  const out = [];
  for (const id of ids) {
    const st = objOrNull(estados[id]) || {}, inf = objOrNull(mapaInfos[id]) || {};
    const di = objOrNull(st._dev_info) || objOrNull(inf._dev_info) || {};
    const modelo = [di.code, inf.code, inf.type, st.code].find(v => typeof v === 'string' && v) || null;
    const nombre = [inf.name, inf.device_name, di.name, st.name].find(v => typeof v === 'string' && v.trim()) || null;
    let genE = genPorModelo(modelo), criterioGen = genE ? 'code' : null;
    if (!genE) { genE = genDesdeInfo(di) ?? genDesdeInfo(inf); criterioGen = genE ? 'campo-gen' : null; }
    if (!genE) { genE = genPorForma(st, modelo); criterioGen = genE ? 'forma' : null; }
    const l = enLinea(st, inf, null);
    out.push({ id: String(di.id || inf.id || id), nombre, gen: genE ? genOperativa(genE) : null, genEtiqueta: genE, modelo, online: l.online, criterioOnline: l.criterio, criterioGen, criterioNombre: nombre ? 'all_status' : null });
  }
  return out;
}

/* Estructura de la respuesta (nombres de campos y tipos; NUNCA valores) para depurar el parser. Lista TODAS las llaves
   (tope de seguridad 400 por objeto y 6 niveles). Las llaves que parecen ids de dispositivo se anonimizan. */
export function formaDe(v, depth = 0) {
  if (Array.isArray(v)) return depth >= 6 ? 'array' : { _array: v.length, _item: v.length ? formaDe(v[0], depth + 1) : null };
  if (v && typeof v === 'object') {
    if (depth >= 6) return 'objeto';
    const ks = Object.keys(v), muestra = ks.slice(0, 400), o = {};
    muestra.forEach((k, i) => { o[/^[0-9a-f]{6,16}$/i.test(k) ? '<id-' + i + '>' : k] = formaDe(v[k], depth + 1); });
    if (ks.length > 400) o['…'] = ks.length - 400 + ' más';
    return o;
  }
  return v === null ? 'null' : typeof v;
}

async function peticionShelly(env, ruta, init, timeoutMs) {
  const espera = ultimaConsulta + Number(env.SHELLY_STATUS_SPACING_MS ?? ESPACIO_DEF_MS) - Date.now();
  if (espera > 0) await dormir(espera);
  ultimaConsulta = Date.now();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const r = await fetch(`${env.SHELLY_HOST}${ruta}`, { ...init, signal: ctrl.signal });
    const txt = await r.text().catch(() => '');
    let j = null; try { j = JSON.parse(txt); } catch (e) { /* no JSON */ }
    return { status: r.status, j, limitado: r.status === 429 || /max_req/i.test(txt) };
  } catch (e) { return { error: ctrl.signal.aborted ? 'timeout' : 'red' }; }
  finally { clearTimeout(timer); }
}

/* Nombres/estado/generación por la API v2 (máx. 10 ids por petición). -> { mapa: Map(id -> {nombre, gen, online, modelo}), forma, error } */
export async function consultarV2(env, ids, { timeoutMs = 8000 } = {}) {
  const mapa = new Map(); let forma = null, error = null;
  for (let i = 0; i < ids.length; i += 10) {
    const r = await peticionShelly(env, `/v2/devices/api/get?auth_key=${encodeURIComponent(env.SHELLY_AUTH_KEY)}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids: ids.slice(i, i + 10), select: ['settings'] }),   // SIN pick: "pick" solo acepta propiedades de primer nivel y el nombre cuelga de sys.device (Gen2+) o name (Gen1)
    }, timeoutMs);
    if (r.error || r.limitado || !r.j) { error = r.error || (r.limitado ? 'limite' : 'respuesta'); continue; }
    const lista = Array.isArray(r.j) ? r.j : (Array.isArray(r.j.data) ? r.j.data : []);
    for (const it of lista) {
      if (!it || typeof it.id !== 'string') continue;
      const nom = nombreDeSettings(it.settings);
      mapa.set(it.id.toLowerCase(), { nombre: nom ? nom.nombre : null, rutaNombre: nom ? nom.ruta : null, gen: genDesdeInfo(it), online: it.online, modelo: typeof it.code === 'string' ? it.code : null });
      // Para el diagnóstico: forma de UN dispositivo de cada generación (3 niveles de settings, solo nombres de campos)
      forma = forma || { _array: lista.length, _item: {} };
      const g = genPorModelo(it.code) ?? genDesdeInfo(it) ?? 0, clave = 'gen' + g;
      if (!(clave in forma._item)) forma._item[clave] = { ...Object.fromEntries(Object.keys(it).filter(k => k !== 'settings').map(k => [k, typeof it[k]])), settings: it.settings === undefined ? 'AUSENTE' : formaDe(it.settings, 3) };
    }
  }
  return { mapa, forma, error };
}

/* -> { ok, dispositivos, forma, formaV2, errorV2, error } ; nunca lanza ni devuelve la llave. */
export async function listarDispositivosCuenta(env, { timeoutMs = 8000 } = {}) {
  if (!env.SHELLY_HOST || !env.SHELLY_AUTH_KEY) return { ok: false, dispositivos: [], forma: null, error: 'sin-credenciales' };
  const r = await peticionShelly(env, ALL_STATUS_PATH, {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ auth_key: env.SHELLY_AUTH_KEY, show_info: 'true' }),
  }, timeoutMs);
  if (r.error) return { ok: false, dispositivos: [], forma: null, error: r.error };
  if (r.limitado) return { ok: false, dispositivos: [], forma: null, error: 'limite' };
  if (r.status < 200 || r.status >= 300 || !r.j) return { ok: false, dispositivos: [], forma: null, error: 'respuesta' };
  if (r.j.isok === false) return { ok: false, dispositivos: [], forma: formaDe(r.j), error: 'rechazado' };
  const dispositivos = parsearListaShelly(r.j);
  const forma = formaDe(r.j);
  // Enriquecer con la API v2: nombre de la app, generación ("G1/G2/G3") y online (0|1) — autoritativos si están.
  const estados = objOrNull(objOrNull(r.j.data) ? r.j.data.devices_status : r.j.devices_status) || {};
  let formaV2 = null, errorV2 = null;
  if (dispositivos.length) {
    const v2 = await consultarV2(env, dispositivos.map(d => d.id), { timeoutMs });
    formaV2 = v2.forma; errorV2 = v2.error;
    for (const d of dispositivos) {
      const x = v2.mapa.get(d.id.toLowerCase()); if (!x) continue;
      if (x.nombre) { d.nombre = x.nombre; d.criterioNombre = x.rutaNombre; }
      if (x.modelo && !d.modelo) d.modelo = x.modelo;
      const gm = genPorModelo(d.modelo);
      if (gm) { d.genEtiqueta = gm; d.gen = genOperativa(gm); d.criterioGen = 'code'; }
      else if (x.gen && !d.genEtiqueta) { d.genEtiqueta = x.gen; d.gen = genOperativa(x.gen); d.criterioGen = 'v2.gen'; }
      const l = enLinea(objOrNull(estados[d.id]) || {}, null, x);
      if (l.criterio === 'v2.online') { d.online = l.online; d.criterioOnline = 'v2.online'; }
    }
  }
  return { ok: true, dispositivos, forma, formaV2, errorV2, error: null };
}
