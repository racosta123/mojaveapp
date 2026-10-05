/* ===========================================================
   Cerrada Mojave · Cloudflare Worker (mojave-proxy)
   El ÚNICO que toca la Shelly. El cliente jamás ve la IP ni la llave.
   -----------------------------------------------------------
   Secrets (wrangler secret put ...):
     SHELLY_HOST          server URI de Shelly Cloud, https://...
     SHELLY_AUTH_KEY      Authorization cloud key de Shelly Cloud
     SHELLY_DEVICES       JSON {"residentes":"<deviceId>","visitantes":"<deviceId>",...} —
                          repo público: los IDs de cada Shelly NUNCA van en el código, solo aquí.
                          Puerta sin entrada en el JSON = sin hardware asignado todavía.
     FIREBASE_PROJECT     (id del proyecto Firebase de Mojave)
     GOOGLE_CREDENTIALS   JSON de la cuenta de servicio (Admin) — único secret de credenciales en Mojave.
                          (SA_EMAIL + SA_PRIVATE_KEY siguen funcionando si existen y tienen prioridad.)
   Vars (wrangler.toml [vars]):
     ALLOWED_ORIGIN       (origen de GitHub Pages de Mojave — ver wrangler.toml)
     SHELLY_GATE_ENABLED  "1" (default, seguro) = toda llamada pasa por el portero de fila.
                          "0" = bypass del portero: llamada directa a Shelly Cloud (mismo
                          timeout, mismos secrets, SIN cola/espaciado/dedupe). Cualquier valor
                          raro o ausente = "1". Solo para A/B de tiempos — ver triggerShelly().
     SHELLY_MIN_SPACING_MS / SHELLY_RETRY_DELAY_MS / SHELLY_MAX_QUEUE_WAIT_MS /
     SHELLY_DEDUPE_WINDOW_MS / SHELLY_CALL_TIMEOUT_MS   ajustes del portero de fila (ver ShellyGate más abajo)
   Durable Object: SHELLY_GATE (clase ShellyGate) — toda llamada a Shelly Cloud pasa por él,
     salvo que SHELLY_GATE_ENABLED="0" (la vinculación sigue existiendo, solo se deja de usar).
   =========================================================== */

// Lógica de Shelly Cloud (selector Gen1/Gen2+, llamada, triggerShelly) en módulo aparte.
import { triggerShelly, callShellyOnce, shellyCfg, shellySleep } from './shelly-core.js';
// Módulo "Dispositivos" (cambiar un Shelly desde la app): lógica pura aparte, igual que shelly-core.
import { PUERTAS_DISP, idShellyValido, parsearDispositivos, mapaParaTrigger, dispositivoEfectivo, consultarShelly, listarDispositivosCuenta, criterioAutoritativo, HISTORIAL_MAX } from './dispositivos-core.js';

// Nombres de puerta válidos. Los IDs reales de cada Shelly YA NO viven en el código (repo
// público): se leen en tiempo de petición del secret SHELLY_DEVICES vía resolveShellyDevice()
// (más abajo, junto a triggerShelly). Una puerta sin entrada en ese JSON (peatones/salida hoy,
// sin hardware instalado) responde error claro en vez de intentar hablarle a un Shelly que no existe.
const PUERTAS = new Set([
  'residentes',  // barrera vehicular de residentes
  'visitantes',  // barrera vehicular de visitas/morosos
  'peatones',    // puerta peatonal
  'salida',      // puerta de salida
]);

// Lectores físicos (QR + PIN) de invitaciones de visita — 4 lectores, cada uno atado a UNA
// puerta de PUERTAS y a una dirección. Dos lectores pueden compartir la misma puerta (peatonal
// entrada/salida son el mismo Shelly, distinto lector físico) — por eso este mapeo vive aparte
// de PUERTAS, no lo reemplaza. readerId lo manda el lector físico en el body (mismo READER_KEY
// compartido para los 4, igual que hoy — ver validarQR/validarPin).
const READERS = {
  'visitantes-entrada': { puerta: 'visitantes', direccion: 'entrada' },
  'peatonal-entrada':   { puerta: 'peatones',   direccion: 'entrada' },
  'peatonal-salida':    { puerta: 'peatones',   direccion: 'salida'  },
  'salida-vehicular':   { puerta: 'salida',     direccion: 'salida'  },
};

const STAFF = new Set(['master','admin']);

/* FASE 7 — esAdmin: un JEFE de familia (rol 'residente' sin jefeId) puede tener además
   esAdmin:true y ganar poderes de staff, conservando casa/cuota/voto/familiares. NO es una
   segunda cuenta ni un rol nuevo: es un permiso aditivo que SOLO el master prende/apaga
   (/personas/admin). El "modo" del front es cosmético; el permiso real se decide AQUÍ,
   releyendo el perfil de Firestore en cada petición.
   El check de estado va solo en la rama esAdmin: master/admin no se suspenden, pero un jefe
   SÍ (por mora) — y un jefe suspendido no debe conservar los poderes de admin. */
function esStaff(p) {
  if (!p) return false;
  if (STAFF.has(p.rol)) return true;
  return p.esAdmin === true && (p.estado || 'activo') === 'activo';
}
/* Vista de "persona del padrón" (no del perfil): a un staff solo lo toca el MASTER — un
   admin no suspende, reactiva ni edita a otro admin. */
function esStaffPersona(p) {
  return !!p && (p.rol === 'master' || p.rol === 'admin' || p.esAdmin === true);
}

export default {
  async fetch(req, env) {
    const reqOrigin = req.headers.get('Origin') || '';
    const allowed = new Set([env.ALLOWED_ORIGIN].filter(Boolean));
    const origin = allowed.has(reqOrigin) ? reqOrigin : (env.ALLOWED_ORIGIN || '*');
    if (req.method === 'OPTIONS') return cors(new Response(null,{status:204}), origin);

    const url = new URL(req.url);
    try {
      let out;
      switch (url.pathname) {
        case '/abrir':             out = await abrir(req, env); break;
        case '/invitacion/crear':  out = await crearInvitacion(req, env); break;
        case '/validar-qr':        out = await validarQR(req, env); break;  // lo llama el lector físico
        case '/validar-pin':       out = await validarPin(req, env); break; // idem, código de respaldo
        case '/finanzas/registrar': out = await registrarFinanza(req, env); break;
        case '/finanzas/resumen':  out = await resumenFinanzas(req, env); break;
        case '/finanzas/cobranza': out = await cobranzaFinanzas(req, env); break;
        case '/finanzas/marcar-recibo': out = await marcarRecibo(req, env); break;
        case '/finanzas/cancelar': out = await cancelarFinanza(req, env); break;
        case '/finanzas/corregir': out = await corregirFinanza(req, env); break;
        case '/finanzas/reactivar': out = await reactivarFinanza(req, env); break;
        case '/finanzas/estado-cuenta': out = await estadoCuentaFinanzas(req, env); break;
        case '/cobranza/aviso-pago':     out = await avisoPagoCasa(req, env); break;
        case '/config/cobranza':            out = await obtenerConfigCobranza(req, env); break;
        case '/config/cobranza-actualizar': out = await actualizarConfigCobranza(req, env); break;
        case '/vecinos/crear':     out = await crearVecino(req, env); break;
        case '/vecinos/actualizar': out = await actualizarVecino(req, env); break;
        case '/vecinos/borrar':    out = await borrarVecino(req, env); break;
        case '/vecinos/listar':    out = await listarVecinos(req, env); break;
        case '/invitaciones/crear':    out = await crearInvitacionRegistro(req, env); break;
        case '/invitaciones/validar':  out = await validarInvitacionRegistro(req, env); break;
        case '/invitaciones/completar': out = await completarInvitacionRegistro(req, env); break;
        case '/usuarios/crear':    out = await crearUsuario(req, env); break;
        case '/usuarios/suspender': out = await suspenderUsuario(req, env); break;
        case '/usuarios/borrar':   out = await borrarUsuario(req, env); break;
        case '/personas/crear':     out = await crearPersona(req, env); break;
        case '/personas/actualizar': out = await actualizarPersona(req, env); break;
        case '/personas/suspender': out = await suspenderPersona(req, env); break;
        case '/personas/reactivar': out = await reactivarPersona(req, env); break;
        case '/personas/borrar':    out = await borrarPersona(req, env); break;
        case '/personas/admin':     out = await adminPersona(req, env); break;
        case '/personas/listar':    out = await listarPersonas(req, env); break;
        case '/personas/mis-familiares': out = await misFamiliares(req, env); break;
        case '/personas/familiar-cancelar': out = await cancelarFamiliar(req, env); break;
        case '/personas/alerta-revisar': out = await revisarAlertaFamiliar(req, env); break;
        case '/personas/pendientes':     out = await pendientesPersonas(req, env); break;
        case '/personas/alta-cancelar':  out = await cancelarAlta(req, env); break;
        case '/personas/duplicado-revisar': out = await revisarDuplicadoPersona(req, env); break;
        case '/personas/baja':           out = await darDeBajaPersona(req, env); break;
        case '/dispositivos/listar':     out = await listarDispositivos(req, env); break;
        case '/dispositivos/estado':     out = await estadoDispositivo(req, env); break;
        case '/dispositivos/verificar':  out = await verificarDispositivo(req, env); break;
        case '/dispositivos/disponibles': out = await disponiblesDispositivos(req, env); break;
        case '/dispositivos/cambiar':    out = await cambiarDispositivo(req, env); break;
        case '/dispositivos/revertir':   out = await revertirDispositivo(req, env); break;
        case '/dispositivos/probar':     out = await probarDispositivo(req, env); break;
        case '/invitaciones/familiar': out = await crearInvitacionFamiliar(req, env); break;
        case '/invitaciones/familiar-reenviar': out = await reenviarInvitacionFamiliar(req, env); break;
        case '/votaciones/crear':         out = await crearVotacion(req, env); break;
        case '/votaciones/cerrar':        out = await cerrarVotacion(req, env); break;
        case '/votaciones/votar':         out = await votarVotacion(req, env); break;
        case '/votaciones/estado':        out = await estadoVotacion(req, env); break;
        case '/votaciones/participacion': out = await participacionVotacion(req, env); break;
        case '/votaciones/historial':     out = await historialVotaciones(req, env); break;
        case '/votaciones/participantes':  out = await participantesVotacion(req, env); break;
        case '/admin/probar-suspension-automatica': out = await probarSuspensionAutomatica(req, env); break;
        case '/admin/simular-recordatorio-pago': out = await simularRecordatorioPago(req, env); break;
        default: out = json({ error:'Ruta no encontrada' }, 404);
      }
      return cors(out, origin);
    } catch (e) {
      return cors(json({ error: e.message || 'Error interno' }, e.status || 500), origin);
    }
  },

  // Cron Trigger (wrangler.toml [triggers]) — corre todos los días; aplicarSuspensionAutomatica
  // decide internamente si le toca actuar (día >= 5 Hermosillo, una vez por mes). ctx.waitUntil
  // evita que el Worker se corte antes de terminar el recorrido de personas/finanzas.
  async scheduled(event, env, ctx) {
    ctx.waitUntil(aplicarSuspensionAutomatica(env));
    // Recordatorio push (días 1 y 3). Aparte y con su propio try/catch: nunca afecta la suspensión.
    ctx.waitUntil(enviarRecordatoriosPago(env));
  },
};

/* ============ /abrir — usuario autenticado abre una puerta ============ */
async function abrir(req, env) {
  const user = await requireAuth(req, env);
  const { puerta } = await req.json();
  if (!PUERTAS.has(puerta)) throw httpErr(400, 'Puerta no válida');

  const perfil = await getPerfil(env, user.uid);
  if (!perfil) throw httpErr(403, 'Sin perfil');
  // Un residente suspendido (por mora) no puede abrir, salvo peatonal y salida (nadie debe
  // quedar atrapado sin poder salir, ni en coche ni a pie); tampoco sus esclavos.
  if (perfil.suspendido && puerta !== 'peatones' && puerta !== 'salida') throw httpErr(403, 'Residente suspendido por mora');
  if (perfil.rol === 'esclavo' && perfil.residenteUid) {
    const padre = await getPerfil(env, perfil.residenteUid);
    if (padre && padre.suspendido && puerta !== 'peatones' && puerta !== 'salida') throw httpErr(403, 'Residente del hogar suspendido por mora');
  }
  // master, admin, residente y esclavo pueden abrir las 4 puertas.
  await triggerShelly(env, puerta, await mapaDispositivos(env));

  const hogar = perfil.rol === 'residente' ? user.uid : (perfil.residenteUid || user.uid);
  if (perfil.rol === 'residente' && perfil.jefeId && perfil.personaId) {
    // FAMILIAR: "Familiar de <Jefe> · <Casa> · dado de alta por <quien>" + posible alerta.
    // Se calcula DESPUÉS del pulso (la puerta ya abrió) y todo sale del servidor.
    const extra = await datosAperturaFamiliar(env, perfil);
    await logAperturaFamiliar(env, { uid: user.uid, nombre: perfil.nombre, puerta, hogar, ...extra });
  } else {
    await logApertura(env, {
      uid: user.uid, nombre: perfil.nombre, puerta, hogar, tipo:'app',
    });
  }
  // Notifica al residente si quien abrió es su esclavo
  if (perfil.rol === 'esclavo' && perfil.residenteUid) {
    await notificarResidente(env, perfil.residenteUid, `${perfil.nombre} usó ${puerta}`);
  }
  return json({ ok:true });
}

/* ============ /invitacion/crear — residente genera QR de visita ============ */
async function crearInvitacion(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!perfil || !['residente','esclavo'].includes(perfil.rol))
    throw httpErr(403, 'Solo residentes pueden invitar');
  // Un residente suspendido (por mora) no puede invitar; tampoco sus esclavos. Misma comprobación
  // que /abrir (titular y, si es esclavo, también el titular padre), sin excepción de puertas.
  if (perfil.suspendido) throw httpErr(403, 'Residente suspendido por mora');
  if (perfil.rol === 'esclavo' && perfil.residenteUid) {
    const padre = await getPerfil(env, perfil.residenteUid);
    if (padre && padre.suspendido) throw httpErr(403, 'Residente del hogar suspendido por mora');
  }

  // El hogar SIEMPRE sale del perfil verificado en el servidor (mismo cálculo que /abrir): el de
  // un esclavo es el de su titular. Se IGNORA cualquier "hogar" que mande el cliente en el cuerpo.
  const hogar = perfil.rol === 'residente' ? user.uid : (perfil.residenteUid || user.uid);
  const { visitante, horas, usos } = await req.json();
  if (!visitante) throw httpErr(400, 'Falta el nombre del visitante');

  // Usos: entero 1..8, sin excepciones. Se RECHAZA lo inválido (0 = ilimitado ya no existe,
  // negativos/no-numéricos/fuera de rango tampoco) en vez de "corregirlo" en silencio — así
  // alguien que llame al Worker directo, saltándose la UI, no puede colar una invitación
  // ilimitada ni con más usos de los permitidos.
  const USOS_MAX = 8;
  if (!Number.isInteger(usos) || usos < 1 || usos > USOS_MAX)
    throw httpErr(400, `usos debe ser un entero entre 1 y ${USOS_MAX}`);

  const ahora = Date.now();
  const expira = ahora + (Math.max(1, +horas||1) * 3600 * 1000);
  const jti = crypto.randomUUID();

  // TOKEN OPACO de alta entropía (CSPRNG, 32 bytes → ~43 chars base64url) que viaja DENTRO
  // del QR. NO contiene datos: ni nombre, ni permiso, ni jti, ni expiración. Solo una cadena
  // aleatoria. Los datos reales viven en Firestore; el QR es solo una llave opaca.
  const qrToken = bytesToB64url(crypto.getRandomValues(new Uint8Array(32)));
  const tokenHash = await sha256b64url(qrToken);   // en Firestore se guarda SOLO el hash

  // PIN de respaldo de 6 dígitos (CSPRNG, no Math.random) — funciona EN PARALELO al QR para la
  // misma invitación (mismos usos, misma vigencia). Solo se guarda pinHash, nunca el PIN en
  // claro; se entrega una sola vez en la respuesta, igual que el token del QR.
  const pin = String(crypto.getRandomValues(new Uint32Array(1))[0] % 1000000).padStart(6, '0');
  const pinHash = await sha256b64url(pin);

  // Guarda la invitación (fuente de verdad online). Se persiste el HASH del token/PIN, NUNCA
  // el valor en claro: quien lea el documento no puede reconstruir el QR ni el PIN.
  await firestoreSet(env, `invitaciones/${jti}`, {
    visitante: { stringValue: visitante },
    hogar: { stringValue: hogar },
    creadaPor: { stringValue: user.uid },
    expira: { timestampValue: new Date(expira).toISOString() },
    usosRestantes: { integerValue: String(usos) },   // ya validado: entero 1..8, nunca 0/ilimitado
    activa: { booleanValue: true },
    tokenHash: { stringValue: tokenHash },
    pinHash: { stringValue: pinHash },
    dentro: { booleanValue: false },   // aún no ha registrado ninguna entrada (ver consumirInvitacion)
  });

  // PRE-SINCRONIZA al lector físico (resiliencia offline). Emite SOLO el hash + metadatos,
  // NUNCA el token en claro: el lector compara SHA-256(token escaneado) contra tokenHash.
  await presyncReader(env, { tokenHash, exp: Math.floor(expira/1000), usos: usos||1 })
    .catch(()=>{});

  // El contenido del QR es SOLO el token opaco (se entrega una vez; no se persiste en claro).
  // Igual el PIN: se entrega en claro aquí y nunca más se puede leer.
  // `expira` (ISO 8601, mismo valor guardado en Firestore) permite al frontend mostrar la hora
  // exacta de vencimiento; no revela nada nuevo (el residente ya eligió la vigencia).
  return json({ ok:true, payload: qrToken, pin, jti, expira: new Date(expira).toISOString() });
}

/* ---- Núcleo compartido: valida y CONSUME una invitación ya encontrada (por QR o por PIN) en
   un lector concreto. No busca nada — eso lo hace cada camino de entrada (validarQR/validarPin)
   con su propio método — solo decide si procede, actualiza usosRestantes/dentro según la
   dirección del lector, dispara la Shelly y registra.

   entrada: exige usosRestantes > 0 y lo descuenta; marca dentro:true. Si ya estaba dentro:true
   (entrada duplicada sin salida de por medio), NO se bloquea — se deja pasar igual (podría ser
   un familiar más llegando con el mismo QR/PIN) pero el texto de logApertura lo marca "revisar".
   salida: NO descuenta usosRestantes (salir es gratis); marca dentro:false. Si ya estaba
   dentro:false, mismo criterio: se deja pasar, pero se marca "revisar". */
async function consumirInvitacion(env, inv, readerId, metodo) {
  if (!Object.hasOwn(READERS, readerId)) throw httpErr(400, 'Lector desconocido');
  const reader = READERS[readerId];

  if (!inv.activa) throw httpErr(403, 'Invitación inválida o cancelada');
  // Expiración: se compara contra el DOCUMENTO (el token/PIN ya no la llevan).
  if (!inv.expira || new Date(inv.expira).getTime() < Date.now()) throw httpErr(403, 'Invitación expirada');
  // Si el residente del hogar está suspendido por mora, no abre (sin gastar usos ni disparar la Shelly).
  const anfitrion = await getPerfil(env, inv.hogar);
  if (anfitrion && anfitrion.suspendido) throw httpErr(403, 'Residente del hogar suspendido por mora');

  let nombreLog = inv.visitante;
  if (reader.direccion === 'entrada') {
    if (inv.usosRestantes !== null && inv.usosRestantes <= 0) throw httpErr(403, 'Sin usos disponibles');
    if (inv.usosRestantes !== null) {
      // Con usos limitados el descuento es ATÓMICO: se relee, se revalida y se descuenta 1 dentro de
      // una transacción (bajo N consumos simultáneos de K usos entran exactamente K). `inv` pasa a
      // llevar el valor de "dentro" leído en la transacción.
      inv = await reservarUsoInvitacion(env, inv);
      if (inv.dentro === true) nombreLog = `${inv.visitante} volvió a entrar sin salida previa registrada — revisar`;
    } else {
      if (inv.dentro === true) nombreLog = `${inv.visitante} volvió a entrar sin salida previa registrada — revisar`;
      await firestoreUpdate(env, `invitaciones/${inv.id}`, { dentro: { booleanValue: true } }, ['dentro']);
    }
  } else {
    if (inv.dentro === false) nombreLog = `${inv.visitante} salió sin entrada previa registrada — revisar`;
    await firestoreUpdate(env, `invitaciones/${inv.id}`, { dentro: { booleanValue: false } }, ['dentro']);
  }

  // El uso y "dentro" arriba son una RESERVA: si el pulso falla (502 Shelly/red, 503 fila llena…)
  // se deshace para ESTA petición, así un acceso fallido nunca quema un uso ni deja una
  // entrada/salida fantasma. El error original se relanza intacto (mismo contrato).
  try {
    await triggerShelly(env, reader.puerta, await mapaDispositivos(env));
  } catch (e) {
    await devolverReservaInvitacion(env, inv, reader.direccion === 'entrada' && inv.usosRestantes !== null);
    throw e;
  }
  // Los datos de "quién invitó" y la alerta se calculan DESPUÉS del pulso: la puerta ya abrió,
  // así estas lecturas extra nunca retrasan el acceso.
  const extra = await datosBitacoraVisita(env, inv, anfitrion);
  await logVisita(env, { metodo, nombre: nombreLog, visitante: inv.visitante, puerta: reader.puerta,
    hogar: inv.hogar, tipo: reader.direccion, invitacionId: inv.id, ...extra });
  await notificarResidente(env, inv.hogar,
    `Visita ${inv.visitante} ${reader.direccion === 'entrada' ? 'entró' : 'salió'} por ${reader.puerta}`);
}

/* ---- Bitácora de visitas: "Invitado por <nombre> · <casa>" + alerta de posible suspendido ----
   Todo sale del SERVIDOR: la invitación (creadaPor, hogar, visitante) y los perfiles/padrón en
   Firestore — nada del cliente ni del lector. Nunca lanza: si algo falla, el registro se escribe
   igual, solo sin estos datos extra (la puerta ya abrió). */
function normNombre(s) {
  return String(s || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase().replace(/\s+/g, ' ').trim();
}
async function datosBitacoraVisita(env, inv, anfitrion) {
  // casaId = persona del JEFE de la casa (el jefe: su propio personaId; un familiar: su jefeId).
  // Sale del anfitrión (dueño del hogar de la invitación; el de un esclavo es su titular) y es lo
  // que usan las reglas para que TODA la casa —jefe y familiares— vea las visitas de la casa.
  const casaId = anfitrion && anfitrion.rol === 'residente' ? (anfitrion.jefeId || anfitrion.personaId || '') : '';
  const out = { invitadoPor: '', casa: anfitrion?.casa || '', casaId, coincideCon: [] };
  try {
    const [creador, personas] = await Promise.all([
      !inv.creadaPor ? null : (inv.creadaPor === inv.hogar && anfitrion ? anfitrion : getPerfil(env, inv.creadaPor)),
      personasList(env),
    ]);
    out.invitadoPor = creador?.nombre || '';
    out.casa = creador?.casa || out.casa;
    // Alerta (solo marca, NO bloquea): el nombre de la visita coincide —sin importar mayúsculas,
    // acentos ni espacios extra— con un jefe o familiar SUSPENDIDO del padrón.
    const n = normNombre(inv.visitante);
    if (n) {
      const byId = {}; personas.forEach(p => byId[p.id] = p);
      out.coincideCon = personas
        .filter(p => p.rol === 'residente' && p.estado === 'suspendido' && normNombre(p.nombre) === n)
        .map(p => { const dom = domicilioDe(p, byId); return `${p.nombre}${dom ? ' (' + dom + ')' : ''}${p.jefeId ? ' · familiar' : ''}`; });
    }
  } catch (e) {
    console.error('[bitacora] no se pudieron completar los datos de la visita:', e && e.name);
  }
  return out;
}
/* Registro de una visita por invitación. aperturas/{id} lo ven el staff, el propio hogar y toda
   la casa (jefe y familiares, por casaId — ver reglas).
   La ALERTA va aparte, en alertas_bitacora/{mismo id}, que SOLO lee el staff: si viviera dentro
   del registro, el residente que invitó podría ver con las devtools que el nombre de su visita
   coincide con un vecino suspendido. Ambos en el mismo commit. */
async function logVisita(env, o) {
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const id = crypto.randomUUID();
  const ts = { timestampValue: new Date().toISOString() };
  const comun = {
    visitante: { stringValue: o.visitante || '' },
    puerta: { stringValue: o.puerta }, hogar: { stringValue: o.hogar }, tipo: { stringValue: o.tipo },
    metodo: { stringValue: o.metodo }, invitacionId: { stringValue: o.invitacionId || '' },
    invitadoPor: { stringValue: o.invitadoPor || '' }, casa: { stringValue: o.casa || '' },
    casaId: { stringValue: o.casaId || '' }, ts,
  };
  const writes = [{
    update: { name: docName(env, `aperturas/${id}`), fields: {
      uid: { stringValue: o.metodo }, nombre: { stringValue: o.nombre || o.visitante || 'Visita' }, ...comun,
    } },
    currentDocument: { exists: false },
  }];
  if (o.coincideCon && o.coincideCon.length) {
    writes.push({
      update: { name: docName(env, `alertas_bitacora/${id}`), fields: {
        aperturaId: { stringValue: id }, tipoAlerta: { stringValue: 'posible-suspendido' },
        coincideCon: { stringValue: o.coincideCon.join('; ').slice(0, 300) }, ...comun,
      } },
      currentDocument: { exists: false },
    });
  }
  const r = await fetch(`${fsBase(env)}:commit`, {
    method: 'POST', headers: { Authorization: 'Bearer ' + at, 'Content-Type': 'application/json' },
    body: JSON.stringify({ writes }),
  });
  if (!r.ok) console.error(`[bitacora] no se pudo registrar la visita (HTTP ${r.status})`);
}

/* ---- Bitácora de aperturas desde la app hechas por un FAMILIAR ----
   Datos del padrón (personas) en el servidor: jefe, casa, quién lo dio de alta y, si su
   alerta sigue ACTIVA (alertas_familiares), la marca. Nunca lanza: si algo falla, la apertura
   se registra igual, sin estos datos extra. */
async function datosAperturaFamiliar(env, perfil) {
  const out = { personaId: perfil.personaId, familiarDe: '', casa: perfil.casa || '', dadoDeAltaNombre: '', alerta: null };
  try {
    const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
    const [pd, jd, ad] = await Promise.all([
      getDoc(env, at, `personas/${perfil.personaId}`),
      getDoc(env, at, `personas/${perfil.jefeId}`),
      getDoc(env, at, `alertas_familiares/${perfil.personaId}`),
    ]);
    const p = pd && readDoc(pd.fields), j = jd && readDoc(jd.fields), a = ad && readDoc(ad.fields);
    out.familiarDe = j?.nombre || '';
    out.casa = j?.domicilio || out.casa;
    // Familiares anteriores a v13 no tienen dadoDeAltaNombre: si los creó su propio jefe, es él.
    out.dadoDeAltaNombre = p?.dadoDeAltaNombre || (p?.creadoPor && j?.uid && p.creadoPor === j.uid ? (j.nombre || '') : '');
    if (a && a.estado === 'activa') out.alerta = { coincideCon: a.coincideCon || '' };
  } catch (e) {
    console.error('[bitacora] no se pudieron completar los datos del familiar:', e && e.name);
  }
  return out;
}
/* aperturas/{id} (lo ve el staff y el propio hogar) + alertas_bitacora/{mismo id} si está
   marcado (SOLO staff: el familiar nunca ve que está marcado). Mismo commit. */
async function logAperturaFamiliar(env, o) {
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const id = crypto.randomUUID();
  const comun = {
    nombre: { stringValue: o.nombre || 'Usuario' }, puerta: { stringValue: o.puerta },
    hogar: { stringValue: o.hogar }, tipo: { stringValue: 'app' },
    personaId: { stringValue: o.personaId || '' }, familiarDe: { stringValue: o.familiarDe || '' },
    casa: { stringValue: o.casa || '' }, dadoDeAltaNombre: { stringValue: o.dadoDeAltaNombre || '' },
    ts: { timestampValue: new Date().toISOString() },
  };
  const writes = [{
    update: { name: docName(env, `aperturas/${id}`), fields: { uid: { stringValue: o.uid }, ...comun } },
    currentDocument: { exists: false },
  }];
  if (o.alerta) {
    writes.push({
      update: { name: docName(env, `alertas_bitacora/${id}`), fields: {
        aperturaId: { stringValue: id }, tipoAlerta: { stringValue: 'posible-otra-casa' },
        coincideCon: { stringValue: String(o.alerta.coincideCon || '').slice(0, 300) }, ...comun,
      } },
      currentDocument: { exists: false },
    });
  }
  const r = await fetch(`${fsBase(env)}:commit`, {
    method: 'POST', headers: { Authorization: 'Bearer ' + at, 'Content-Type': 'application/json' },
    body: JSON.stringify({ writes }),
  });
  if (!r.ok) console.error(`[bitacora] no se pudo registrar la apertura del familiar (HTTP ${r.status})`);
}

/* Reserva ATÓMICA de un uso (entrada con usos limitados). Transacción de Firestore REST (los
   mismos helpers conTx/txGet/txCommit de votaciones): lee la invitación y al anfitrión, revalida
   (activa, vigente, anfitrión no suspendido, usos > 0 — mismos mensajes 403 de siempre), y descuenta
   exactamente 1 uso + dentro:true en el mismo commit. Si otra petición modificó el documento entre
   la lectura y el commit, Firestore aborta y se reintenta (relee y revalida): bajo N consumos
   simultáneos de K usos entran exactamente K; el resto ve 0 y recibe 403 "Sin usos disponibles".
   Devuelve la invitación con el "dentro" previo leído en la transacción (para logs y devolución). */
async function reservarUsoInvitacion(env, inv) {
  const docName = `projects/${env.FIREBASE_PROJECT}/databases/(default)/documents/invitaciones/${inv.id}`;
  let intento = 0;
  const fresca = await conTx(env, async (at, tx) => {
    if (intento++ > 0) await new Promise(r => setTimeout(r, 20 + Math.random() * 60));   // jitter entre reintentos
    const doc = await txGet(env, at, `invitaciones/${inv.id}`, tx);
    const cur = doc ? readDoc(doc.fields) : null;
    if (!cur || !cur.activa) throw httpErr(403, 'Invitación inválida o cancelada');
    if (!cur.expira || new Date(cur.expira).getTime() < Date.now()) throw httpErr(403, 'Invitación expirada');
    const ad = await txGet(env, at, `usuarios/${cur.hogar}`, tx);
    if (ad && readDoc(ad.fields)?.suspendido) throw httpErr(403, 'Residente del hogar suspendido por mora');
    if (cur.usosRestantes !== null && cur.usosRestantes <= 0) throw httpErr(403, 'Sin usos disponibles');
    return {
      value: cur,
      writes: [{
        update: { name: docName, fields: { dentro: { booleanValue: true } } },
        updateMask: { fieldPaths: ['dentro'] },
        updateTransforms: [{ fieldPath: 'usosRestantes', increment: { integerValue: '-1' } }],
      }],
    };
  }, 10);   // 10 intentos: con ≤8 usos, un contendiente pierde como mucho 8 rondas antes de ver 0
  return { ...inv, ...fresca, id: inv.id };
}

/* Deshace la reserva de consumirInvitacion cuando el pulso a Shelly falló. Cada petición
   devuelve SU propio uso con un incremento ATÓMICO (+1, updateTransforms) — no reescribe un
   valor absoluto, así no pisa el descuento de otra petición concurrente sobre la misma
   invitación. `dentro` vuelve a su valor previo (si se conocía). Best-effort: si la devolución
   misma falla se deja registro (sin datos sensibles) y el error original del pulso se conserva. */
async function devolverReservaInvitacion(env, inv, devolverUso) {
  try {
    const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
    const base = `projects/${env.FIREBASE_PROJECT}/databases/(default)`;
    const write = { update: { name: `${base}/documents/invitaciones/${inv.id}`, fields: {} }, updateMask: { fieldPaths: [] } };
    if (typeof inv.dentro === 'boolean') {
      write.update.fields.dentro = { booleanValue: inv.dentro };
      write.updateMask.fieldPaths.push('dentro');
    }
    if (devolverUso) write.updateTransforms = [{ fieldPath: 'usosRestantes', increment: { integerValue: '1' } }];
    if (!write.updateMask.fieldPaths.length && !write.updateTransforms) return;
    const r = await fetch(`https://firestore.googleapis.com/v1/${base}/documents:commit`, {
      method: 'POST', headers: { Authorization: 'Bearer ' + at, 'Content-Type': 'application/json' },
      body: JSON.stringify({ writes: [write] }),
    });
    if (!r.ok) console.error(`[shelly-gate] no se pudo devolver la reserva de la invitación (HTTP ${r.status})`);
  } catch (e) {
    console.error('[shelly-gate] no se pudo devolver la reserva de la invitación');
  }
}

/* ============ /validar-qr — lo llama el LECTOR físico al escanear ============
   Funciona aunque el lector esté pre-sincronizado y sin internet (lógica local
   del lector). Cuando hay internet, valida y registra contra el Worker. */
async function validarQR(req, env) {
  // El lector se autentica con una llave propia (no un token de usuario)
  const readerKey = req.headers.get('X-Reader-Key');
  if (!env.READER_KEY || readerKey !== env.READER_KEY) throw httpErr(401, 'Lector no autorizado');

  const { payload, readerId } = await req.json();
  // El payload es ahora el TOKEN OPACO (cadena aleatoria, sin datos). Se busca su hash en
  // Firestore; TODOS los datos salen del documento, nunca del token.
  if (!payload || typeof payload !== 'string') throw httpErr(400, 'Falta el token del QR');
  const tokenHash = await sha256b64url(payload);
  const inv = await getInvitacionPorTokenHash(env, tokenHash);
  if (!inv) throw httpErr(403, 'QR inválido o cancelado');

  await consumirInvitacion(env, inv, readerId, 'qr');
  return json({ ok:true });
}

/* ============ /validar-pin — camino de respaldo si el QR no se puede escanear ============
   Mismo patrón de auth que /validar-qr (X-Reader-Key compartido entre los 4 lectores). Un PIN
   de 6 dígitos es 10^6 combinaciones — lo que lo hace seguro NO es su longitud, es el candado
   de fuerza bruta (checarCandadoPin/registrarFalloPin, por lector) que se revisa ANTES de
   buscar nada. */
async function validarPin(req, env) {
  const readerKey = req.headers.get('X-Reader-Key');
  if (!env.READER_KEY || readerKey !== env.READER_KEY) throw httpErr(401, 'Lector no autorizado');

  const { pin, readerId } = await req.json();
  if (!pin || typeof pin !== 'string') throw httpErr(400, 'Falta el PIN');
  // Se valida el lector ANTES de tocar controlPin/{readerId}: un readerId desconocido no debe
  // crear ni leer ningún documento de candado.
  if (!Object.hasOwn(READERS, readerId)) throw httpErr(400, 'Lector desconocido');

  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');

  // Candado ANTES de tocar cualquier otra cosa: si ya está bloqueado, ni se calcula el hash.
  await checarCandadoPin(env, at, readerId);

  const pinHash = await sha256b64url(pin);
  const inv = await getInvitacionPorPinHash(env, pinHash);
  if (!inv) {
    await registrarFalloPin(env, at, readerId);
    throw httpErr(403, 'PIN inválido');
  }

  await resetearCandadoPin(env, at, readerId);
  await consumirInvitacion(env, inv, readerId, 'pin');
  return json({ ok:true });
}

/* ============ /usuarios/suspender — solo staff, sobre residentes ============ */
async function suspenderUsuario(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!esStaff(perfil)) throw httpErr(403, 'No autorizado');

  const { uid, suspendido } = await req.json();
  if (!uid || typeof suspendido !== 'boolean') throw httpErr(400, 'Datos inválidos');
  const objetivo = await getPerfil(env, uid);
  if (!objetivo) throw httpErr(404, 'Usuario no encontrado');
  if (objetivo.rol !== 'residente') throw httpErr(403, 'Solo se pueden suspender residentes');

  await firestoreUpdate(env, `usuarios/${uid}`, {
    suspendido: { booleanValue: suspendido },
  }, ['suspendido']);
  return json({ ok:true, uid, suspendido });
}

/* ============ /usuarios/borrar — SOLO master ============
   Borra la cuenta de Firebase Auth + su doc /usuarios, y limpia el uid del vecino
   vinculado (uid→null) para que se pueda reinvitar. Respaldo a usuarios_borrados y
   registro en bitácora. No permite borrarse a sí mismo ni a otra cuenta master. */
async function borrarUsuario(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!perfil || perfil.rol !== 'master') throw httpErr(403, 'Solo master borra cuentas');

  const { uid } = await req.json();
  if (!uid || typeof uid !== 'string' || uid.length < 6 || uid.length > 128) throw httpErr(400, 'uid inválido');
  if (uid === user.uid) throw httpErr(409, 'No puedes borrar tu propia cuenta');

  const at = await saToken(env, 'https://www.googleapis.com/auth/identitytoolkit https://www.googleapis.com/auth/datastore');

  // Snapshot del doc /usuarios para el respaldo.
  const rGet = await fetch(`${fsBase(env)}/usuarios/${uid}`, { headers:{ Authorization:'Bearer '+at } });
  const usuarioDoc = rGet.ok ? await rGet.json() : null;
  const objetivo = usuarioDoc ? readDoc(usuarioDoc.fields) : {};
  if (objetivo.rol === 'master') throw httpErr(403, 'No se puede borrar una cuenta master');

  // Respaldo (quién/cuándo/snapshot completo).
  await firestoreSet(env, `usuarios_borrados/${uid}`, {
    ...(usuarioDoc?.fields || {}),
    borradoPor:{stringValue:user.uid},
    borradoNombre:{stringValue:perfil.nombre||''},
    borradoTs:{timestampValue:new Date().toISOString()},
  }, at);

  // Borra la cuenta de Firebase Auth. Si ya no existe (USER_NOT_FOUND), sigue limpiando.
  const rDel = await fetch(`https://identitytoolkit.googleapis.com/v1/projects/${env.FIREBASE_PROJECT}/accounts:delete`, {
    method:'POST', headers:{ Authorization:'Bearer '+at, 'Content-Type':'application/json' },
    body: JSON.stringify({ localId: uid }),
  });
  if (!rDel.ok) {
    const err = await rDel.json().catch(() => ({}));
    if (!String(err.error?.message || '').includes('USER_NOT_FOUND')) throw httpErr(500, 'No se pudo borrar la cuenta de Auth');
  }

  // Borra el doc /usuarios/{uid}.
  await fetch(`${fsBase(env)}/usuarios/${uid}`, { method:'DELETE', headers:{ Authorization:'Bearer '+at } }).catch(() => {});

  // Limpia el uid del vecino vinculado (→ null) para poder reinvitar ese domicilio.
  let domicilioLiberado = null;
  const vinc = (await firestoreList(env, 'vecinos')).find(d => readDoc(d.fields).uid === uid);
  if (vinc) {
    const vid = vinc.name.split('/').pop();
    domicilioLiberado = readDoc(vinc.fields).domicilio || null;
    await firestoreActualizarCampos(env, `vecinos/${vid}`, { uid:{nullValue:null} }, 'Vecino');
  }

  await logBitacora(env, at, {
    uid: user.uid,
    nombre: `${perfil.nombre || 'Master'} borró la cuenta de ${objetivo.nombre || objetivo.email || uid}`,
  });

  return json({ ok:true, uid, domicilioLiberado });
}

// Trim + colapsa espacios dobles/múltiples a uno solo (no prohíbe espacios internos,
// solo normaliza — así "casa  57" y "casa 57" terminan guardados igual).
/* ===========================================================
   FINANZAS PROTEGIDAS — un movimiento NUNCA se borra.
   - Cancelar: estado:'cancelado' + motivo obligatorio. Sigue visible (tachado) pero ya no cuenta
     en la caja, la cobranza, el adeudo ni la suspensión automática (todos filtran esCancelado).
     El folio del recibo se conserva: la numeración nunca tiene huecos.
   - Corregir: en UNA sola transacción cancela el original (con el motivo) y crea el corregido,
     ligados (corregidoPorId ↔ corrigeAId). Si es ingreso, el corregido lleva folio NUEVO.
   - Reactivar (solo master): deshace una cancelación, con motivo.
   - Permisos: staff (master/admin/jefe-admin) cancela/corrige movimientos del mes actual y el
     anterior (hora Hermosillo); más viejos, solo master. Límite: 5 cancelaciones+correcciones
     por hora POR CUENTA (también el master: el riesgo es una cuenta robada) → 429 + aviso al master.
   - Bitácora: cada alta/cambio escribe finanzas_log/{auto} EN EL MISMO commit que el cambio —
     nunca queda un cambio sin su registro, ni un registro de algo que no pasó.
   =========================================================== */
const FIN_LIMITE_POR_HORA = 5;
const esCancelado = d => !!d && d.estado === 'cancelado';
const ID_MOV_RE = /^[A-Za-z0-9-]{10,64}$/;

function mesIndexHermosillo(instante) {
  const d = aHermosillo(instante);
  return d.getUTCFullYear() * 12 + d.getUTCMonth();
}
// Admin/jefe-admin: mes actual y el anterior. Master: cualquiera.
function checarVentanaMovimiento(perfil, mov) {
  if (perfil.rol === 'master') return;
  if (mesIndexHermosillo(Date.now()) - mesIndexHermosillo(mov.ts) > 1) {
    throw httpErr(403, 'Ese movimiento es de hace más de un mes: solo el master puede cancelarlo o corregirlo');
  }
}
function validarMotivo(motivo) {
  const m = String(motivo == null ? '' : motivo).trim().replace(/\s+/g, ' ');
  if (m.length < 5) throw httpErr(400, 'El motivo es obligatorio (mínimo 5 caracteres)');
  return m.slice(0, 300);
}
function rolEtiqueta(perfil) {
  if (!perfil) return '';
  return perfil.rol === 'residente' && perfil.esAdmin === true ? 'jefe-admin' : (perfil.rol || '');
}
// Referencia humana de un movimiento: su folio de recibo o, si no tiene (gastos), #ABC123.
function refMov(id, d) { return (d && d.folioRecibo) || ('#' + String(id).slice(0, 6).toUpperCase()); }
function resumenMov(id, d) {
  const signo = d.tipo === 'ingreso' ? '+' : '−';
  return `${refMov(id, d)} · ${signo}$${d.monto} · ${d.categoria || 'Otro'} · ${d.concepto || ''}${d.casa ? ' · ' + d.casa : ''}`;
}

/* Commit NO transaccional de varias escrituras juntas (atómico: o todas o ninguna). */
async function fsCommit(env, at, writes) {
  const r = await fetch(`${fsBase(env)}:commit`, {
    method: 'POST', headers: { Authorization: 'Bearer ' + at, 'Content-Type': 'application/json' },
    body: JSON.stringify({ writes }),
  });
  if (r.status === 404) throw httpErr(404, 'Movimiento no existe');
  if (!r.ok) throw httpErr(500, 'Firestore commit falló');
  return r.json();
}

/* Una entrada de finanzas_log como write de commit. antes/despues son mapas de fields de
   Firestore tal cual (foto del movimiento). ip/ua salen de Cloudflare para rastrear una cuenta
   robada. Solo el Worker escribe aquí; staff lo lee (reglas). */
function writeLogFinanzas(env, req, { movId, accion, uid, perfil, resumen, motivo, relacionadoId, antes, despues }) {
  const fields = {
    movId: { stringValue: movId },
    accion: { stringValue: accion },
    uid: { stringValue: uid },
    nombre: { stringValue: perfil?.nombre || (uid === 'sistema' ? 'Sistema' : '') },
    rol: { stringValue: rolEtiqueta(perfil) },
    ts: { timestampValue: new Date().toISOString() },
    resumen: { stringValue: String(resumen || '').slice(0, 300) },
  };
  if (motivo) fields.motivo = { stringValue: motivo };
  if (relacionadoId) fields.relacionadoId = { stringValue: relacionadoId };
  if (antes) fields.antes = { mapValue: { fields: antes } };
  if (despues) fields.despues = { mapValue: { fields: despues } };
  if (req) {
    fields.ip = { stringValue: req.headers.get('cf-connecting-ip') || '' };
    fields.ua = { stringValue: (req.headers.get('user-agent') || '').slice(0, 200) };
  }
  return { update: { name: docName(env, `finanzas_log/${crypto.randomUUID()}`), fields }, currentDocument: { exists: false } };
}

/* Límite de cancelaciones+correcciones por hora, DENTRO de la transacción (dos pestañas a la vez
   no se lo saltan). finanzas_limites/{uid}.marcas = timestamps de la última hora. Devuelve el
   write que agrega la marca nueva; si ya hay FIN_LIMITE_POR_HORA, lanza 429. */
async function limiteCancelacionTx(env, at, tx, uid) {
  const doc = await txGet(env, at, `finanzas_limites/${uid}`, tx);
  const hace1h = Date.now() - HORA_MS;
  const marcas = (doc?.fields?.marcas?.arrayValue?.values || [])
    .map(v => v.timestampValue).filter(t => t && new Date(t).getTime() > hace1h);
  if (marcas.length >= FIN_LIMITE_POR_HORA) {
    throw httpErr(429, `Límite alcanzado: máximo ${FIN_LIMITE_POR_HORA} cancelaciones o correcciones por hora. Se avisó al master.`);
  }
  marcas.push(new Date().toISOString());
  return {
    update: { name: docName(env, `finanzas_limites/${uid}`), fields: { marcas: { arrayValue: { values: marcas.map(t => ({ timestampValue: t })) } } } },
    updateMask: { fieldPaths: ['marcas'] },
  };
}

/* Aviso de límite: bitácora de finanzas + bitácora general + push a los master que tengan
   notificaciones activas. Máximo un push por cuenta por hora (avisadoTs). Nunca lanza. */
async function avisarLimiteFinanzas(env, req, user, perfil, movId) {
  try {
    const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
    const quien = `${perfil?.nombre || 'Alguien'} (${rolEtiqueta(perfil)})`;
    const texto = `${quien} alcanzó el límite de ${FIN_LIMITE_POR_HORA} cancelaciones/correcciones por hora en Finanzas y fue bloqueado.`;
    await fsCommit(env, at, [writeLogFinanzas(env, req, {
      movId: movId || '', accion: 'limite', uid: user.uid, perfil, resumen: texto,
    })]);
    await logBitacora(env, at, { uid: user.uid, nombre: texto });

    const lim = await getDoc(env, at, `finanzas_limites/${user.uid}`);
    const avisado = lim?.fields?.avisadoTs?.timestampValue;
    if (avisado && Date.now() - new Date(avisado).getTime() < HORA_MS) return;
    await firestoreUpdate(env, `finanzas_limites/${user.uid}`, { avisadoTs: { timestampValue: new Date().toISOString() } }, ['avisadoTs']);
    const masters = (await firestoreList(env, 'usuarios')).map(d => readDoc(d.fields)).filter(u => u && u.rol === 'master' && u.fcmToken);
    if (!masters.length) return;
    const atFcm = await saToken(env, 'https://www.googleapis.com/auth/firebase.messaging');
    for (const m of masters) {
      await fetch(`https://fcm.googleapis.com/v1/projects/${env.FIREBASE_PROJECT}/messages:send`, {
        method: 'POST', headers: { Authorization: 'Bearer ' + atFcm, 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: { token: m.fcmToken, notification: { title: '⚠️ Finanzas · Cerrada Mojave', body: texto } } }),
      }).catch(() => {});
    }
  } catch (e) {
    console.error('avisarLimiteFinanzas', e);
  }
}

/* Valida y normaliza los datos de un movimiento (alta o corrección). NO se confía en el front.
   En ingresos, casa DEBE ser un JEFE de familia del padrón (comparación normalizada) y se guarda
   el domicilio canónico. Se acepta la casa ACTIVA o SUSPENDIDA (por mora o manual): un moroso que
   llega a pagar tiene que poder pagar, y es justo ese pago el que dispara intentarReactivarPorPago
   (que solo levanta suspensiones por mora; una manual NO se quita sola). */
async function validarDatosMovimiento(env, body) {
  const { tipo, concepto, categoria, monto, casa } = body || {};
  if (!['ingreso','egreso'].includes(tipo)) throw httpErr(400, 'Tipo inválido');
  const m = Number(monto);
  if (!concepto || !(m > 0)) throw httpErr(400, 'Concepto o monto inválido');
  const cat = String(categoria||'Otro').slice(0,40);

  let casaCanon = '';
  if (tipo === 'ingreso') {
    const dom = String(casa == null ? '' : casa).trim().replace(/\s+/g, ' ');
    if (!dom) throw httpErr(400, 'Falta el domicilio para un ingreso');
    const domNorm = normDomicilio(dom);
    const jefes = (await personasList(env)).filter(p => esJefe(p));
    const match = jefes.find(j => j.domicilioNorm === domNorm);
    if (!match) throw httpErr(400, `Domicilio no registrado: "${dom}"`);
    casaCanon = match.domicilio;
  }
  return { tipo, concepto: String(concepto).slice(0,120), cat, m, casaCanon };
}

/* ============ /finanzas/registrar — solo master/admin ============ */
async function registrarFinanza(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!esStaff(perfil)) throw httpErr(403, 'Solo master/admin registran finanzas');

  const { tipo, concepto, cat, m, casaCanon } = await validarDatosMovimiento(env, await req.json());

  // Los ingresos llevan recibo: folio consecutivo del mes, asignado de forma atómica.
  // Se asigna DESPUÉS de validar la casa para no quemar un folio en un registro inválido.
  const folioRecibo = tipo === 'ingreso' ? await siguienteFolioRecibo(env) : '';

  const id = crypto.randomUUID();
  const fields = {
    tipo:{stringValue:tipo},
    concepto:{stringValue:concepto},
    categoria:{stringValue:cat},
    monto:{doubleValue:m},
    casa:{stringValue:casaCanon},
    ...(folioRecibo ? { folioRecibo:{stringValue:folioRecibo} } : {}),
    creadoPor:{stringValue:user.uid},
    creadoNombre:{stringValue:perfil.nombre||''},
    ts:{timestampValue:new Date().toISOString()},
  };
  // Movimiento + su entrada de bitácora en el MISMO commit.
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  await fsCommit(env, at, [
    { update:{ name: docName(env, `finanzas/${id}`), fields }, currentDocument:{ exists:false } },
    writeLogFinanzas(env, req, { movId:id, accion:'crear', uid:user.uid, perfil,
      resumen: resumenMov(id, readDoc(fields)), despues: fields }),
  ]);

  // Reactivación automática: solo cuando el ingreso es una Cuota con casa válida. No bloquea
  // ni puede fallar la respuesta (ver comentario de intentarReactivarPorPago) — el ingreso ya
  // quedó escrito arriba pase lo que pase aquí.
  if (tipo === 'ingreso' && cat === 'Cuota' && casaCanon) {
    await intentarReactivarPorPago(env, casaCanon);
  }

  // FASE 7 — autocobro: un jefe-admin puede registrar el pago de SU PROPIA casa (es admin y
  // es casa a la vez). Es legítimo, pero no debe ser invisible: queda en la bitácora. Ya nadie
  // borra movimientos (solo se cancelan, con motivo y rastro), así que no puede tapar su rastro.
  if (perfil.esAdmin === true && casaCanon && normDomicilio(perfil.casa || '') === normDomicilio(casaCanon)) {
    await logBitacora(env, at, {
      uid: user.uid,
      nombre: `${perfil.nombre || 'Admin'} registró un pago de su propia casa (${casaCanon}) por ${m}`,
    });
  }
  return json({ ok:true, id, folioRecibo });
}

/* Clave del contador de folios del mes (rec_YYYYMM). Mismo criterio que siempre: mes del
   reloj del Worker. Compartida por siguienteFolioRecibo y la corrección transaccional. */
function claveFolioMes() {
  const now = new Date();
  const ym = `${now.getFullYear()}${String(now.getMonth()+1).padStart(2,'0')}`;
  return { ym, campo: `rec_${ym}` };
}

/* folio consecutivo atómico REC-YYYYMM-### — un solo commit con updateTransforms
   (increment) sobre config/folios: Firestore aplica el +1 de forma atómica y
   devuelve el valor resultante en transformResults, sin transacción explícita ni
   carreras entre registros simultáneos. El contador reinicia cada mes (campo
   rec_YYYYMM nuevo). config/folios está bajo match /config → solo el Worker escribe. */
async function siguienteFolioRecibo(env) {
  const { ym, campo } = claveFolioMes();
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const base = `projects/${env.FIREBASE_PROJECT}/databases/(default)`;
  const r = await fetch(`https://firestore.googleapis.com/v1/${base}/documents:commit`, {
    method:'POST', headers:{ Authorization:'Bearer '+at, 'Content-Type':'application/json' },
    body: JSON.stringify({
      writes: [{
        // update con máscara vacía = merge que crea el doc si no existe;
        // el increment va aparte en updateTransforms.
        update: { name: `${base}/documents/config/folios`, fields: {} },
        updateMask: { fieldPaths: [] },
        updateTransforms: [{ fieldPath: campo, increment: { integerValue: '1' } }],
      }],
    }),
  });
  if (!r.ok) throw httpErr(500, 'No se pudo asignar folio');
  const d = await r.json();
  const n = Number(d.writeResults?.[0]?.transformResults?.[0]?.integerValue);
  if (!Number.isInteger(n) || n <= 0) throw httpErr(500, 'No se pudo asignar folio');
  return `REC-${ym}-${String(n).padStart(3,'0')}`;
}

/* ============ /finanzas/marcar-recibo — solo master/admin ============
   Marca en el movimiento cuándo se compartió o descargó su recibo, para que el
   reporte por casa pueda referenciar "enviado el ...". Solo toca ese campo (y deja
   su entrada en la bitácora, en el mismo commit). */
async function marcarRecibo(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!esStaff(perfil)) throw httpErr(403, 'Solo master/admin');

  const { id, accion } = await req.json();
  if (!id || !ID_MOV_RE.test(id)) throw httpErr(400, 'id inválido');
  if (!['compartido','descargado'].includes(accion)) throw httpErr(400, 'accion inválida');

  const campo = accion === 'compartido' ? 'reciboCompartidoTs' : 'reciboDescargadoTs';
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  await fsCommit(env, at, [
    { update:{ name: docName(env, `finanzas/${id}`), fields:{ [campo]:{timestampValue:new Date().toISOString()} } },
      updateMask:{ fieldPaths:[campo] }, currentDocument:{ exists:true } },
    writeLogFinanzas(env, req, { movId:id, accion:'marcar-recibo', uid:user.uid, perfil,
      resumen: `Recibo ${accion}` }),
  ]);
  return json({ ok:true, id, [campo]: true });
}

/* Campos que marcan un movimiento como cancelado (se agregan con updateMask; el resto del
   documento queda intacto — folio incluido). */
function camposCancelacion(user, perfil, motivo, extra = {}) {
  return {
    estado:{stringValue:'cancelado'},
    motivoCancelacion:{stringValue:motivo},
    canceladoPor:{stringValue:user.uid},
    canceladoNombre:{stringValue:perfil.nombre||''},
    canceladoTs:{timestampValue:new Date().toISOString()},
    ...extra,
  };
}

/* ============ /finanzas/cancelar — staff, con motivo ============ */
async function cancelarFinanza(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!esStaff(perfil)) throw httpErr(403, 'Solo staff cancela movimientos');

  const { id, motivo } = await req.json();
  if (!id || !ID_MOV_RE.test(id)) throw httpErr(400, 'id inválido');
  const mot = validarMotivo(motivo);

  try {
    await conTx(env, async (at, tx) => {
      const doc = await txGet(env, at, `finanzas/${id}`, tx);
      if (!doc) throw httpErr(404, 'Movimiento no existe');
      const d = readDoc(doc.fields);
      if (esCancelado(d)) throw httpErr(409, 'Ese movimiento ya está cancelado');
      checarVentanaMovimiento(perfil, d);
      const wLimite = await limiteCancelacionTx(env, at, tx, user.uid);

      const campos = camposCancelacion(user, perfil, mot);
      return { writes: [
        { update:{ name: docName(env, `finanzas/${id}`), fields: campos },
          updateMask:{ fieldPaths: Object.keys(campos) }, currentDocument:{ exists:true } },
        wLimite,
        writeLogFinanzas(env, req, { movId:id, accion:'cancelar', uid:user.uid, perfil, motivo:mot,
          resumen: 'Canceló ' + resumenMov(id, d), antes: doc.fields, despues: campos }),
      ] };
    });
  } catch (e) {
    if (e.status === 429) await avisarLimiteFinanzas(env, req, user, perfil, id);
    throw e;
  }
  // Cancelar un pago NO suspende al instante: si la casa queda con adeudo, lo decide la
  // suspensión automática (cron) con sus reglas de siempre.
  return json({ ok:true, id });
}

/* ============ /finanzas/corregir — staff, con motivo ============
   UNA transacción: cancela el original (motivo + corregidoPorId) y crea el corregido
   (corrigeAId, misma fecha del movimiento original). Si el corregido es ingreso lleva folio
   NUEVO, reservado dentro de la misma transacción (config/folios leído y escrito en ella):
   si algo falla no se quema folio ni queda el original cancelado sin su reemplazo. */
async function corregirFinanza(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!esStaff(perfil)) throw httpErr(403, 'Solo staff corrige movimientos');

  const body = await req.json();
  const { id } = body;
  if (!id || !ID_MOV_RE.test(id)) throw httpErr(400, 'id inválido');
  const mot = validarMotivo(body.motivo);
  const nuevo = await validarDatosMovimiento(env, body);

  const nuevoId = crypto.randomUUID();
  let folioRecibo = '';
  try {
    folioRecibo = await conTx(env, async (at, tx) => {
      const doc = await txGet(env, at, `finanzas/${id}`, tx);
      if (!doc) throw httpErr(404, 'Movimiento no existe');
      const d = readDoc(doc.fields);
      if (esCancelado(d)) throw httpErr(409, 'Ese movimiento ya está cancelado: no se puede corregir');
      checarVentanaMovimiento(perfil, d);
      const wLimite = await limiteCancelacionTx(env, at, tx, user.uid);

      const writes = [];
      let folio = '';
      if (nuevo.tipo === 'ingreso') {
        const { ym, campo } = claveFolioMes();
        const fol = await txGet(env, at, 'config/folios', tx);
        const n = Number(fol?.fields?.[campo]?.integerValue || 0) + 1;
        folio = `REC-${ym}-${String(n).padStart(3,'0')}`;
        writes.push({ update:{ name: docName(env, 'config/folios'), fields:{ [campo]:{ integerValue:String(n) } } },
                      updateMask:{ fieldPaths:[campo] } });
      }

      const fieldsNuevo = {
        tipo:{stringValue:nuevo.tipo},
        concepto:{stringValue:nuevo.concepto},
        categoria:{stringValue:nuevo.cat},
        monto:{doubleValue:nuevo.m},
        casa:{stringValue:nuevo.casaCanon},
        ...(folio ? { folioRecibo:{stringValue:folio} } : {}),
        corrigeAId:{stringValue:id},
        creadoPor:{stringValue:user.uid},
        creadoNombre:{stringValue:perfil.nombre||''},
        // Conserva la fecha del movimiento original: la corrección de un pago de agosto sigue
        // contando en agosto. registradoTs = cuándo se capturó la corrección.
        ts:{timestampValue: d.ts || new Date().toISOString()},
        registradoTs:{timestampValue:new Date().toISOString()},
      };
      const camposOrig = camposCancelacion(user, perfil, mot, { corregidoPorId:{stringValue:nuevoId} });

      writes.push(
        { update:{ name: docName(env, `finanzas/${id}`), fields: camposOrig },
          updateMask:{ fieldPaths: Object.keys(camposOrig) }, currentDocument:{ exists:true } },
        { update:{ name: docName(env, `finanzas/${nuevoId}`), fields: fieldsNuevo }, currentDocument:{ exists:false } },
        wLimite,
        writeLogFinanzas(env, req, { movId:id, accion:'corregir', uid:user.uid, perfil, motivo:mot, relacionadoId:nuevoId,
          resumen: `Corrigió ${resumenMov(id, d)} → ${resumenMov(nuevoId, readDoc(fieldsNuevo))}`,
          antes: doc.fields, despues: fieldsNuevo }),
      );
      return { writes, value: folio };
    });
  } catch (e) {
    if (e.status === 429) await avisarLimiteFinanzas(env, req, user, perfil, id);
    throw e;
  }

  // Si el corregido es un pago de Cuota, puede saldar el adeudo → reactivación de siempre.
  // Si al revés la casa queda debiendo, NO se suspende aquí: lo decide el cron.
  if (nuevo.tipo === 'ingreso' && nuevo.cat === 'Cuota' && nuevo.casaCanon) {
    await intentarReactivarPorPago(env, nuevo.casaCanon);
  }
  return json({ ok:true, id, nuevoId, folioRecibo });
}

/* ============ /finanzas/reactivar — SOLO master, con motivo ============
   Deshace una cancelación. Si el movimiento fue CORREGIDO, solo se permite cuando la corrección
   ya está cancelada (si no, contarían los dos). */
async function reactivarFinanza(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!perfil || perfil.rol !== 'master') throw httpErr(403, 'Solo el master reactiva movimientos');

  const { id, motivo } = await req.json();
  if (!id || !ID_MOV_RE.test(id)) throw httpErr(400, 'id inválido');
  const mot = validarMotivo(motivo);

  const d = await conTx(env, async (at, tx) => {
    const doc = await txGet(env, at, `finanzas/${id}`, tx);
    if (!doc) throw httpErr(404, 'Movimiento no existe');
    const d = readDoc(doc.fields);
    if (!esCancelado(d)) throw httpErr(409, 'Ese movimiento no está cancelado');
    if (d.corregidoPorId) {
      const corr = await txGet(env, at, `finanzas/${d.corregidoPorId}`, tx);
      if (corr && !esCancelado(readDoc(corr.fields))) {
        throw httpErr(409, `Este movimiento fue corregido por ${refMov(d.corregidoPorId, readDoc(corr.fields))}: cancela primero la corrección`);
      }
    }
    // Campos en la máscara pero ausentes del body = se BORRAN del doc (limpia la cancelación;
    // el historial completo queda en finanzas_log).
    const campos = {
      estado:{stringValue:'vigente'},
      reactivadoPor:{stringValue:user.uid},
      reactivadoNombre:{stringValue:perfil.nombre||''},
      reactivadoTs:{timestampValue:new Date().toISOString()},
      motivoReactivacion:{stringValue:mot},
    };
    const mascara = [...Object.keys(campos), 'motivoCancelacion', 'canceladoPor', 'canceladoNombre', 'canceladoTs', 'corregidoPorId'];
    return { writes: [
      { update:{ name: docName(env, `finanzas/${id}`), fields: campos },
        updateMask:{ fieldPaths: mascara }, currentDocument:{ exists:true } },
      writeLogFinanzas(env, req, { movId:id, accion:'reactivar', uid:user.uid, perfil, motivo:mot,
        resumen: 'Reactivó ' + resumenMov(id, d), antes: doc.fields, despues: campos }),
    ], value: d };
  });

  if (d.tipo === 'ingreso' && d.categoria === 'Cuota' && d.casa) await intentarReactivarPorPago(env, d.casa);
  return json({ ok:true, id });
}

/* ===========================================================
   VECINOS (padrón) — FASE 5, solo staff
   Padrón de jefes de familia. El domicilio es la fuente de verdad de las "casas"
   en Finanzas. Campos uid/miembros quedan reservados para FASE 6 (vínculo con
   cuentas de login); aquí solo se inicializan, no se usan.
   El cliente NUNCA lee vecinos directo: lo hace vía /vecinos/listar (sin match en
   las reglas = denegado por default), así no hubo que tocar firestore.rules.
   =========================================================== */

/* Normaliza el domicilio SOLO para comparar unicidad: trim + colapsar espacios +
   MAYÚSCULAS. Así "Ajoya 12", "ajoya 12" y "AJOYA  12" son la misma casa. */
function normDomicilio(s) {
  return String(s || '').trim().replace(/\s+/g, ' ').toUpperCase();
}

async function crearVecino(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!esStaff(perfil)) throw httpErr(403, 'Solo staff da de alta vecinos');

  const { nombre, correo, telefono, domicilio } = await req.json();
  const nom = String(nombre || '').trim().slice(0, 80);
  const tel = String(telefono || '').trim().slice(0, 30);
  const dom = String(domicilio || '').trim().replace(/\s+/g, ' ').slice(0, 80);
  const cor = String(correo || '').trim().slice(0, 120);
  if (!nom) throw httpErr(400, 'Falta el nombre del vecino');
  if (!tel) throw httpErr(400, 'El teléfono es obligatorio');
  if (!dom) throw httpErr(400, 'Falta el domicilio');
  const domNorm = normDomicilio(dom);

  // Anti-duplicados server-side: el domicilio normalizado no debe existir aún.
  const existentes = (await firestoreList(env, 'vecinos')).map(d => readDoc(d.fields));
  if (existentes.some(v => v.domicilioNorm === domNorm)) {
    throw httpErr(409, `Ya existe un vecino con el domicilio "${dom}"`);
  }

  const id = crypto.randomUUID();
  await firestoreSet(env, `vecinos/${id}`, {
    nombre:{stringValue:nom},
    correo:{stringValue:cor},
    telefono:{stringValue:tel},
    domicilio:{stringValue:dom},
    domicilioNorm:{stringValue:domNorm},
    estado:{stringValue:'activo'},
    uid:{nullValue:null},                    // reservado FASE 6
    miembros:{arrayValue:{values:[]}},       // reservado FASE 6
    creadoPor:{stringValue:user.uid},
    creadoNombre:{stringValue:perfil.nombre||''},
    ts:{timestampValue:new Date().toISOString()},
  });
  return json({ ok:true, id });
}

async function actualizarVecino(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!esStaff(perfil)) throw httpErr(403, 'Solo staff edita vecinos');

  const { id, nombre, correo, telefono, domicilio, estado } = await req.json();
  if (!id || !/^[A-Za-z0-9-]{10,64}$/.test(id)) throw httpErr(400, 'id inválido');

  const fields = {};
  if (nombre !== undefined) {
    const nom = String(nombre).trim().slice(0, 80);
    if (!nom) throw httpErr(400, 'El nombre no puede quedar vacío');
    fields.nombre = {stringValue:nom};
  }
  if (correo !== undefined) fields.correo = {stringValue:String(correo).trim().slice(0,120)};
  if (telefono !== undefined) {
    const tel = String(telefono).trim();
    if (!tel) throw httpErr(400, 'El teléfono es obligatorio');
    fields.telefono = {stringValue:tel.slice(0,30)};
  }
  if (estado !== undefined) {
    if (!['activo','suspendido'].includes(estado)) throw httpErr(400, 'estado inválido');
    fields.estado = {stringValue:estado};
  }
  if (domicilio !== undefined) {
    const dom = String(domicilio).trim().replace(/\s+/g, ' ').slice(0, 80);
    if (!dom) throw httpErr(400, 'Falta el domicilio');
    const domNorm = normDomicilio(dom);
    const existentes = await firestoreList(env, 'vecinos');
    const dup = existentes.some(d => d.name.split('/').pop() !== id && readDoc(d.fields).domicilioNorm === domNorm);
    if (dup) throw httpErr(409, `Ya existe otro vecino con el domicilio "${dom}"`);
    fields.domicilio = {stringValue:dom};
    fields.domicilioNorm = {stringValue:domNorm};
  }
  if (!Object.keys(fields).length) throw httpErr(400, 'Nada que actualizar');

  await firestoreActualizarCampos(env, `vecinos/${id}`, fields, 'Vecino');
  return json({ ok:true, id });
}

async function listarVecinos(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!esStaff(perfil)) throw httpErr(403, 'Solo staff consulta el padrón');

  const docs = await firestoreList(env, 'vecinos');
  const vecinos = docs.map(d => {
    const x = readDoc(d.fields);
    return {
      id: d.name.split('/').pop(),
      nombre: x.nombre || '',
      correo: x.correo || '',
      telefono: x.telefono || '',
      domicilio: x.domicilio || '',
      domicilioNorm: x.domicilioNorm || '',
      estado: x.estado || 'activo',
      uid: x.uid ?? null,          // reservado FASE 6
    };
  });
  // El conteo de activos se calcula AQUÍ (server-side) y es el que usa el termómetro:
  // el frontend no lo deriva por su cuenta (no se confía en el cliente).
  const activos = vecinos.filter(v => v.estado === 'activo').length;
  return json({ vecinos, activos });
}

/* ============ /vecinos/borrar — SOLO master ============
   Baja del padrón con respaldo (mismo patrón que finanzas/borrar). Reglas:
   - Solo master (validado aquí, no se confía en el frontend).
   - Bloquea si el vecino tiene pagos en finanzas → evita recibos huérfanos; en ese
     caso solo se permite editar/suspender.
   - Copia el doc completo a vecinos_borrados (quién/cuándo/snapshot) y lo elimina de
     "vecinos", con lo que el domicilio se LIBERA para el anti-dup (que solo compara
     contra vecinos vivos, nunca contra borrados).
   - Deja registro en la bitácora. */
async function borrarVecino(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!perfil || perfil.rol !== 'master') throw httpErr(403, 'Solo master borra vecinos');

  const { id } = await req.json();
  if (!id || !/^[A-Za-z0-9-]{10,64}$/.test(id)) throw httpErr(400, 'id inválido');

  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const rGet = await fetch(`${fsBase(env)}/vecinos/${id}`, { headers:{ Authorization:'Bearer '+at } });
  if (rGet.status === 404) throw httpErr(404, 'Vecino no existe');
  if (!rGet.ok) throw httpErr(500, 'Firestore get falló');
  const docActual = await rGet.json();
  const vecino = readDoc(docActual.fields);
  const domNorm = vecino.domicilioNorm || normDomicilio(vecino.domicilio || '');

  // Bloqueo por pagos: si existe algún movimiento de finanzas de este domicilio, no se
  // borra (los recibos quedarían huérfanos). Solo editar/suspender.
  // Incluye movimientos CANCELADOS a propósito: un recibo cancelado sigue amarrado a su casa.
  const finanzas = (await firestoreList(env, 'finanzas')).map(d => readDoc(d.fields));
  const tienePagos = finanzas.some(m => m.casa && normDomicilio(m.casa) === domNorm);
  if (tienePagos) {
    throw httpErr(409, 'Este vecino tiene pagos registrados: solo puedes editarlo o suspenderlo, no borrarlo');
  }

  await firestoreSet(env, `vecinos_borrados/${id}`, {
    ...(docActual.fields || {}),
    borradoPor:{stringValue:user.uid},
    borradoNombre:{stringValue:perfil.nombre||''},
    borradoTs:{timestampValue:new Date().toISOString()},
  }, at);

  const rDel = await fetch(`${fsBase(env)}/vecinos/${id}`, { method:'DELETE', headers:{ Authorization:'Bearer '+at } });
  if (!rDel.ok) throw httpErr(500, 'Firestore delete falló');

  await logBitacora(env, at, {
    uid: user.uid,
    nombre: `${perfil.nombre || 'Master'} borró al vecino ${vecino.domicilio || id}`,
  });

  return json({ ok:true, id });
}

/* Registro de acción administrativa en la bitácora (colección aperturas). tipo:'gestion'
   la distingue de aperturas de puertas; hogar = uid del staff que actúa, así los
   residentes (que filtran su bitácora por hogar) no la ven — solo staff. */
async function logBitacora(env, at, { uid, nombre }) {
  await fetch(`${fsBase(env)}/aperturas`, {
    method:'POST', headers:{ Authorization:'Bearer '+at, 'Content-Type':'application/json' },
    body: JSON.stringify({ fields: {
      uid:{stringValue:uid},
      nombre:{stringValue:nombre},
      puerta:{stringValue:'gestion'},
      hogar:{stringValue:uid},
      tipo:{stringValue:'gestion'},
      ts:{timestampValue:new Date().toISOString()},
    }}),
  });
}

/* ===========================================================
   INVITACIONES DE REGISTRO (FASE 6) — vincular vecino → cuenta de login
   Colección registro_invitaciones/{hashToken} (SEPARADA de los QR de visita, que
   viven en /invitaciones). El token en claro NUNCA se guarda ni se genera en el
   frontend: solo su hash SHA-256, que además es el id del doc → lookup O(1) por hash,
   sin enumerar. El token viaja solo en el fragmento del link.
   =========================================================== */

async function sha256b64url(str) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return bytesToB64url(new Uint8Array(digest));
}
/* Igualdad en tiempo constante: no corta en el primer byte distinto. */
function timingSafeEqual(a, b) {
  const ba = new TextEncoder().encode(a), bb = new TextEncoder().encode(b);
  if (ba.length !== bb.length) return false;
  let diff = 0;
  for (let i = 0; i < ba.length; i++) diff |= ba[i] ^ bb[i];
  return diff === 0;
}

/* Lee y valida una invitación por su token. Devuelve { x, updateTime, hash } o null.
   Validación POR HASH y en tiempo constante — nunca por igualdad del token en claro. */
async function leerInvitacionValida(env, at, token) {
  const hash = await sha256b64url(limpiarToken(token));
  const r = await fetch(`${fsBase(env)}/registro_invitaciones/${hash}`, { headers:{ Authorization:'Bearer '+at } });
  if (!r.ok) return null;
  const doc = await r.json();
  const x = readDoc(doc.fields);
  if (!x || !timingSafeEqual(x.hashToken || '', hash)) return null;
  if (x.usado || x.reemplazada) return null;
  if (!x.expiraEn || new Date(x.expiraEn) < new Date()) return null;
  return { x, updateTime: doc.updateTime, hash };
}

/* El token es base64url: cualquier otro carácter (espacios, saltos de línea, puntuación que añade
   un chat al pegar el enlace) se descarta. Mayúsculas/minúsculas NO se tocan (cuentan). */
function limpiarToken(token) { return String(token || '').replace(/[^A-Za-z0-9_-]/g, ''); }

/* Motivo por el que una invitación NO sirve (solo se llama cuando leerInvitacionValida dio null).
   Devuelve un código, nunca datos de la persona: 'usada' | 'reemplazada' | 'vencida' | 'invalida'. */
async function motivoInvitacionFallida(env, at, token) {
  const limpio = limpiarToken(token);
  if (!limpio) return 'sin_codigo';
  const hash = await sha256b64url(limpio);
  const r = await fetch(`${fsBase(env)}/registro_invitaciones/${hash}`, { headers:{ Authorization:'Bearer '+at } });
  if (!r.ok) return 'invalida';
  const x = readDoc((await r.json()).fields);
  if (!x) return 'invalida';
  if (x.usado) return 'usada';
  if (x.reemplazada) return 'reemplazada';
  if (!x.expiraEn || new Date(x.expiraEn) < new Date()) return 'vencida';
  return 'invalida';
}
const MENSAJE_INVITACION = {
  usada: 'Esta invitación ya se usó. Si no fuiste tú, pide una nueva a la administración.',
  vencida: 'Esta invitación venció. Pide una nueva a la administración.',
  reemplazada: 'Esta invitación fue reemplazada por una más nueva. Usa el último enlace que recibiste.',
  invalida: 'Este enlace no es válido. Revisa que lo copiaste completo o pide uno nuevo a la administración.',
  sin_codigo: 'Abre el enlace completo que te mandó la administración, no el ícono de la app.',
};

/* IP truncada (privacidad): IPv4 → a.b.c.0 · IPv6 → primeros 3 grupos. */
function ipTruncada(req) {
  const ip = req.headers.get('CF-Connecting-IP') || '';
  if (ip.includes(':')) return ip.split(':').slice(0, 3).join(':') + '::';
  const p = ip.split('.');
  return p.length === 4 ? p.slice(0, 3).join('.') + '.0' : 'desconocida';
}
/* Registro de intentos fallidos de /invitaciones/validar: un doc por día + IP truncada + motivo
   con contador. NUNCA se guarda el token (ni su hash). Best-effort: jamás afecta la respuesta. */
async function registrarIntentoFallido(env, at, req, motivo) {
  try {
    const ahora = new Date(), dia = ahora.toISOString().slice(0, 10), ip = ipTruncada(req);
    const id = `${dia}_${ip.replace(/[^0-9a-fA-F.:]/g, '').replace(/:/g, '-')}_${motivo}`;
    const previo = await getDoc(env, at, `registro_intentos/${id}`);
    const p = previo ? readDoc(previo.fields) : null;
    await firestoreSet(env, `registro_intentos/${id}`, {
      dia:{stringValue:dia}, motivo:{stringValue:motivo}, ip:{stringValue:ip},
      intentos:{integerValue:String((p?.intentos || 0) + 1)},
      primero:{timestampValue: p?.primero || ahora.toISOString()}, ultimo:{timestampValue: ahora.toISOString()},
    }, at);
  } catch (e) {
    console.error('[registro_intentos] no se pudo registrar:', e && e.name);
  }
}

/* /invitaciones/crear — SOLO staff. Token de un uso para que un vecino ACTIVO y SIN
   cuenta se registre. Invalida invitaciones previas no usadas del mismo vecino (solo
   una viva a la vez). Devuelve el token en claro UNA sola vez. */
async function crearInvitacionRegistro(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!esStaff(perfil)) throw httpErr(403, 'Solo staff genera invitaciones');

  const { personaId } = await req.json();
  if (!personaId || !/^[A-Za-z0-9-]{10,64}$/.test(personaId)) throw httpErr(400, 'personaId inválido');

  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const all = await personasList(env, at);
  const byId = {}; all.forEach(p => byId[p.id] = p);
  const persona = byId[personaId];
  if (!persona) throw httpErr(404, 'Persona no existe');
  if ((persona.estado || 'activo') !== 'activo') throw httpErr(409, 'La persona no está activa');
  if (persona.uid) throw httpErr(409, 'Esta persona ya tiene una cuenta');
  if (persona.jefeId) throw httpErr(400, 'A un familiar lo invita su jefe, no staff');

  const t = await emitirInvitacion(env, at, { persona, byId, creadoPor: user.uid });
  return json({ ok:true, token: t.token, expiraEn: t.expiraEn });
}

/* /invitaciones/familiar — el JEFE (residente activo con cuenta) invita a un familiar.
   Crea la persona familiar (Sin cuenta, hereda domicilio del jefe) + token. ≤5 familiares
   vivos validado AQUÍ (server-side). Familiar y suspendido NO pueden invitar. */
async function crearInvitacionFamiliar(req, env) {
  const user = await requireAuth(req, env);
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const all = await personasList(env, at);
  const byId = {}; all.forEach(p => byId[p.id] = p);
  const jefe = all.find(p => p.uid === user.uid);
  if (!jefe) throw httpErr(403, 'Sin perfil');
  if (!esJefe(jefe)) throw httpErr(403, 'Solo un jefe de familia puede invitar familiares');
  if ((jefe.estado || 'activo') !== 'activo') throw httpErr(403, 'Tu cuenta está suspendida; no puedes invitar');

  const { nombre, telefono } = await req.json();
  const nom = String(nombre || '').trim().slice(0, 80);
  const tel = String(telefono || '').trim().slice(0, 30);
  if (!nom) throw httpErr(400, 'Falta el nombre del familiar');
  if (!tel) throw httpErr(400, 'El teléfono es obligatorio');

  // Límite de 5 familiares VIVOS (los suspendidos ocupan slot).
  if (all.filter(p => p.jefeId === jefe.id && !esBaja(p)).length >= 5) throw httpErr(409, 'Ya alcanzaste el máximo de 5 familiares');

  const fid = crypto.randomUUID();
  await firestoreSet(env, `personas/${fid}`, {
    nombre:{stringValue:nom},
    telefono:{stringValue:tel},
    correo:{nullValue:null},
    domicilio:{stringValue:''},          // familiar NO guarda domicilio: se DERIVA del jefe
    domicilioNorm:{stringValue:''},
    rol:{stringValue:'residente'},
    estado:{stringValue:'activo'},
    uid:{nullValue:null},
    jefeId:{stringValue:jefe.id},
    suspendidoPor:{nullValue:null},
    creadoPor:{stringValue:user.uid},
    creadoEn:{timestampValue:new Date().toISOString()},
    // Quién lo dio de alta: del perfil verificado en el SERVIDOR (el jefe autenticado), nunca
    // del cuerpo de la petición. Se muestra en la bitácora y en la alerta.
    dadoDeAltaPor:{stringValue:user.uid},
    dadoDeAltaNombre:{stringValue:jefe.nombre || ''},
  }, at);

  const persona = { id: fid, nombre: nom, telefono: tel, jefeId: jefe.id, rol:'residente' };
  byId[fid] = persona;
  const t = await emitirInvitacion(env, at, { persona, byId, creadoPor: user.uid });
  // Solo MARCA (nunca bloquea): el alta ya quedó hecha arriba y esto no lanza.
  await evaluarFamiliarSospechoso(env, at, { familiar: persona, jefe, all, dadoDeAltaPor: user.uid });
  return json({ ok:true, familiarId: fid, token: t.token, expiraEn: t.expiraEn });
}

/* ---- Alerta "⚠️ Posible residente de otra casa" (familiares) ----
   Detecta a un vecino que se da de alta como FAMILIAR de otra casa para entrar aunque esté
   suspendido. NO bloquea nada: solo deja una marca en alertas_familiares/{personaId} (SOLO
   staff la lee — ver reglas) para que el comité decida con las acciones que ya existen
   (suspender / borrar), y avisa por push al staff. Sospechoso si:
     a) su teléfono coincide con el de un jefe o familiar de OTRA casa, o
     b) su nombre (sin mayúsculas, acentos ni espacios extra) coincide con un residente o
        familiar SUSPENDIDO de otra casa.
   "Casa" = persona del jefe (jefe: su id; familiar: su jefeId). */
function normTel(s) {
  const d = String(s || '').replace(/\D/g, '');
  return d.length >= 8 ? d.slice(-10) : '';   // últimos 10: ignora +52 / 044 / lada
}
function coincidenciasFamiliar(familiar, jefeId, all) {
  const byId = {}; all.forEach(p => byId[p.id] = p);
  const tel = normTel(familiar.telefono), nom = normNombre(familiar.nombre);
  const out = [];
  for (const p of all) {
    if (p.id === familiar.id || p.rol !== 'residente') continue;
    if ((p.jefeId || p.id) === jefeId) continue;           // misma casa: no cuenta
    const porTel = !!tel && normTel(p.telefono) === tel;
    const porNombre = !!nom && p.estado === 'suspendido' && normNombre(p.nombre) === nom;
    if (!porTel && !porNombre) continue;
    const dom = domicilioDe(p, byId);
    out.push({ id: p.id, motivo: porTel ? 'telefono' : 'nombre', texto: `${p.nombre}${dom ? ' (' + dom + ')' : ''}` });
  }
  return out;
}
function idsCoincidencia(c) { return [...new Set(c.map(x => x.id))].sort().join(','); }
/* Escribe (crea o REACTIVA) la alerta ACTIVA de un familiar y avisa por push al staff. */
async function marcarFamiliar(env, at, { familiar, jefe, c, dadoDeAltaPor, dadoDeAltaNombre, previa, origen }) {
  const coincideCon = c.map(x => x.texto).join('; ').slice(0, 300);
  const motivos = [...new Set(c.map(x => x.motivo))];
  await firestoreSet(env, `alertas_familiares/${familiar.id}`, {
    personaId:{stringValue:familiar.id}, nombre:{stringValue:familiar.nombre || ''},
    telefono:{stringValue:familiar.telefono || ''},
    jefeId:{stringValue:jefe.id}, jefeNombre:{stringValue:jefe.nombre || ''}, casa:{stringValue:jefe.domicilio || ''},
    dadoDeAltaPor:{stringValue:dadoDeAltaPor || ''}, dadoDeAltaNombre:{stringValue:dadoDeAltaNombre || ''},
    tipoAlerta:{stringValue:'posible-otra-casa'},
    motivos:{arrayValue:{values: motivos.map(m => ({stringValue:m}))}},
    coincideCon:{stringValue:coincideCon},
    coincideIds:{stringValue:idsCoincidencia(c)},   // con QUIÉN coincide (ids del padrón), para comparar
    estado:{stringValue:'activa'},
    origen:{stringValue:origen},   // 'alta' | 'edicion'
    creadaEn:{timestampValue:(previa && previa.creadaEn) || new Date().toISOString()},
    actualizadaEn:{timestampValue:new Date().toISOString()},
    // Una revisión/descartado anterior ya no aplica a la coincidencia nueva: se limpia (el
    // historial de quién revisó queda en la bitácora general).
    revisadoPor:{nullValue:null}, revisadoNombre:{nullValue:null}, revisadoEn:{nullValue:null},
  }, at);
  await pushStaff(env, '⚠️ Familiar marcado · Cerrada Mojave',
    `${familiar.nombre}, familiar de ${jefe.nombre || '—'} (${jefe.domicilio || '—'}): posible residente de otra casa · coincide con ${coincideCon}`
    + (origen === 'edicion' ? ' (tras editar el padrón)' : ''));
  return { coincideCon, motivos };
}
/* Alta de un familiar. Nunca lanza: el alta ya está hecha y no debe fallar por esto. */
async function evaluarFamiliarSospechoso(env, at, { familiar, jefe, all, dadoDeAltaPor }) {
  try {
    const c = coincidenciasFamiliar(familiar, jefe.id, all);
    if (!c.length) return null;
    return await marcarFamiliar(env, at, { familiar, jefe, c, dadoDeAltaPor, dadoDeAltaNombre: jefe.nombre || '', previa: null, origen: 'alta' });
  } catch (e) {
    console.error('[alerta-familiar] no se pudo evaluar:', e && e.name);
    return null;
  }
}
/* Tras EDITAR nombre, teléfono o domicilio de un residente (jefe o familiar): se vuelve a
   evaluar a TODOS los familiares con la misma lógica, porque el dato editado puede crear o
   quitar coincidencias en OTRAS casas (p.ej. el teléfono nuevo de un jefe = el de un familiar
   ajeno). `all` ya trae los datos editados. Solo MARCA, nunca bloquea; nunca lanza.
     - coincide y no había alerta (o estaba descartada) → alerta ACTIVA + push
     - coincide y estaba ACTIVA → actualiza con quién coincide (sin push)
     - coincide y estaba REVISADA ("es correcto"): se respeta si coincide con lo MISMO que se
       revisó (mismas personas, por id); si ahora coincide con alguien distinto es un caso nuevo → se reactiva + push
     - ya NO coincide y estaba ACTIVA → se descarta sola, con registro (quién editó y cuándo) */
async function reevaluarAlertasFamiliares(env, at, all, { editor, editado }) {
  const cambios = [];
  try {
    const byId = {}; all.forEach(p => byId[p.id] = p);
    const previas = {};
    (await firestoreList(env, 'alertas_familiares')).forEach(d => { previas[d.name.split('/').pop()] = readDoc(d.fields); });
    for (const f of all.filter(p => p.rol === 'residente' && p.jefeId)) {
      const jefe = byId[f.jefeId]; if (!jefe) continue;
      const previa = previas[f.id] || null;
      const c = coincidenciasFamiliar(f, jefe.id, all);
      const coincideCon = c.map(x => x.texto).join('; ').slice(0, 300);
      const dadoDeAltaNombre = f.dadoDeAltaNombre || previa?.dadoDeAltaNombre || '';
      if (c.length) {
        const nueva = !previa || previa.estado === 'descartada' || (previa.estado === 'revisada' && (previa.coincideIds || '') !== idsCoincidencia(c));
        if (nueva) {
          await marcarFamiliar(env, at, { familiar: f, jefe, c, dadoDeAltaPor: f.dadoDeAltaPor || previa?.dadoDeAltaPor || '', dadoDeAltaNombre, previa, origen: 'edicion' });
          cambios.push(`${previa ? 'reactivó' : 'marcó'} a ${f.nombre}`);
        } else if (previa.estado === 'activa' && (previa.coincideCon !== coincideCon || previa.nombre !== f.nombre || previa.telefono !== (f.telefono || '') || previa.casa !== (jefe.domicilio || ''))) {
          await firestoreActualizarCampos(env, `alertas_familiares/${f.id}`, {
            coincideCon:{stringValue:coincideCon}, coincideIds:{stringValue:idsCoincidencia(c)},
            motivos:{arrayValue:{values: [...new Set(c.map(x => x.motivo))].map(m => ({stringValue:m}))}},
            nombre:{stringValue:f.nombre || ''}, telefono:{stringValue:f.telefono || ''}, casa:{stringValue:jefe.domicilio || ''},
            actualizadaEn:{timestampValue:new Date().toISOString()},
          }, 'Alerta');
        }
      } else if (previa && previa.estado === 'activa') {
        await firestoreActualizarCampos(env, `alertas_familiares/${f.id}`, {
          estado:{stringValue:'descartada'},
          descartadaEn:{timestampValue:new Date().toISOString()},
          descartadaPor:{stringValue:editor.uid}, descartadaNombre:{stringValue:editor.nombre || ''},
          motivoDescarte:{stringValue:`Ya no coincide tras editar a ${editado}`},
        }, 'Alerta');
        cambios.push(`descartó la alerta de ${f.nombre} (ya no coincide)`);
      }
    }
    if (cambios.length) {
      await logBitacora(env, at, { uid: editor.uid, nombre: `Alertas de familiares tras editar a ${editado} (${editor.nombre || 'staff'}): ${cambios.join('; ')}`.slice(0, 500) });
    }
  } catch (e) {
    console.error('[alerta-familiar] no se pudo reevaluar:', e && e.name);
  }
  return cambios;
}
/* Push a TODO el staff (master, admin y jefe-admin activo) con notificaciones activas. Nunca lanza. */
async function pushStaff(env, titulo, texto) {
  try {
    const staff = (await firestoreList(env, 'usuarios')).map(d => readDoc(d.fields)).filter(u => esStaff(u) && u.fcmToken);
    if (!staff.length) return;
    const atFcm = await saToken(env, 'https://www.googleapis.com/auth/firebase.messaging');
    for (const s of staff) {
      await fetch(`https://fcm.googleapis.com/v1/projects/${env.FIREBASE_PROJECT}/messages:send`, {
        method: 'POST', headers: { Authorization: 'Bearer ' + atFcm, 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: { token: s.fcmToken, notification: { title: titulo, body: texto.slice(0, 900) } } }),
      }).catch(() => {});
    }
  } catch (e) {
    console.error('[pushStaff]', e && e.name);
  }
}

/* /personas/alerta-revisar — SOLO staff. "Revisado, es correcto": quita la marca de un
   familiar (caso legítimo). Queda registrado quién y cuándo en la alerta y en la bitácora.
   No borra la alerta (historial); desde ese momento sus aperturas ya no se marcan. */
async function revisarAlertaFamiliar(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!esStaff(perfil)) throw httpErr(403, 'Solo staff revisa alertas');
  const { personaId } = await req.json();
  if (!personaId || !/^[A-Za-z0-9-]{10,64}$/.test(personaId)) throw httpErr(400, 'personaId inválido');
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const doc = await getDoc(env, at, `alertas_familiares/${personaId}`);
  const a = doc && readDoc(doc.fields);
  if (!a) throw httpErr(404, 'Esa alerta no existe');
  if (a.estado !== 'activa') throw httpErr(409, 'Esa alerta ya no está activa (revisada o descartada)');
  const ahora = new Date().toISOString();
  await firestoreActualizarCampos(env, `alertas_familiares/${personaId}`, {
    estado:{stringValue:'revisada'}, revisadoPor:{stringValue:user.uid},
    revisadoNombre:{stringValue:perfil.nombre || ''}, revisadoEn:{timestampValue:ahora},
  }, 'Alerta');
  await logBitacora(env, at, {
    uid: user.uid,
    nombre: `${perfil.nombre || 'Staff'} revisó la alerta de ${a.nombre}${a.casa ? ' (familiar de ' + a.casa + ')' : ''}: es correcto`,
  });
  return json({ ok:true, personaId, revisadoEn: ahora });
}

/* /invitaciones/familiar-reenviar — el JEFE re-emite el link de un familiar suyo que sigue
   "Sin cuenta" (perdió el mensaje). NO crea persona ni cuenta contra el tope de 5: solo emite
   un token nuevo (emitirInvitacion invalida el previo). Mismas validaciones que crear: solo el
   jefe DUEÑO, jefe suspendido NO puede, y no se reenvía a alguien ya registrado. */
async function reenviarInvitacionFamiliar(req, env) {
  const user = await requireAuth(req, env);
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const all = await personasList(env, at);
  const byId = {}; all.forEach(p => byId[p.id] = p);
  const jefe = all.find(p => p.uid === user.uid);
  if (!jefe) throw httpErr(403, 'Sin perfil');
  if (!esJefe(jefe)) throw httpErr(403, 'Solo un jefe de familia puede reenviar invitaciones');
  if ((jefe.estado || 'activo') !== 'activo') throw httpErr(403, 'Tu cuenta está suspendida; no puedes invitar');

  const { id } = await req.json();
  if (!id || !/^[A-Za-z0-9-]{10,64}$/.test(id)) throw httpErr(400, 'id inválido');
  const fam = byId[id];
  if (!fam || fam.jefeId !== jefe.id) throw httpErr(404, 'Ese familiar no es tuyo');
  if (fam.uid) throw httpErr(409, 'Ese familiar ya tiene cuenta');

  const t = await emitirInvitacion(env, at, { persona: fam, byId, creadoPor: user.uid });
  return json({ ok:true, familiarId: fam.id, token: t.token, expiraEn: t.expiraEn });
}

/* Emite un token de un uso para una persona: invalida los previos no usados de esa persona
   (solo una viva a la vez) y guarda el hash + datos denormalizados (nombre + domicilio
   resuelto para mostrar). Devuelve el token en claro UNA sola vez. */
async function emitirInvitacion(env, at, { persona, byId, creadoPor }) {
  const previas = (await firestoreList(env, 'registro_invitaciones'))
    .filter(d => { const x = readDoc(d.fields); return x.personaId === persona.id && !x.usado && !x.reemplazada; });
  // Las anteriores NO se borran: se marcan "reemplazada" para poder decirle al vecino el motivo real.
  for (const d of previas) {
    const r = await fetch(`${fsBase(env)}/registro_invitaciones/${d.name.split('/').pop()}?updateMask.fieldPaths=reemplazada&updateMask.fieldPaths=reemplazadaEn`, {
      method:'PATCH', headers:{ Authorization:'Bearer '+at, 'Content-Type':'application/json' },
      body: JSON.stringify({ fields:{ reemplazada:{booleanValue:true}, reemplazadaEn:{timestampValue:new Date().toISOString()} } }),
    });
    if (!r.ok) throw httpErr(500, 'No se pudo invalidar la invitación anterior');
  }
  const token = bytesToB64url(crypto.getRandomValues(new Uint8Array(32)));
  const hash = await sha256b64url(token);
  const expiraEn = new Date(Date.now() + 72 * 3600 * 1000).toISOString();
  await firestoreSet(env, `registro_invitaciones/${hash}`, {
    hashToken:{stringValue:hash},
    personaId:{stringValue:persona.id},
    domicilio:{stringValue: domicilioDe(persona, byId)},
    nombre:{stringValue: persona.nombre || ''},
    creadoPor:{stringValue: creadoPor},
    creadoEn:{timestampValue:new Date().toISOString()},
    expiraEn:{timestampValue:expiraEn},
    usado:{booleanValue:false},
    usadoEn:{nullValue:null},
  }, at);
  return { token, expiraEn };
}

/* /personas/familiar-cancelar — el JEFE elimina a un familiar suyo que sigue "Sin cuenta"
   (invitado pero nunca registrado), liberando el slot; invalida sus invitaciones vivas. */
async function cancelarFamiliar(req, env) {
  const user = await requireAuth(req, env);
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const all = await personasList(env, at);
  const jefe = all.find(p => p.uid === user.uid);
  if (!jefe || !esJefe(jefe)) throw httpErr(403, 'Solo un jefe puede cancelar a sus familiares');

  const { id } = await req.json();
  if (!id || !/^[A-Za-z0-9-]{10,64}$/.test(id)) throw httpErr(400, 'id inválido');
  const fam = all.find(p => p.id === id);
  if (!fam || fam.jefeId !== jefe.id) throw httpErr(404, 'Ese familiar no es tuyo');
  if (fam.uid) throw httpErr(409, 'Ese familiar ya tiene cuenta; no se puede cancelar aquí');

  for (const iv of (await firestoreList(env, 'registro_invitaciones')).filter(d => { const x = readDoc(d.fields); return x.personaId === id && !x.usado; })) {
    await fetch(`${fsBase(env)}/registro_invitaciones/${iv.name.split('/').pop()}`, { method:'DELETE', headers:{ Authorization:'Bearer '+at } }).catch(()=>{});
  }
  await fetch(`${fsBase(env)}/personas/${id}`, { method:'DELETE', headers:{ Authorization:'Bearer '+at } });
  return json({ ok:true, id });
}

/* /invitaciones/validar — PÚBLICO (token-gated). Solo revela nombre + domicilio.
   Error genérico si no sirve (sin decir si fue inexistente/usada/vencida). */
async function validarInvitacionRegistro(req, env) {
  const { token } = await req.json();
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const inv = await leerInvitacionValida(env, at, token);
  if (!inv) {
    const motivo = await motivoInvitacionFallida(env, at, token);
    await registrarIntentoFallido(env, at, req, motivo);
    return json({ error: MENSAJE_INVITACION[motivo], motivo }, 400);   // código de motivo, sin datos de la persona
  }
  return json({ ok:true, nombre: inv.x.nombre || '', domicilio: inv.x.domicilio || '' });
}

/* /invitaciones/completar — PÚBLICO. Crea la cuenta del residente. QUEMA-PRIMERO:
   CAS atómico usado:false→true por precondición de updateTime; si gana la carrera crea
   la cuenta y escribe el uid; si la creación falla (p.ej. correo ya existe) revierte el
   token a usado:false. rol/casa/nombre los pone el Worker desde el doc del vecino —
   NUNCA del payload del cliente. */
async function completarInvitacionRegistro(req, env) {
  const { token, email, password } = await req.json();
  const correo = String(email || '').trim();
  const pass = String(password || '');
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(correo)) throw httpErr(400, 'Correo inválido');
  if (pass.length < 8) throw httpErr(400, 'La contraseña debe tener al menos 8 caracteres');

  const at = await saToken(env, 'https://www.googleapis.com/auth/identitytoolkit https://www.googleapis.com/auth/datastore');
  const inv = await leerInvitacionValida(env, at, token);
  if (!inv) throw httpErr(400, 'Invitación inválida o expirada');

  // La persona debe seguir viva, activa y sin cuenta. rol/domicilio/jefeId salen del doc.
  const all = await personasList(env, at);
  const byId = {}; all.forEach(p => byId[p.id] = p);
  const persona = byId[inv.x.personaId];
  if (!persona) throw httpErr(409, 'La invitación ya no es válida');
  if (persona.uid) throw httpErr(409, 'Esta persona ya tiene una cuenta');
  if ((persona.estado || 'activo') !== 'activo') throw httpErr(409, 'Esta persona está suspendida');

  // 1) QUEMA-PRIMERO con compare-and-set (precondición updateTime). 412 = otro ya lo quemó.
  const burnUrl = `${fsBase(env)}/registro_invitaciones/${inv.hash}`
    + `?updateMask.fieldPaths=usado&updateMask.fieldPaths=usadoEn`
    + `&currentDocument.updateTime=${encodeURIComponent(inv.updateTime)}`;
  const rBurn = await fetch(burnUrl, {
    method:'PATCH', headers:{ Authorization:'Bearer '+at, 'Content-Type':'application/json' },
    body: JSON.stringify({ fields:{ usado:{booleanValue:true}, usadoEn:{timestampValue:new Date().toISOString()} } }),
  });
  if (rBurn.status === 412 || rBurn.status === 409) throw httpErr(409, 'Esta invitación ya fue usada');
  if (!rBurn.ok) throw httpErr(500, 'No se pudo procesar la invitación');

  const revertirQuemado = async () => {
    await fetch(`${fsBase(env)}/registro_invitaciones/${inv.hash}?updateMask.fieldPaths=usado&updateMask.fieldPaths=usadoEn`, {
      method:'PATCH', headers:{ Authorization:'Bearer '+at, 'Content-Type':'application/json' },
      body: JSON.stringify({ fields:{ usado:{booleanValue:false}, usadoEn:{nullValue:null} } }),
    }).catch(()=>{});
  };

  // 2) Crear la cuenta de Auth (nombre del padrón). Si el correo ya existe, revertir.
  const res = await fetch(`https://identitytoolkit.googleapis.com/v1/projects/${env.FIREBASE_PROJECT}/accounts`, {
    method:'POST', headers:{ Authorization:'Bearer '+at, 'Content-Type':'application/json' },
    body: JSON.stringify({ email: correo, password: pass, displayName: persona.nombre || '', emailVerified:false }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    await revertirQuemado();
    if (String(err.error?.message || '').startsWith('EMAIL_EXISTS')) {
      throw httpErr(409, 'Ese correo ya está registrado. Usa otro o inicia sesión con él.');
    }
    throw httpErr(400, 'No se pudo crear la cuenta');
  }
  const { localId } = await res.json();

  // 3) Escribir correo+uid en la PERSONA (fuente de verdad) y sincronizar el índice
  //    usuarios/{uid} (rol/casa/estado desde el doc de la persona, jamás del payload).
  await firestoreActualizarCampos(env, `personas/${persona.id}`, { correo:{stringValue:correo}, uid:{stringValue:localId} }, 'Persona');
  byId[persona.id] = { ...persona, correo, uid: localId };
  await syncUsuarioIndex(env, at, byId[persona.id], byId);

  return json({ ok:true });
}

/* ===========================================================
   PERSONAS (FASE 6.5) — padrón unificado. personas/{personaId} (id random estable) es
   la FUENTE DE VERDAD; el Worker lee de ahí rol/estado/domicilio, nunca del payload.
   usuarios/{uid} se mantiene como índice de auth (para reglas, getPerfil y /abrir) y lo
   sincroniza el Worker. Jefe = residente sin jefeId (la CASA). Familiar = residente con
   jefeId (HEREDA el domicilio del jefe, no se guarda copia). Admin/master = sin domicilio.
   =========================================================== */

async function personasList(env, at) {
  at = at || await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const docs = await firestoreList(env, 'personas');
  return docs.map(d => ({ id: d.name.split('/').pop(), ...readDoc(d.fields) }));
}
/* domicilio efectivo: el familiar HEREDA el del jefe (derivado, no copiado). */
function domicilioDe(p, byId) {
  if (p.jefeId) { const j = byId[p.jefeId]; return j ? (j.domicilio || '') : ''; }
  return p.domicilio || '';
}
/* BAJA (venta de casa, mudanza): la persona queda en el padrón solo para auditoría. Una baja ya no
   cuenta como casa (cobranza, cupo, anti-duplicado de domicilio: el domicilio queda libre). */
const esBaja = p => !!p && p.estado === 'baja';
function esJefe(p) { return p.rol === 'residente' && !p.jefeId && !esBaja(p); }

/* Proyecta la persona a usuarios/{uid} (solo si tiene cuenta) para reglas/getPerfil/abrir.
   updateMask para NO borrar el fcmToken que escribe el cliente. */
async function syncUsuarioIndex(env, at, persona, byId) {
  if (!persona || !persona.uid || esBaja(persona)) return;
  const fields = {
    nombre:{stringValue: persona.nombre || ''},
    rol:{stringValue: persona.rol || 'residente'},
    casa:{stringValue: domicilioDe(persona, byId)},
    estado:{stringValue: persona.estado || 'activo'},
    suspendido:{booleanValue: (persona.estado || 'activo') === 'suspendido'},
    personaId:{stringValue: persona.id},
    jefeId:{stringValue: persona.jefeId || ''},
    esAdmin:{booleanValue: persona.esAdmin === true},   // FASE 7: lo leen esStaff() y staff() de las reglas
  };
  if (persona.correo) fields.email = {stringValue: persona.correo};
  await firestoreUpdate(env, `usuarios/${persona.uid}`, fields, Object.keys(fields));
}
/* Reindexar una persona y (si cambió su domicilio) todos sus familiares registrados. */
async function resyncFamilia(env, at, personaId, incluirFamiliares) {
  const all = await personasList(env, at);
  const byId = {}; all.forEach(p => byId[p.id] = p);
  await syncUsuarioIndex(env, at, byId[personaId], byId);
  if (incluirFamiliares) {
    for (const f of all.filter(x => x.jefeId === personaId)) await syncUsuarioIndex(env, at, f, byId);
  }
}

/* /personas/crear — SOLO staff. Alta de jefe (residente) o admin. El familiar NO se crea
   aquí (lo invita su jefe). El correo NO se captura (lo pone la persona al registrarse). */
async function crearPersona(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!esStaff(perfil)) throw httpErr(403, 'Solo staff da de alta personas');

  const { nombre, telefono, domicilio, rol, confirmarDuplicado } = await req.json();
  const nom = String(nombre || '').trim().slice(0, 80);
  const tel = String(telefono || '').trim().slice(0, 30);
  if (!nom) throw httpErr(400, 'Falta el nombre');
  if (!tel) throw httpErr(400, 'El teléfono es obligatorio');
  if (!['admin', 'residente'].includes(rol)) throw httpErr(400, 'Rol inválido (admin o residente)');
  if (rol === 'admin' && perfil.rol !== 'master') throw httpErr(403, 'Solo master crea administradores');

  let dom = '', domNorm = '';
  if (rol === 'residente') {
    dom = String(domicilio || '').trim().replace(/\s+/g, ' ').slice(0, 80);
    if (!dom) throw httpErr(400, 'El domicilio es obligatorio para residentes');
    domNorm = normDomicilio(dom);
    // Anti-duplicados SOLO entre jefes de familia vivos.
    const jefes = (await personasList(env)).filter(p => esJefe(p));
    if (jefes.some(j => j.domicilioNorm === domNorm)) throw httpErr(409, `Ya existe una casa con el domicilio "${dom}"`);
  }

  // Mismo teléfono o mismo nombre completo que alguien del padrón: NO bloquea. Sin confirmación
  // explícita responde 409 con la lista para que el staff decida; con confirmación crea el alta
  // MARCADA (roja en Gestión) para que el comité la revise. Solo marca, nunca impide.
  const todas = await personasList(env);
  const dup = duplicadosAlta(nom, tel, todas);
  if (dup.length && confirmarDuplicado !== true) {
    return json({ error: 'Ya existe ' + dup.map(d => d.texto).join('; '), requiereConfirmacion: true, duplicados: dup.map(d => d.texto) }, 409);
  }

  const id = crypto.randomUUID();
  await firestoreSet(env, `personas/${id}`, {
    nombre:{stringValue:nom},
    telefono:{stringValue:tel},
    correo:{nullValue:null},
    domicilio:{stringValue:dom},
    domicilioNorm:{stringValue:domNorm},
    rol:{stringValue:rol},
    estado:{stringValue:'activo'},
    esAdmin:{booleanValue:false},        // FASE 7: solo el master lo prende, vía /personas/admin
    uid:{nullValue:null},
    jefeId:{nullValue:null},
    suspendidoPor:{nullValue:null},
    creadoPor:{stringValue:user.uid},
    creadoEn:{timestampValue:new Date().toISOString()},
    dadoDeAltaNombre:{stringValue: perfil.nombre || ''},
    ...(dup.length ? {
      duplicadoEstado:{stringValue:'activa'},
      duplicadoCon:{stringValue: dup.map(d => d.texto).join('; ').slice(0, 300)},
    } : {}),
  });
  if (dup.length) {
    await pushStaff(env, '⚠️ Alta duplicada · Cerrada Mojave',
      `${nom}${dom ? ' (' + dom + ')' : ''} dada de alta por ${perfil.nombre || 'staff'}: coincide con ${dup.map(d => d.texto).join('; ')}`);
  }
  return json({ ok:true, id, duplicado: dup.length > 0 });
}

/* Coincidencias de un alta con el padrón: mismo teléfono (últimos 10 dígitos) o mismo nombre
   completo (sin acentos/mayúsculas/espacios extra). Cualquier rol cuenta. */
function duplicadosAlta(nombre, telefono, all) {
  const byId = {}; all.forEach(p => byId[p.id] = p);
  const tel = normTel(telefono), nom = normNombre(nombre);
  const out = [];
  for (const p of all) {
    const porTel = !!tel && normTel(p.telefono) === tel;
    const porNombre = !!nom && normNombre(p.nombre) === nom;
    if (!porTel && !porNombre) continue;
    const dom = domicilioDe(p, byId);
    out.push({ id: p.id, motivo: porTel ? 'telefono' : 'nombre', texto: `${p.nombre}${dom ? ' · ' + dom : ''}` });
  }
  return out;
}

/* /personas/actualizar — SOLO staff. Edita nombre/teléfono/domicilio. El familiar no
   tiene domicilio propio. Renombrar domicilio se BLOQUEA si la casa tiene pagos. */
async function actualizarPersona(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!esStaff(perfil)) throw httpErr(403, 'Solo staff edita personas');

  const { id, nombre, telefono, domicilio } = await req.json();
  if (!id || !/^[A-Za-z0-9-]{10,64}$/.test(id)) throw httpErr(400, 'id inválido');
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const all = await personasList(env, at);
  const byId = {}; all.forEach(p => byId[p.id] = p);
  const p = byId[id]; if (!p) throw httpErr(404, 'Persona no existe');
  if (esBaja(p)) throw httpErr(409, 'Esta persona está dada de baja: solo consulta.');
  if (esStaffPersona(p) && perfil.rol !== 'master') throw httpErr(403, 'Solo master puede editar a un administrador');

  const fields = {};
  if (nombre !== undefined) { const nom = String(nombre).trim().slice(0,80); if (!nom) throw httpErr(400,'El nombre no puede quedar vacío'); fields.nombre = {stringValue:nom}; }
  if (telefono !== undefined) { const tel = String(telefono).trim(); if (!tel) throw httpErr(400,'El teléfono es obligatorio'); fields.telefono = {stringValue:tel.slice(0,30)}; }
  let cambioDomicilio = false;
  if (domicilio !== undefined) {
    if (p.jefeId) throw httpErr(400, 'Un familiar hereda el domicilio del jefe; no se edita aparte');
    if (p.rol !== 'residente') throw httpErr(400, 'Solo los residentes (jefes) tienen domicilio');
    const dom = String(domicilio).trim().replace(/\s+/g, ' ').slice(0, 80);
    if (!dom) throw httpErr(400, 'Falta el domicilio');
    const domNorm = normDomicilio(dom);
    if (domNorm !== p.domicilioNorm) {
      // Incluye movimientos CANCELADOS a propósito: un recibo cancelado sigue amarrado a su casa.
      const finanzas = (await firestoreList(env, 'finanzas')).map(d => readDoc(d.fields));
      if (finanzas.some(m => m.casa && normDomicilio(m.casa) === p.domicilioNorm)) {
        throw httpErr(409, 'Esta casa tiene pagos registrados: no se puede renombrar el domicilio (rompería recibos y morosos). Solo se permite si no tiene pagos.');
      }
      if (all.some(x => esJefe(x) && x.id !== id && x.domicilioNorm === domNorm)) throw httpErr(409, `Ya existe otra casa con el domicilio "${dom}"`);
      fields.domicilio = {stringValue:dom}; fields.domicilioNorm = {stringValue:domNorm};
      cambioDomicilio = true;
    }
  }
  if (!Object.keys(fields).length) throw httpErr(400, 'Nada que actualizar');

  await firestoreActualizarCampos(env, `personas/${id}`, fields, 'Persona');
  await resyncFamilia(env, at, id, cambioDomicilio);   // si cambió domicilio, resync familiares
  // v13 — nombre/teléfono/domicilio de un residente (jefe o familiar) cambian las
  // coincidencias: se reevalúan las alertas de familiares. Solo marca; nunca lanza.
  if (p.rol === 'residente') {
    const editadaP = { ...p };
    for (const [k, v] of Object.entries(fields)) editadaP[k] = v.stringValue;
    await reevaluarAlertasFamiliares(env, at, all.map(x => x.id === id ? editadaP : x),
      { editor: { uid: user.uid, nombre: perfil.nombre || '' }, editado: editadaP.nombre || id });
  }
  return json({ ok:true, id });
}

/* CAMPO RESERVADO (aún no implementado en ningún lado): motivoSuspension.
   Cuando se construya la auto-suspensión por mora (Cron Trigger), esa función escribirá
   motivoSuspension:'mora' en las personas que suspenda automáticamente.
   Este campo NUNCA debe escribirse aquí en /personas/suspender (suspensión manual de staff),
   ni en /personas/reactivar, ni en crearPersona/crearInvitacionFamiliar.
   La AUSENCIA de este campo (undefined/null) es la señal de "esta persona fue suspendida
   o está activa por decisión manual de un humano — el cron nunca debe tocarla".
   Solo el cron, en el futuro, leerá y escribirá este campo.
   ACTUALIZACIÓN: ya implementado (ver aplicarSuspensionAutomatica/intentarReactivarPorPago).
   NO CONFUNDIR con motivoManual (abajo) — son dos campos separados a propósito: motivoManual
   es el texto libre que el staff escribe al suspender a mano (por qué), motivoSuspension es
   la marca fija 'mora' que solo pone el cron (para qué NO debe tocarla el cron). */

/* /personas/suspender — SOLO staff. Suspender jefe hace CASCADA a sus familiares activos
   (suspendidoPor='cascada'). Suspender familiar es individual. Todo en el Worker.
   motivoManual (texto libre, requerido, máx 200) queda guardado en el jefe y en cada familiar
   de la cascada, visible para cualquier staff — para que nadie tenga que preguntar por qué. */
async function suspenderPersona(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!esStaff(perfil)) throw httpErr(403, 'Solo staff suspende personas');

  const { id, motivo } = await req.json();
  if (!id || !/^[A-Za-z0-9-]{10,64}$/.test(id)) throw httpErr(400, 'id inválido');
  const motivoManual = String(motivo || '').trim().slice(0, 200);
  if (!motivoManual) throw httpErr(400, 'Falta el motivo de la suspensión');
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const all = await personasList(env, at);
  const byId = {}; all.forEach(x => byId[x.id] = x);
  const p = byId[id]; if (!p) throw httpErr(404, 'Persona no existe');
  if (esBaja(p)) throw httpErr(409, 'Esta persona está dada de baja: no se suspende.');
  if (p.rol === 'master') throw httpErr(403, 'No se puede suspender un master');
  if (esStaffPersona(p) && perfil.rol !== 'master') throw httpErr(403, 'Solo master puede suspender a un administrador');

  await firestoreActualizarCampos(env, `personas/${id}`, { estado:{stringValue:'suspendido'}, suspendidoPor:{stringValue:'individual'}, motivoManual:{stringValue:motivoManual} }, 'Persona');
  if (esJefe(p)) {
    for (const f of all.filter(x => x.jefeId === id && x.estado === 'activo')) {
      await firestoreActualizarCampos(env, `personas/${f.id}`, { estado:{stringValue:'suspendido'}, suspendidoPor:{stringValue:'cascada'}, motivoManual:{stringValue:motivoManual} }, 'Persona');
    }
  }
  await resyncFamilia(env, at, id, esJefe(p));
  await logBitacora(env, at, { uid:user.uid, nombre: `${perfil.nombre || 'Staff'} suspendió a ${p.nombre}${p.domicilio ? ' ('+p.domicilio+')' : ''} — motivo: ${motivoManual}` });
  return json({ ok:true, id });
}

/* /personas/reactivar — SOLO staff. Reactivar jefe reactiva SOLO los familiares con
   suspendidoPor='cascada'. No se puede reactivar un familiar si su jefe sigue suspendido. */
async function reactivarPersona(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!esStaff(perfil)) throw httpErr(403, 'Solo staff reactiva personas');

  const { id } = await req.json();
  if (!id || !/^[A-Za-z0-9-]{10,64}$/.test(id)) throw httpErr(400, 'id inválido');
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const all = await personasList(env, at);
  const byId = {}; all.forEach(x => byId[x.id] = x);
  const p = byId[id]; if (!p) throw httpErr(404, 'Persona no existe');
  if (esBaja(p)) throw httpErr(409, 'Esta persona está dada de baja: no se reactiva.');
  if (esStaffPersona(p) && perfil.rol !== 'master') throw httpErr(403, 'Solo master puede reactivar a un administrador');
  if (p.jefeId) {
    const jefe = byId[p.jefeId];
    if (jefe && jefe.estado === 'suspendido') throw httpErr(409, 'Reactiva primero al jefe de familia (la casa está suspendida).');
  }

  await firestoreActualizarCampos(env, `personas/${id}`, { estado:{stringValue:'activo'}, suspendidoPor:{nullValue:null}, motivoManual:{nullValue:null} }, 'Persona');
  if (esJefe(p)) {
    for (const f of all.filter(x => x.jefeId === id && x.estado === 'suspendido' && x.suspendidoPor === 'cascada')) {
      await firestoreActualizarCampos(env, `personas/${f.id}`, { estado:{stringValue:'activo'}, suspendidoPor:{nullValue:null}, motivoManual:{nullValue:null} }, 'Persona');
    }
  }
  await resyncFamilia(env, at, id, esJefe(p));
  await logBitacora(env, at, { uid:user.uid, nombre: `${perfil.nombre || 'Staff'} reactivó a ${p.nombre}${p.domicilio ? ' ('+p.domicilio+')' : ''}` });
  return json({ ok:true, id });
}

/* /personas/borrar — SOLO master. Bloquea si el jefe tiene familiares o pagos. Respalda a
   personas_borradas, borra la cuenta Auth + índice usuarios + invitaciones vivas, y registra. */
async function borrarPersona(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!perfil || perfil.rol !== 'master') throw httpErr(403, 'Solo master borra personas');

  const { id } = await req.json();
  if (!id || !/^[A-Za-z0-9-]{10,64}$/.test(id)) throw httpErr(400, 'id inválido');
  const at = await saToken(env, 'https://www.googleapis.com/auth/identitytoolkit https://www.googleapis.com/auth/datastore');
  const all = await personasList(env, at);
  const byId = {}; all.forEach(x => byId[x.id] = x);
  const p = byId[id]; if (!p) throw httpErr(404, 'Persona no existe');
  if (esBaja(p)) throw httpErr(409, 'Esta persona está dada de baja: se conserva para auditoría (pagos e historial).');
  if (p.rol === 'master') throw httpErr(403, 'No se puede borrar un master');

  if (esJefe(p)) {
    const nFam = all.filter(x => x.jefeId === id).length;
    if (nFam) throw httpErr(409, `Este jefe tiene ${nFam} familiar(es). Elimínalos primero.`);
    // Incluye movimientos CANCELADOS a propósito: un recibo cancelado sigue amarrado a su casa.
    const finanzas = (await firestoreList(env, 'finanzas')).map(d => readDoc(d.fields));
    if (finanzas.some(m => m.casa && normDomicilio(m.casa) === p.domicilioNorm)) {
      throw httpErr(409, 'Esta casa tiene pagos registrados: solo puedes suspenderla, no borrarla.');
    }
  }

  // 1) Borra la cuenta de Firebase Auth PRIMERO. Si falla (y no es USER_NOT_FOUND), aborta
  //    ANTES de tocar Firestore: nada se respalda ni se borra, la persona queda intacta en el
  //    padrón y no se registra en bitácora — así no quedan estados a medias (persona sin cuenta
  //    o cuenta sin persona). El token pide scope identitytoolkit (ver arriba) para poder borrar.
  if (p.uid) {
    const rDel = await fetch(`https://identitytoolkit.googleapis.com/v1/projects/${env.FIREBASE_PROJECT}/accounts:delete`, {
      method:'POST', headers:{ Authorization:'Bearer '+at, 'Content-Type':'application/json' },
      body: JSON.stringify({ localId: p.uid }),
    });
    if (!rDel.ok) {
      const err = await rDel.json().catch(() => ({}));
      if (!String(err.error?.message || '').includes('USER_NOT_FOUND')) throw httpErr(500, 'No se pudo borrar la cuenta de Auth');
    }
  }

  // 2) Con Auth ya resuelto, respalda el doc y borra en Firestore.
  const rGet = await fetch(`${fsBase(env)}/personas/${id}`, { headers:{ Authorization:'Bearer '+at } });
  const doc = rGet.ok ? await rGet.json() : null;
  await firestoreSet(env, `personas_borradas/${id}`, {
    ...(doc?.fields || {}),
    borradoPor:{stringValue:user.uid}, borradoNombre:{stringValue:perfil.nombre||''}, borradoTs:{timestampValue:new Date().toISOString()},
  }, at);

  if (p.uid) {
    await fetch(`${fsBase(env)}/usuarios/${p.uid}`, { method:'DELETE', headers:{ Authorization:'Bearer '+at } }).catch(() => {});
  }
  for (const iv of (await firestoreList(env, 'registro_invitaciones')).filter(d => { const x = readDoc(d.fields); return x.personaId === id && !x.usado; })) {
    await fetch(`${fsBase(env)}/registro_invitaciones/${iv.name.split('/').pop()}`, { method:'DELETE', headers:{ Authorization:'Bearer '+at } }).catch(() => {});
  }
  await fetch(`${fsBase(env)}/personas/${id}`, { method:'DELETE', headers:{ Authorization:'Bearer '+at } });
  await logBitacora(env, at, { uid:user.uid, nombre: `${perfil.nombre || 'Master'} borró a ${p.nombre}${p.domicilio ? ' ('+p.domicilio+')' : ''}` });
  return json({ ok:true, id });
}

/* /personas/admin — SOLO MASTER. Prende/apaga esAdmin sobre un JEFE de familia. El check es
   perfil.rol === 'master' (NO esStaff): un admin —puro o jefe-admin— no puede otorgárselo a
   sí mismo ni a nadie más. Funciona aunque el jefe aún no tenga cuenta: syncUsuarioIndex
   proyecta el permiso cuando se registre. */
async function adminPersona(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!perfil || perfil.rol !== 'master') throw httpErr(403, 'Solo master otorga permisos de administrador');

  const { id, esAdmin } = await req.json();
  if (!id || !/^[A-Za-z0-9-]{10,64}$/.test(id)) throw httpErr(400, 'id inválido');
  if (typeof esAdmin !== 'boolean') throw httpErr(400, 'esAdmin debe ser true o false');

  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const all = await personasList(env, at);
  const p = all.find(x => x.id === id);
  if (!p) throw httpErr(404, 'Persona no existe');
  // Solo un jefe: bloquea familiares (heredan domicilio), admins puros (ya son staff) y master.
  if (!esJefe(p)) throw httpErr(400, 'Solo un jefe de familia puede ser administrador');

  await firestoreActualizarCampos(env, `personas/${id}`, { esAdmin:{booleanValue:esAdmin} }, 'Persona');
  await resyncFamilia(env, at, id, false);
  await logBitacora(env, at, {
    uid: user.uid,
    nombre: `${perfil.nombre || 'Master'} ${esAdmin ? 'nombró administrador a' : 'quitó el permiso de administrador a'} ${p.nombre}${p.domicilio ? ' ('+p.domicilio+')' : ''}`,
  });
  return json({ ok:true, id, esAdmin });
}

/* /personas/listar — SOLO staff. Devuelve todo el padrón con domicilio resuelto (familiar
   hereda el del jefe) + el conteo de CASAS ACTIVAS (jefes activos) para el termómetro. */
async function listarPersonas(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!esStaff(perfil)) throw httpErr(403, 'Solo staff consulta el padrón');

  const all = await personasList(env);
  const byId = {}; all.forEach(p => byId[p.id] = p);
  const personas = all.map(p => ({
    id: p.id, nombre: p.nombre || '', telefono: p.telefono || '', correo: p.correo ?? null,
    rol: p.rol || 'residente', estado: p.estado || 'activo', uid: p.uid ?? null,
    jefeId: p.jefeId ?? null, suspendidoPor: p.suspendidoPor ?? null,
    motivoManual: p.motivoManual ?? null,   // texto libre del staff al suspender a mano
    domicilio: domicilioDe(p, byId), domicilioNorm: p.domicilioNorm || '',
    registrado: !!p.uid,
    esAdmin: p.esAdmin === true,   // FASE 7: para la etiqueta y el botón de master en Gestión
    dadoDeAltaNombre: p.dadoDeAltaNombre || '',   // v13: quién dio de alta al familiar
    duplicadoEstado: p.duplicadoEstado ?? null,   // 'activa' = alta con teléfono/nombre repetido, pendiente de revisar
    duplicadoCon: p.duplicadoCon ?? null,
    bajaMotivo: p.bajaMotivo ?? null, bajaEn: p.bajaEn ?? null, bajaNombre: p.bajaNombre ?? null,
  }));
  const casasActivas = all.filter(p => esJefe(p) && (p.estado || 'activo') === 'activo').length;
  return json({ personas, casasActivas });
}

/* ---- Altas PENDIENTES de activar (persona dada de alta que aún no crea su cuenta) ----
   /personas/pendientes — SOLO staff. Personas sin uid y sin jefeId (los familiares los invita y
   cancela su jefe). Para cada una: quién la dio de alta, cuándo y el estado de su liga de
   registro (viva con vencimiento / vencida / sin liga). Todo se resuelve en el servidor. */
async function pendientesPersonas(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!esStaff(perfil)) throw httpErr(403, 'Solo staff consulta altas pendientes');

  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const all = await personasList(env, at);
  const byId = {}; all.forEach(p => byId[p.id] = p);
  const nombrePorUid = {}; all.forEach(p => { if (p.uid) nombrePorUid[p.uid] = p.nombre || ''; });
  const invs = (await firestoreList(env, 'registro_invitaciones')).map(d => readDoc(d.fields)).filter(Boolean);
  const ahora = Date.now();

  const pendientes = all.filter(p => !p.uid && !p.jefeId && p.rol !== 'master' && !esBaja(p)).map(p => {
    const todas = invs.filter(i => i.personaId === p.id);
    const estadoInv = i => i.usado ? 'usada' : i.reemplazada ? 'reemplazada' : (i.expiraEn && new Date(i.expiraEn).getTime() > ahora) ? 'vigente' : 'vencida';
    const historial = todas.map(i => ({ estado: estadoInv(i), creadoEn: i.creadoEn || null, expiraEn: i.expiraEn || null }))
      .sort((a, b) => String(b.creadoEn || '').localeCompare(String(a.creadoEn || ''))).slice(0, 5);
    const mias = todas.filter(i => !i.usado && !i.reemplazada);
    const viva = mias.filter(i => i.expiraEn && new Date(i.expiraEn).getTime() > ahora)
      .sort((a, b) => String(b.expiraEn).localeCompare(String(a.expiraEn)))[0];
    const liga = viva ? { estado: 'viva', expiraEn: viva.expiraEn }
      : mias.length ? { estado: 'vencida', expiraEn: mias.map(i => i.expiraEn).sort().pop() || null }
      : { estado: 'sin-liga', expiraEn: null };
    return {
      id: p.id, nombre: p.nombre || '', rol: p.rol || 'residente', estado: p.estado || 'activo',
      domicilio: domicilioDe(p, byId),
      creadoPorNombre: p.dadoDeAltaNombre || nombrePorUid[p.creadoPor] || '',
      creadoEn: p.creadoEn || null,
      liga, historial,
      duplicadoEstado: p.duplicadoEstado ?? null,
    };
  }).sort((a, b) => String(b.creadoEn || '').localeCompare(String(a.creadoEn || '')));
  return json({ pendientes });
}

/* /personas/alta-cancelar — CUALQUIER staff. Cancela un alta que nunca se activó: la persona NO
   tiene cuenta (uid null), ni familiares, ni pagos de su casa. Borra la persona y sus ligas sin
   usar, deja respaldo en personas_borradas y registro en la bitácora (quién, cuándo, a quién).
   Un admin (rol) solo lo cancela el master, igual que su alta. /personas/borrar sigue siendo
   exclusivo de master y es el único camino para personas con cuenta. */
async function cancelarAlta(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!esStaff(perfil)) throw httpErr(403, 'Solo staff cancela altas');

  const { id } = await req.json();
  if (!id || !/^[A-Za-z0-9-]{10,64}$/.test(id)) throw httpErr(400, 'id inválido');
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const all = await personasList(env, at);
  const p = all.find(x => x.id === id);
  if (!p) throw httpErr(404, 'Persona no existe');
  if (p.rol === 'master') throw httpErr(403, 'No se puede cancelar un master');
  if (esBaja(p)) throw httpErr(409, 'Esta persona está dada de baja: se conserva para auditoría');
  if (p.uid) throw httpErr(409, 'Esta persona ya tiene cuenta: no es un alta pendiente');
  if (esStaffPersona(p) && perfil.rol !== 'master') throw httpErr(403, 'Solo master cancela el alta de un administrador');
  const nFam = all.filter(x => x.jefeId === id).length;
  if (nFam) throw httpErr(409, `Tiene ${nFam} familiar(es) asociados: no se puede cancelar el alta`);
  if (esJefe(p)) {
    // Incluye movimientos CANCELADOS a propósito: un recibo cancelado sigue amarrado a su casa.
    const finanzas = (await firestoreList(env, 'finanzas')).map(d => readDoc(d.fields));
    if (finanzas.some(m => m.casa && normDomicilio(m.casa) === p.domicilioNorm)) {
      throw httpErr(409, 'Esta casa tiene pagos registrados: no se puede cancelar el alta.');
    }
  }

  const rGet = await fetch(`${fsBase(env)}/personas/${id}`, { headers:{ Authorization:'Bearer '+at } });
  const doc = rGet.ok ? await rGet.json() : null;
  await firestoreSet(env, `personas_borradas/${id}`, {
    ...(doc?.fields || {}),
    borradoPor:{stringValue:user.uid}, borradoNombre:{stringValue:perfil.nombre||''}, borradoTs:{timestampValue:new Date().toISOString()},
    motivoBorrado:{stringValue:'alta-cancelada'},
  }, at);
  for (const iv of (await firestoreList(env, 'registro_invitaciones')).filter(d => { const x = readDoc(d.fields); return x.personaId === id && !x.usado; })) {
    await fetch(`${fsBase(env)}/registro_invitaciones/${iv.name.split('/').pop()}`, { method:'DELETE', headers:{ Authorization:'Bearer '+at } }).catch(() => {});
  }
  const rDel = await fetch(`${fsBase(env)}/personas/${id}`, { method:'DELETE', headers:{ Authorization:'Bearer '+at } });
  if (!rDel.ok) throw httpErr(500, 'No se pudo cancelar el alta');
  await logBitacora(env, at, { uid:user.uid, nombre: `${perfil.nombre || 'Staff'} canceló el alta de ${p.nombre}${p.domicilio ? ' ('+p.domicilio+')' : ''}` });
  return json({ ok:true, id });
}

/* /personas/duplicado-revisar — SOLO staff. "Revisado, es correcto" sobre un alta marcada por
   teléfono/nombre repetido (mismo criterio que las alertas de familiares): quita lo rojo, deja
   quién y cuándo en el registro y en la bitácora. No borra ni bloquea nada. */
async function revisarDuplicadoPersona(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!esStaff(perfil)) throw httpErr(403, 'Solo staff revisa altas duplicadas');
  const { id } = await req.json();
  if (!id || !/^[A-Za-z0-9-]{10,64}$/.test(id)) throw httpErr(400, 'id inválido');
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const doc = await getDoc(env, at, `personas/${id}`);
  const p = doc && readDoc(doc.fields);
  if (!p) throw httpErr(404, 'Persona no existe');
  if (p.duplicadoEstado !== 'activa') throw httpErr(409, 'Esa alta no está marcada');
  await firestoreActualizarCampos(env, `personas/${id}`, {
    duplicadoEstado:{stringValue:'revisada'},
    duplicadoRevisadoPor:{stringValue:user.uid},
    duplicadoRevisadoNombre:{stringValue:perfil.nombre || ''},
    duplicadoRevisadoEn:{timestampValue:new Date().toISOString()},
  }, 'Persona');
  await logBitacora(env, at, { uid:user.uid, nombre: `${perfil.nombre || 'Staff'} revisó el alta duplicada de ${p.nombre}: es correcto` });
  return json({ ok:true, id });
}

/* /personas/baja — SOLO MASTER (como /personas/borrar). "Dar de baja" a una persona real que sale
   (venta de casa, mudanza) sin perder su historia. Si es jefe, la baja alcanza a TODA su familia.
   Para cada persona dada de baja:
     1) Auth: se DESHABILITA la cuenta (no puede volver a entrar). Si falla, se aborta ANTES de tocar
        Firestore, como /personas/borrar.
     2) Puertas: se elimina su índice usuarios/{uid}; /abrir responde "Sin perfil" para TODAS las puertas
        (incluye peatones y salida) sin tocar /abrir. Sus QR de visita activos se desactivan.
     3) Sus ligas de registro sin usar se borran.
     4) personas/{id} queda estado:'baja' con motivo, quién y cuándo. NO se borra: pagos, recibos,
        finanzas y bitácora siguen intactos y con su nombre para auditoría.
   Una baja no cuenta como casa (esJefe) ni aparece en listas activas; su domicilio queda libre.
   No aplica a master, a uno mismo ni a quien ya está de baja. */
async function darDeBajaPersona(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!perfil || perfil.rol !== 'master') throw httpErr(403, 'Solo master da de baja');

  const { id, motivo } = await req.json();
  if (!id || !/^[A-Za-z0-9-]{10,64}$/.test(id)) throw httpErr(400, 'id inválido');
  const mot = String(motivo || '').trim().replace(/\s+/g, ' ').slice(0, 300);
  if (mot.length < 3) throw httpErr(400, 'El motivo de la baja es obligatorio');

  const at = await saToken(env, 'https://www.googleapis.com/auth/identitytoolkit https://www.googleapis.com/auth/datastore');
  const all = await personasList(env, at);
  const p = all.find(x => x.id === id);
  if (!p) throw httpErr(404, 'Persona no existe');
  if (p.rol === 'master') throw httpErr(403, 'No se puede dar de baja a un master');
  if (p.uid && p.uid === user.uid) throw httpErr(403, 'No puedes darte de baja a ti mismo');
  if (esBaja(p)) throw httpErr(409, 'Esta persona ya está dada de baja');

  // Objetivos: la persona y, si es jefe, toda su familia que siga viva.
  const objetivos = [p, ...(p.rol === 'residente' && !p.jefeId ? all.filter(x => x.jefeId === p.id && !esBaja(x)) : [])];
  if (objetivos.some(t => t.uid && t.uid === user.uid)) throw httpErr(403, 'No puedes darte de baja a ti mismo');

  // 1) Auth primero (todas): si algo falla, Firestore no se ha tocado.
  for (const t of objetivos) {
    if (!t.uid) continue;
    const r = await fetch(`https://identitytoolkit.googleapis.com/v1/projects/${env.FIREBASE_PROJECT}/accounts:update`, {
      method:'POST', headers:{ Authorization:'Bearer '+at, 'Content-Type':'application/json' },
      body: JSON.stringify({ localId: t.uid, disableUser: true }),
    });
    if (!r.ok) {
      const err = await r.json().catch(() => ({}));
      if (!String(err.error?.message || '').includes('USER_NOT_FOUND')) throw httpErr(500, 'No se pudo deshabilitar la cuenta de acceso');
    }
  }

  // 2-4) Firestore
  const ahora = new Date().toISOString();
  const invisitas = (await firestoreList(env, 'invitaciones')).map(d => ({ id: d.name.split('/').pop(), ...readDoc(d.fields) }));
  const ligas = (await firestoreList(env, 'registro_invitaciones')).map(d => ({ id: d.name.split('/').pop(), ...readDoc(d.fields) }));
  for (const t of objetivos) {
    if (t.uid) {
      await fetch(`${fsBase(env)}/usuarios/${t.uid}`, { method:'DELETE', headers:{ Authorization:'Bearer '+at } }).catch(() => {});
      for (const v of invisitas.filter(v => v.activa && (v.creadaPor === t.uid || v.hogar === t.uid))) {
        await firestoreUpdate(env, `invitaciones/${v.id}`, { activa:{ booleanValue:false } }, ['activa']);
      }
    }
    for (const l of ligas.filter(l => l.personaId === t.id && !l.usado)) {
      await fetch(`${fsBase(env)}/registro_invitaciones/${l.id}`, { method:'DELETE', headers:{ Authorization:'Bearer '+at } }).catch(() => {});
    }
    await firestoreActualizarCampos(env, `personas/${t.id}`, {
      estado:{ stringValue:'baja' },
      bajaMotivo:{ stringValue: mot },
      bajaPor:{ stringValue: user.uid },
      bajaNombre:{ stringValue: perfil.nombre || '' },
      bajaEn:{ timestampValue: ahora },
      bajaEstadoPrevio:{ stringValue: t.estado || 'activo' },
      bajaDeJefeId:{ stringValue: t.id === p.id ? '' : p.id },
    }, 'Persona');
  }
  const fam = objetivos.length - 1;
  await logBitacora(env, at, { uid:user.uid, nombre: `${perfil.nombre || 'Master'} dio de baja a ${p.nombre}${domicilioDe(p, Object.fromEntries(all.map(x => [x.id, x]))) ? ' (' + domicilioDe(p, Object.fromEntries(all.map(x => [x.id, x]))) + ')' : ''}${fam ? ' y a ' + fam + ' familiar(es)' : ''}: ${mot}`.slice(0, 500) });
  return json({ ok:true, id, bajas: objetivos.map(t => t.id) });
}

/* ===========================================================
   DISPOSITIVOS — cambiar/revertir el Shelly de una puerta desde la app (SOLO master).
   config/dispositivos (Firestore; las reglas niegan TODO acceso al cliente, solo este Worker lo lee/escribe)
   manda sobre el secret SHELLY_DEVICES, que SIGUE siendo el respaldo: si el documento no existe, falla,
   tarda o viene corrupto, /abrir usa el secret como siempre. SHELLY_HOST y SHELLY_AUTH_KEY no se mueven.
   =========================================================== */
const DISP_TTL_MS = 30000;        // un cambio guardado se ve en TODAS las instancias en <= 30 s (en la que lo guarda, al instante)
const DISP_FALLO_TTL_MS = 15000;  // si la lectura falla, no se reintenta en cada apertura: se usa el secret 15 s
const DISP_LECTURA_MAX_MS = 1500; // tope DURO que una apertura espera al documento antes de caer al secret
let DISP_CACHE = { mapa: null, exp: 0 };
let DISP_VUELO = null;
function invalidarCacheDispositivos() { DISP_CACHE = { mapa: null, exp: 0 }; DISP_VUELO = null; }

/* Mapa JSON (formato SHELLY_DEVICES) del documento, o null (=> el secret). NUNCA lanza ni demora más de
   DISP_LECTURA_MAX_MS: la puerta jamás espera ni falla por este módulo. Con caché vigente no hace ninguna lectura. */
async function mapaDispositivos(env) {
  const ahora = Date.now();
  if (ahora < DISP_CACHE.exp) return DISP_CACHE.mapa;
  try {
    if (!DISP_VUELO) {
      DISP_VUELO = (async () => {
        const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
        const doc = await getDoc(env, at, 'config/dispositivos');
        return doc ? mapaParaTrigger(parsearDispositivos(readDoc(doc.fields))) : null;
      })();
      DISP_VUELO.catch(() => {});
    }
    const vuelo = DISP_VUELO;
    const mapa = await Promise.race([vuelo, new Promise((_, rej) => setTimeout(() => rej(new Error('tope')), DISP_LECTURA_MAX_MS))]);
    if (DISP_VUELO === vuelo) { DISP_CACHE = { mapa, exp: Date.now() + DISP_TTL_MS }; DISP_VUELO = null; }
    return mapa;
  } catch (e) {
    DISP_VUELO = null;
    DISP_CACHE = { mapa: null, exp: Date.now() + DISP_FALLO_TTL_MS };
    return null;
  }
}

async function soloMaster(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!perfil || perfil.rol !== 'master') throw httpErr(403, 'Solo master administra los dispositivos');
  return { user, perfil };
}
/* Contraseña de nuevo: el cliente reautentica con Firebase y manda un token fresco; aquí se exige que el
   inicio de sesión (auth_time) sea de hace <= 5 min. Se lee del token YA verificado por requireAuth. */
function reautenticacionFresca(req) {
  try {
    const t = (req.headers.get('Authorization') || '').slice(7);
    const at = JSON.parse(b64urlToStr(t.split('.')[1])).auth_time;
    const ahora = Date.now() / 1000;
    return typeof at === 'number' && ahora - at <= 300 && at <= ahora + 60;
  } catch (e) { return false; }
}
const pideContrasena = () => json({ error: 'Confirma tu contraseña para continuar', requiereContrasena: true }, 403);

async function leerDocDispositivos(env, at) {
  const doc = await getDoc(env, at, 'config/dispositivos');
  if (!doc) return { existe: false, updateTime: null, campos: {}, parsed: parsearDispositivos(null) };
  const campos = readDoc(doc.fields) || {};
  return { existe: true, updateTime: doc.updateTime, campos, parsed: parsearDispositivos(campos) };
}
async function guardarDispositivos(env, at, previo, fields) {
  const mask = Object.keys(fields).map(f => 'updateMask.fieldPaths=' + encodeURIComponent(f)).join('&');
  const pre = previo.existe ? 'currentDocument.updateTime=' + encodeURIComponent(previo.updateTime) : 'currentDocument.exists=false';
  const r = await fetch(`${fsBase(env)}/config/dispositivos?${mask}&${pre}`, {
    method: 'PATCH', headers: { Authorization: 'Bearer ' + at, 'Content-Type': 'application/json' }, body: JSON.stringify({ fields }),
  });
  if (r.status === 409 || r.status === 412) throw httpErr(409, 'Otro cambio se guardó al mismo tiempo: vuelve a intentar');
  if (!r.ok) throw httpErr(500, 'No se pudo guardar el cambio');
  invalidarCacheDispositivos();
}
const ult6 = id => '…' + String(id || '').slice(-6);
const idUsadoPorOtra = (parsed, secret, puerta, id) => PUERTAS_DISP.some(p => p !== puerta && (dispositivoEfectivo(parsed, secret, p)?.id || '').toLowerCase() === id.toLowerCase());
function errorShelly(q) {
  if (q.error === 'no-existe') return httpErr(404, 'Ese Shelly no existe en tu cuenta de Shelly Cloud');
  if (q.error === 'formato') return httpErr(400, 'ID inválido: son de 6 a 16 caracteres hexadecimales (0-9, a-f)');
  if (q.error) return httpErr(503, 'No se pudo consultar Shelly Cloud, intenta en un minuto');
  return null;
}

/* /dispositivos/listar — SOLO master. Sin llamar a Shelly (no gasta el límite de la cuenta). */
async function listarDispositivos(req, env) {
  await soloMaster(req, env);
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const d = await leerDocDispositivos(env, at);
  const puertas = PUERTAS_DISP.map(p => {
    const e = dispositivoEfectivo(d.parsed, env.SHELLY_DEVICES, p);
    const hist = d.parsed.historial.filter(h => h.puerta === p);
    const ult = hist[hist.length - 1];
    return { puerta: p, id: e?.id || null, gen: e?.gen || null, origen: e ? e.origen : 'sin-asignar',
      cambios: hist.length, ultimoCambio: ult ? { en: ult.en, nombre: ult.nombre, tipo: ult.tipo } : null, puedeRegresar: hist.length > 0 };
  });
  return json({ puertas });
}

/* /dispositivos/estado — SOLO master. UNA puerta por llamada, a petición (cada consulta gasta del límite de Shelly Cloud). */
const DISP_ESTADO_CACHE = new Map();
async function estadoDispositivo(req, env) {
  await soloMaster(req, env);
  const { puerta } = await req.json();
  if (!PUERTAS_DISP.includes(puerta)) throw httpErr(400, 'Puerta no válida');
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const e = dispositivoEfectivo((await leerDocDispositivos(env, at)).parsed, env.SHELLY_DEVICES, puerta);
  if (!e) return json({ ok: true, puerta, asignado: false });
  const previo = DISP_ESTADO_CACHE.get(puerta);
  if (previo && Date.now() - previo.at < 10000 && previo.id === e.id) return json({ ...previo.r, cache: true });
  const q = await consultarShelly(env, e.id);
  const r = { ok: true, puerta, asignado: true, existe: q.existe, online: q.online, gen: q.gen || e.gen, error: q.error };
  DISP_ESTADO_CACHE.set(puerta, { at: Date.now(), id: e.id, r });
  return json(r);
}

/* /dispositivos/disponibles — SOLO master. MANUAL (una consulta por toque, máx. 1 cada 8 s: gasta del límite de 1 req/s de la
   cuenta de Shelly). Pide a Shelly Cloud la lista de dispositivos de la cuenta y devuelve SOLO los EN LÍNEA que NO están
   asignados a ninguna puerta (nombre puesto en la app de Shelly, generación e ID). El frontend nunca recibe la llave de Shelly.
   diagnostico:true añade la FORMA de la respuesta (campos y tipos, sin valores) para validar el parser contra la nube real. */
let ULTIMA_LISTA = 0;
async function disponiblesDispositivos(req, env) {
  await soloMaster(req, env);
  const { diagnostico } = await req.json().catch(() => ({}));
  if (Date.now() - ULTIMA_LISTA < 8000) throw httpErr(429, 'Espera unos segundos antes de buscar de nuevo');
  ULTIMA_LISTA = Date.now();
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const d = await leerDocDispositivos(env, at);
  const asignados = new Set(PUERTAS_DISP.map(p => (dispositivoEfectivo(d.parsed, env.SHELLY_DEVICES, p)?.id || '').toLowerCase()).filter(Boolean));
  const q = await listarDispositivosCuenta(env);
  if (!q.ok) {
    const msg = q.error === 'limite' ? 'Shelly Cloud pide esperar un momento (límite de consultas). Intenta en un minuto.' : 'No se pudo consultar Shelly Cloud, intenta en un minuto.';
    return json({ error: msg, codigo: q.error, ...(diagnostico === true && q.forma ? { forma: q.forma } : {}) }, 503);
  }
  const libres = q.dispositivos.filter(x => idShellyValido(x.id) && !asignados.has(x.id.toLowerCase()));
  // Un repuesto cuyo "en línea" solo viene de una PISTA (all_status devuelve el último estado conocido) se confirma con la consulta
  // por dispositivo antes de ofrecerlo. Máx. 4 confirmaciones por toque (cada una gasta del límite de 1 req/s).
  for (const x of libres.filter(x => !criterioAutoritativo(x.criterioOnline)).slice(0, 4)) {
    const c = await consultarShelly(env, x.id);
    if (c.existe) { x.online = c.online; x.criterioOnline = 'v1.status'; if (!x.gen && c.gen) { x.gen = c.gen; x.criterioGen = 'v1.status'; } }
    else { x.online = false; x.criterioOnline = 'sin-confirmar:' + (c.error || '?'); }
  }
  const disponibles = libres.filter(x => x.online).map(x => ({ id: x.id, nombre: x.nombre, gen: x.gen, genEtiqueta: x.genEtiqueta || x.gen, modelo: x.modelo }));
  const extra = diagnostico !== true ? {} : {
    forma: q.forma, formaV2: q.formaV2, errorV2: q.errorV2,
    // TODA la cuenta (solo últimos 6 del ID): a qué puerta está asignado cada uno y con qué criterio se decidió generación y línea
    cuenta: q.dispositivos.map(x => ({ id6: x.id.slice(-6), nombre: x.nombre, gen: x.gen, genEtiqueta: x.genEtiqueta || x.gen, modelo: x.modelo, online: x.online,
      criterioGen: x.criterioGen, criterioOnline: x.criterioOnline, criterioNombre: x.criterioNombre || null,
      asignadoA: PUERTAS_DISP.find(p => (dispositivoEfectivo(d.parsed, env.SHELLY_DEVICES, p)?.id || '').toLowerCase() === x.id.toLowerCase()) || null })),
  };
  return json({ ok: true, disponibles, fueraDeLinea: libres.length - disponibles.length, totalCuenta: q.dispositivos.length, ...extra });
}

/* /dispositivos/verificar — SOLO master. Valida un ID candidato SIN guardar: formato, existencia, línea y generación. */
async function verificarDispositivo(req, env) {
  await soloMaster(req, env);
  const { id, puerta } = await req.json();
  const nuevo = String(id || '').trim();
  if (!idShellyValido(nuevo)) throw httpErr(400, 'ID inválido: son de 6 a 16 caracteres hexadecimales (0-9, a-f)');
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const d = await leerDocDispositivos(env, at);
  if (PUERTAS_DISP.includes(puerta) && idUsadoPorOtra(d.parsed, env.SHELLY_DEVICES, puerta, nuevo)) throw httpErr(409, 'Ese Shelly ya está asignado a otra puerta');
  const q = await consultarShelly(env, nuevo);
  const err = errorShelly(q); if (err) throw err;
  return json({ ok: true, existe: true, online: q.online, gen: q.gen, generacionDetectada: q.gen !== null });
}

/* Cambia/regresa una puerta: arma el registro, guarda con precondición (updateTime) y deja bitácora. */
async function aplicarCambioDispositivo(env, at, { user, perfil, d, puerta, nuevoId, nuevoGen, tipo }) {
  const actual = dispositivoEfectivo(d.parsed, env.SHELLY_DEVICES, puerta);
  const secreto = (() => { try { const e = JSON.parse(env.SHELLY_DEVICES || 'null')?.[puerta]; return typeof e === 'string' ? e : e?.id || null; } catch (x) { return null; } })();
  const ahora = new Date().toISOString();
  const hist = d.parsed.historial.concat([{ puerta, idAnterior: actual?.id || null, genAnterior: actual?.gen || null, idNuevo: nuevoId, genNuevo: nuevoGen, en: ahora, por: user.uid, nombre: perfil.nombre || '', tipo }]).slice(-HISTORIAL_MAX);
  const vuelveAlSecreto = !!secreto && secreto.toLowerCase() === nuevoId.toLowerCase();
  const fields = {
    [`${puerta}_id`]: vuelveAlSecreto ? { nullValue: null } : { stringValue: nuevoId },
    [`${puerta}_gen`]: vuelveAlSecreto ? { nullValue: null } : { integerValue: String(nuevoGen) },
    [`${puerta}_offSec`]: { nullValue: null },
    historial: { stringValue: JSON.stringify(hist) },
    version: { integerValue: String((d.parsed.version || 0) + 1) },
    actualizadoEn: { timestampValue: ahora },
    actualizadoPor: { stringValue: user.uid },
  };
  await guardarDispositivos(env, at, d, fields);
  await logBitacora(env, at, { uid: user.uid, nombre: `${perfil.nombre || 'Master'} ${tipo === 'regreso' ? 'regresó' : 'cambió'} el Shelly de ${puerta}: ${actual ? ult6(actual.id) + ' (Gen' + actual.gen + ')' : 'sin asignar'} → ${ult6(nuevoId)} (Gen${nuevoGen})` });
}

/* /dispositivos/cambiar — SOLO master + contraseña reciente. El Shelly nuevo debe existir y estar EN LÍNEA antes de guardar. */
async function cambiarDispositivo(req, env) {
  const { user, perfil } = await soloMaster(req, env);
  if (!reautenticacionFresca(req)) return pideContrasena();
  const { puerta, id, genManual } = await req.json();
  if (!PUERTAS_DISP.includes(puerta)) throw httpErr(400, 'Puerta no válida');
  const nuevo = String(id || '').trim();
  if (!idShellyValido(nuevo)) throw httpErr(400, 'ID inválido: son de 6 a 16 caracteres hexadecimales (0-9, a-f)');
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const d = await leerDocDispositivos(env, at);
  const actual = dispositivoEfectivo(d.parsed, env.SHELLY_DEVICES, puerta);
  if (actual && actual.id.toLowerCase() === nuevo.toLowerCase()) throw httpErr(409, 'Ese ya es el Shelly de esta puerta');
  if (idUsadoPorOtra(d.parsed, env.SHELLY_DEVICES, puerta, nuevo)) throw httpErr(409, 'Ese Shelly ya está asignado a otra puerta');
  const q = await consultarShelly(env, nuevo);
  const err = errorShelly(q); if (err) throw err;
  if (!q.online) throw httpErr(409, 'El Shelly existe pero está fuera de línea: enciéndelo y conéctalo antes de asignarlo');
  const gen = q.gen ?? ([1, 2, 3].includes(genManual) ? genManual : null);
  if (!gen) throw httpErr(409, 'No se pudo detectar la generación: indícala manualmente (Gen1, Gen2 o Gen3)');
  await aplicarCambioDispositivo(env, at, { user, perfil, d, puerta, nuevoId: nuevo, nuevoGen: gen, tipo: 'cambio' });
  return json({ ok: true, puerta, gen });
}

/* /dispositivos/revertir — SOLO master + contraseña reciente. Un toque: vuelve al Shelly anterior de esa puerta
   (si el anterior era el del secret, la puerta regresa al secret). Exige que el anterior esté en línea, salvo forzar:true. */
async function revertirDispositivo(req, env) {
  const { user, perfil } = await soloMaster(req, env);
  if (!reautenticacionFresca(req)) return pideContrasena();
  const { puerta, forzar } = await req.json();
  if (!PUERTAS_DISP.includes(puerta)) throw httpErr(400, 'Puerta no válida');
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const d = await leerDocDispositivos(env, at);
  const ult = d.parsed.historial.filter(h => h.puerta === puerta).pop();
  if (!ult || !ult.idAnterior || !idShellyValido(ult.idAnterior)) throw httpErr(409, 'No hay un Shelly anterior para esta puerta');
  const objetivoGen = [1, 2, 3].includes(ult.genAnterior) ? ult.genAnterior : 1;
  if (forzar !== true) {
    const q = await consultarShelly(env, ult.idAnterior);
    const err = errorShelly(q); if (err) throw err;
    if (!q.online) return json({ error: 'El Shelly anterior está fuera de línea. Si aun así quieres regresar, confirma.', anteriorFueraDeLinea: true }, 409);
  }
  await aplicarCambioDispositivo(env, at, { user, perfil, d, puerta, nuevoId: ult.idAnterior, nuevoGen: objetivoGen, tipo: 'regreso' });
  return json({ ok: true, puerta });
}

/* /dispositivos/probar — SOLO master + contraseña reciente + confirmar:true. ABRE LA PUERTA FÍSICA por la ruta normal
   (portero y todo), para comprobar el Shelly recién asignado. Máximo una prueba cada 10 s. */
let ULTIMA_PRUEBA = 0;
async function probarDispositivo(req, env) {
  const { user, perfil } = await soloMaster(req, env);
  if (!reautenticacionFresca(req)) return pideContrasena();
  const { puerta, confirmar } = await req.json();
  if (!PUERTAS_DISP.includes(puerta)) throw httpErr(400, 'Puerta no válida');
  if (confirmar !== true) throw httpErr(400, 'Falta la confirmación explícita: el pulso ABRE la puerta');
  if (Date.now() - ULTIMA_PRUEBA < 10000) throw httpErr(429, 'Espera unos segundos entre pulsos de prueba');
  ULTIMA_PRUEBA = Date.now();
  await triggerShelly(env, puerta, await mapaDispositivos(env));
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  await logBitacora(env, at, { uid: user.uid, nombre: `${perfil.nombre || 'Master'} hizo un pulso de prueba en ${puerta}` });
  return json({ ok: true, puerta });
}

/* /personas/mis-familiares — el JEFE lista SOLO a su propia familia (self-service:
   badge N/5, invitar, cancelar). Nunca expone otras casas ni al resto del padrón.
   Devuelve id/nombre/estado/registrado de cada familiar + el tope de 5. */
async function misFamiliares(req, env) {
  const user = await requireAuth(req, env);
  const all = await personasList(env);
  const jefe = all.find(p => p.uid === user.uid);
  if (!jefe || !esJefe(jefe)) throw httpErr(403, 'Solo un jefe de familia tiene familiares');
  const familiares = all.filter(p => p.jefeId === jefe.id && !esBaja(p))
    .map(f => ({
      id: f.id, nombre: f.nombre || '', telefono: f.telefono || '',
      estado: f.estado || 'activo', registrado: !!f.uid, suspendidoPor: f.suspendidoPor ?? null,
    }))
    .sort((a, b) => a.nombre.localeCompare(b.nombre, 'es'));
  return json({
    familiares, max: 5,
    domicilio: jefe.domicilio || '',
    puedeInvitar: (jefe.estado || 'activo') === 'activo',
  });
}

/* Hermosillo/Sonora usa UTC-7 fijo todo el año (no aplica horario de verano), pero
   Cloudflare Workers corre siempre en UTC — por eso new Date().getFullYear()/getMonth()/
   getDate() daba el calendario en UTC, no en Hermosillo, al calcular "hoy" para cortes de
   mes o meses transcurridos. Estos helpers NO cambian cómo se guardan los timestamps
   (siguen en UTC absoluto vía toISOString()); solo ajustan cómo se leen sus componentes
   de calendario (año/mes/día) para que representen la hora de pared en Hermosillo. */
const HERMOSILLO_OFFSET_MS = 7 * 60 * 60 * 1000;

function aHermosillo(instante) {
  return new Date(new Date(instante).getTime() - HERMOSILLO_OFFSET_MS);
}
function ahoraHermosillo() {
  return aHermosillo(Date.now());
}
// Instante UTC absoluto de las 00:00 hora Hermosillo de (year, month, day) — para construir
// cortes de mes que coincidan con la medianoche real en Hermosillo, no con la de UTC.
function inicioDiaHermosilloUTC(year, month, day) {
  return new Date(Date.UTC(year, month, day, 0, 0, 0, 0) + HERMOSILLO_OFFSET_MS);
}

/* ============ /finanzas/resumen — cualquier usuario autenticado ============
   Devuelve SOLO agregados del mes en curso (cobrado, gastos, balance, y el
   termómetro X de Y casas pagaron) — nunca el detalle de movimientos ni qué
   casa específica pagó. Así el dashboard de residentes no necesita leer
   "finanzas" directo (las reglas de Firestore ya se lo bloquean). */
async function resumenFinanzas(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!perfil) throw httpErr(403, 'Sin perfil');

  const now = ahoraHermosillo();
  const inicioMes = inicioDiaHermosilloUTC(now.getUTCFullYear(), now.getUTCMonth(), 1);
  const finMes = inicioDiaHermosilloUTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1);

  const docs = await firestoreList(env, 'finanzas');
  let ingreso = 0, egreso = 0;
  const pagaron = new Set();
  for (const doc of docs) {
    const d = readDoc(doc.fields);
    if (esCancelado(d)) continue;   // cancelado = no cuenta en la caja
    const ts = new Date(d.ts);
    if (!(ts >= inicioMes && ts < finMes)) continue;
    if (d.tipo === 'ingreso') ingreso += d.monto || 0;
    else if (d.tipo === 'egreso') egreso += d.monto || 0;
    if (d.tipo === 'ingreso' && d.categoria === 'Cuota' && d.casa) pagaron.add(d.casa);
  }

  // FASE 6.5 (corregido): el total es el # de JEFES de familia (una casa = un jefe),
  // ACTIVOS Y SUSPENDIDOS. Se revoca el criterio de FASE 5 de excluir suspendidos: si un
  // suspendido no cuenta en el denominador, el % de cobranza mentiría.
  const totalCasas = (await personasList(env)).filter(p => esJefe(p)).length;

  return json({
    ingreso, egreso, balance: ingreso - egreso,
    pagaron: pagaron.size,
    totalCasas,
  });
}

/* ============ /finanzas/cobranza — SOLO staff ============
   Dos listas de casas (JEFES de familia, ACTIVAS y SUSPENDIDAS) para cobrar sin adivinar:
   las que ya pagaron Cuota este mes y las que no. Cada casa lleva su domicilio, el nombre
   del jefe, si está suspendida (para etiquetarla) y su adeudo acumulado (cuota fija, ver
   calcularEstadoCuenta). TODO el conteo se hace aquí, no en el cliente. Las suspendidas SÍ
   aparecen (suelen estarlo justo por mora). */
async function cobranzaFinanzas(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!esStaff(perfil)) throw httpErr(403, 'Solo staff consulta la cobranza');

  const now = ahoraHermosillo();
  const inicioMes = inicioDiaHermosilloUTC(now.getUTCFullYear(), now.getUTCMonth(), 1);
  const finMes = inicioDiaHermosilloUTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1);

  // Un solo recorrido de "finanzas" arma a la vez: (a) qué domicilios pagaron Cuota ESTE MES
  // (termómetro/listas, igual que antes) y (b) el historial COMPLETO de pagos de Cuota por
  // domicilio (para el adeudo acumulado, PARTE 2/4 del plan maestro de cobranza).
  const pagadas = new Set();
  const pagosPorCasa = new Map(); // domicilioNorm -> [{ts, monto}, ...] (todo el tiempo)
  for (const doc of await firestoreList(env, 'finanzas')) {
    const d = readDoc(doc.fields);
    if (esCancelado(d)) continue;   // un pago cancelado no abona al adeudo
    if (d.tipo !== 'ingreso' || d.categoria !== 'Cuota' || !d.casa) continue;
    const dn = normDomicilio(d.casa);
    const ts = new Date(d.ts);
    if (ts >= inicioMes && ts < finMes) pagadas.add(dn);
    if (!pagosPorCasa.has(dn)) pagosPorCasa.set(dn, []);
    pagosPorCasa.get(dn).push({ ts: d.ts, monto: d.monto || 0 });
  }

  const cfg = await leerConfigCobranza(env);

  // TODAS las casas (jefes), activas y suspendidas.
  const casas = (await personasList(env)).filter(p => esJefe(p));
  const pagaron = [], sinPago = [];
  for (const c of casas) {
    const estado = calcularEstadoCuenta({ altaCasa: c.creadoEn, cfg, pagosCuotaPorCasa: pagosPorCasa.get(c.domicilioNorm) });
    const item = {
      domicilio: c.domicilio || '', nombre: c.nombre || '',
      suspendido: (c.estado || 'activo') === 'suspendido',
      adeudo: estado.adeudo,
    };
    (pagadas.has(c.domicilioNorm) ? pagaron : sinPago).push(item);
  }
  const cmp = (a, b) => (a.domicilio || '').localeCompare(b.domicilio || '', 'es', { numeric: true });
  pagaron.sort(cmp); sinPago.sort(cmp);

  return json({ pagaron, sinPago, totalCasas: casas.length });
}

/* ============ /finanzas/estado-cuenta — cualquier residente/familiar, SOLO su propia casa ============
   Cuota mensual fija + adeudo acumulado (PARTE 1/2 del plan de cobranza). La casa la determina
   el Worker a partir del perfil de quien llama (perfil.casa, sincronizado por syncUsuarioIndex);
   NUNCA de un parámetro del cliente, para que nadie pueda consultar el adeudo de otra casa. */
async function estadoCuentaFinanzas(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!perfil || perfil.rol !== 'residente' || !perfil.casa) throw httpErr(403, 'Solo residentes con casa consultan su estado de cuenta');

  const domNorm = normDomicilio(perfil.casa);
  const jefe = (await personasList(env)).find(p => esJefe(p) && p.domicilioNorm === domNorm);
  if (!jefe) throw httpErr(404, 'Tu casa no está en el padrón');

  const cfg = await leerConfigCobranza(env);
  const pagos = [];
  for (const doc of await firestoreList(env, 'finanzas')) {
    const d = readDoc(doc.fields);
    if (esCancelado(d)) continue;
    if (d.tipo === 'ingreso' && d.categoria === 'Cuota' && d.casa && normDomicilio(d.casa) === domNorm) {
      pagos.push({ ts: d.ts, monto: d.monto || 0 });
    }
  }

  const estado = calcularEstadoCuenta({ altaCasa: jefe.creadoEn, cfg, pagosCuotaPorCasa: pagos });

  // avisoCorte: cuenta regresiva al corte automático por mora del día 5 (Hermosillo). null si
  // ya está al corriente, ya está suspendida (avisar de algo que ya pasó no tiene caso), o
  // faltan más de 72h. Si el corte ya pasó pero el cron todavía no corrió, horasRestantes:0
  // (nunca negativo) — el aviso sigue siendo válido: puede pasar en cualquier momento.
  let avisoCorte = null;
  if (estado.adeudo > 0 && (jefe.estado || 'activo') !== 'suspendido') {
    const ahora = ahoraHermosillo();
    const corte = inicioDiaHermosilloUTC(ahora.getUTCFullYear(), ahora.getUTCMonth(), 5);
    const horasHastaCorte = (corte.getTime() - Date.now()) / 3600000;
    if (horasHastaCorte <= 72) {
      avisoCorte = { horasRestantes: Math.max(0, Math.floor(horasHastaCorte)) };
    }
  }

  return json({ ok:true, ...estado, avisoCorte });
}

/* ---- Núcleo del cálculo de adeudo acumulado (cuota mensual fija) — compartido por
   /finanzas/estado-cuenta (una casa) y /finanzas/cobranza (todas). No migra ni toca
   finanzas/{id}; solo agrega sobre lo que ya existe. ----
   fechaEfectiva = la MÁS TARDÍA entre fechaInicioCobro (config) y el alta de la casa
   (creadoEn del jefe) — así nadie paga meses de antes de que su ficha existiera.
   mesesTranscurridos = meses calendario COMPLETOS entre fechaEfectiva y hoy (si el día del
   mes de "hoy" aún no alcanza al de fechaEfectiva, ese mes en curso no cuenta como completo).
   Si fechaEfectiva cae en el futuro, meses da negativo y se recorta a 0 (nunca error, nunca
   adeudo negativo). */
function calcularEstadoCuenta({ altaCasa, cfg, pagosCuotaPorCasa, ahora = ahoraHermosillo() }) {
  const inicioCobro = new Date(cfg.fechaInicioCobro);
  const alta = altaCasa ? new Date(altaCasa) : inicioCobro;
  const fechaEfectiva = (alta instanceof Date && !isNaN(alta) && alta > inicioCobro) ? alta : inicioCobro;

  const fechaEfectivaHermosillo = aHermosillo(fechaEfectiva);
  let meses = (ahora.getUTCFullYear() - fechaEfectivaHermosillo.getUTCFullYear()) * 12
            + (ahora.getUTCMonth() - fechaEfectivaHermosillo.getUTCMonth());
  if (ahora.getUTCDate() < fechaEfectivaHermosillo.getUTCDate()) meses -= 1;
  const mesesTranscurridos = Math.max(0, meses);

  const montoEsperado = mesesTranscurridos * cfg.cuotaMensual;
  const montoPagado = (pagosCuotaPorCasa || [])
    .filter(m => new Date(m.ts) >= fechaEfectiva)
    .reduce((s, m) => s + (m.monto || 0), 0);
  const adeudo = Math.max(0, montoEsperado - montoPagado);

  return { cuotaMensual: cfg.cuotaMensual, mesesTranscurridos, montoEsperado, montoPagado, adeudo, alCorriente: adeudo === 0 };
}

/* ============ Suspensión automática por mora ============
   aplicarSuspensionAutomatica(env, modo) — función interna, sin req/HTTP. La llaman DOS
   caminos: el Cron Trigger diario (scheduled(), más abajo, siempre modo:'aplicar') y
   /admin/probar-suspension-automatica (botón de prueba/emergencia para master, modo lo
   decide quien llama). Ambos comparten exactamente esta lógica de cálculo.

   modo:'simular' (default más seguro desde HTTP, ver probarSuspensionAutomatica) — recorre
   el MISMO cálculo pero NO escribe absolutamente nada: ni suspende, ni resyncFamilia, ni
   bitácora, ni ultimoMesProcesado. Es una foto de "quién se suspendería si corriera ahora",
   consultable en cualquier momento del mes (no espera al día 5).

   modo:'aplicar' — el comportamiento real. Corre TODOS los días pero solo actúa desde el
   día 5 del mes en adelante (hora Hermosillo, ver ahoraHermosillo) y como máximo UNA VEZ
   por mes: config/cobranza.ultimoMesProcesado ("YYYY-MM" en Hermosillo) lo marca. Así, si el
   cron falla un día, se recupera solo al siguiente sin perder el mes ni volver a suspender
   lo ya suspendido. ultimoMesProcesado NUNCA se expone via /config/cobranza (esa ruta solo
   devuelve lo que da leerConfigCobranza, que no lo incluye) ni se toca desde la pantalla de
   configuración existente.

   Para cada jefe ACTIVO con adeudo > 0, reutiliza el MISMO núcleo de escritura que
   /personas/suspender (estado:'suspendido', cascada a familiares activos con
   suspendidoPor:'cascada', resyncFamilia) sumando motivoSuspension:'mora' — el campo
   reservado (ver comentario junto a suspenderPersona) que distingue esta suspensión
   automática de una manual de staff. Una suspensión manual (motivoSuspension ausente)
   jamás se toca aquí: solo se suspende a quien está 'activo' hoy. */
/* Núcleo ÚNICO de "quién debe": jefes ACTIVOS con adeudo > 0. Lo usan la suspensión automática
   y el recordatorio de pago (mismo criterio, sin duplicar el cálculo). Solo lee. `ahora` es
   opcional (hora Hermosillo, ver calcularEstadoCuenta); sin él, el momento actual. */
async function casasConAdeudo(env, at, cfg, ahora, soloDomNorm) {
  // Mismo recorrido único de "finanzas" que ya usa cobranzaFinanzas para armar el historial
  // completo de pagos de Cuota por casa, en vez de repetirlo casa por casa.
  const pagosPorCasa = new Map();
  for (const doc of await firestoreList(env, 'finanzas')) {
    const d = readDoc(doc.fields);
    if (esCancelado(d)) continue;   // un pago cancelado no abona al adeudo
    if (d.tipo !== 'ingreso' || d.categoria !== 'Cuota' || !d.casa) continue;
    const dn = normDomicilio(d.casa);
    if (soloDomNorm && dn !== soloDomNorm) continue;   // consulta de UNA casa: mismo cálculo, menos trabajo
    if (!pagosPorCasa.has(dn)) pagosPorCasa.set(dn, []);
    pagosPorCasa.get(dn).push({ ts: d.ts, monto: d.monto || 0 });
  }
  const all = await personasList(env, at);
  const morosas = [];
  for (const jefe of all.filter(p => esJefe(p) && p.estado === 'activo' && (!soloDomNorm || p.domicilioNorm === soloDomNorm))) {
    const estado = calcularEstadoCuenta({ altaCasa: jefe.creadoEn, cfg, pagosCuotaPorCasa: pagosPorCasa.get(jefe.domicilioNorm), ...(ahora ? { ahora } : {}) });
    if (estado.adeudo > 0) morosas.push({ jefe, estado });
  }
  return { all, morosas };
}
/* Config de cobranza SOLO lectura (no siembra config/cobranza si falta). */
function cfgCobranzaDesdeDoc(rawCfgDoc) {
  const raw = rawCfgDoc ? readDoc(rawCfgDoc.fields) : {};
  return {
    cuotaMensual: typeof raw.cuotaMensual === 'number' ? raw.cuotaMensual : CUOTA_DEFAULT,
    fechaInicioCobro: raw.fechaInicioCobro || FECHA_INICIO_COBRO_DEFAULT,
  };
}

async function aplicarSuspensionAutomatica(env, modo = 'aplicar') {
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const ahora = ahoraHermosillo();
  const mesActual = `${ahora.getUTCFullYear()}-${String(ahora.getUTCMonth() + 1).padStart(2, '0')}`;

  const rawCfgDoc = await getDoc(env, at, 'config/cobranza');
  const ultimoMesProcesado = rawCfgDoc ? (readDoc(rawCfgDoc.fields).ultimoMesProcesado || null) : null;

  // El tope de "una vez por mes, solo desde el día 5" es del comportamiento REAL. 'simular'
  // es una consulta de solo lectura: siempre calcula, sin importar la fecha ni lo ya procesado.
  if (modo === 'aplicar' && (ahora.getUTCDate() < 5 || ultimoMesProcesado === mesActual)) {
    return { ok:true, modo, aplico:false, mesActual, ultimoMesProcesado, suspendidas:[] };
  }

  let cfg;
  if (modo === 'aplicar') {
    cfg = await leerConfigCobranza(env); // asegura que config/cobranza exista antes de actualizarlo
  } else {
    // 'simular' NUNCA escribe — ni siquiera sembrar config/cobranza si no existiera todavía.
    // Arma cfg en memoria desde rawCfgDoc (ya leído arriba, un solo GET), con los mismos
    // defaults que usa leerConfigCobranza, pero sin llamarla (esa sí siembra el doc si falta).
    cfg = cfgCobranzaDesdeDoc(rawCfgDoc);
  }

  const { all, morosas } = await casasConAdeudo(env, at, cfg);
  const suspendidas = [];
  for (const { jefe, estado } of morosas) {
    if (modo === 'aplicar') {
      await firestoreActualizarCampos(env, `personas/${jefe.id}`, {
        estado:{stringValue:'suspendido'}, suspendidoPor:{stringValue:'individual'}, motivoSuspension:{stringValue:'mora'},
      }, 'Persona');
      for (const f of all.filter(x => x.jefeId === jefe.id && x.estado === 'activo')) {
        await firestoreActualizarCampos(env, `personas/${f.id}`, {
          estado:{stringValue:'suspendido'}, suspendidoPor:{stringValue:'cascada'}, motivoSuspension:{stringValue:'mora'},
        }, 'Persona');
      }
      await resyncFamilia(env, at, jefe.id, true);
      await logBitacora(env, at, { uid:'sistema', nombre:
        `Sistema suspendió a ${jefe.nombre}${jefe.domicilio ? ' ('+jefe.domicilio+')' : ''} por falta de pago — adeudo $${estado.adeudo}` });
    }
    suspendidas.push({ id: jefe.id, nombre: jefe.nombre, domicilio: jefe.domicilio, adeudo: estado.adeudo });
  }

  if (modo === 'aplicar') {
    await firestoreActualizarCampos(env, 'config/cobranza', { ultimoMesProcesado:{stringValue:mesActual} }, 'Configuración de cobranza');
  }
  return { ok:true, modo, aplico: modo === 'aplicar', mesActual, ultimoMesProcesado, suspendidas };
}

/* ============ Recordatorio de pago por push ============
   Lo dispara el MISMO cron diario (scheduled()); no hay cron nuevo. Día 1 y día 3 del mes
   (hora Hermosillo) avisa por push SOLO al jefe de las casas que el día 5 serían suspendidas.
   "Serían suspendidas" = casasConAdeudo (el núcleo de la suspensión automática) evaluado al día 5
   del mes en curso, así el criterio es idéntico al del corte. Antes de fechaInicioCobro el adeudo
   es 0 por definición, por lo que nadie recibe nada. Quien está al corriente, suspendido o dado
   de baja no sale en casasConAdeudo.
   Una marca por casa y día (recordatorios_pago/{personaId}_{AAAA-MM-DD}, creada con
   currentDocument.exists=false) evita repetir si el cron corre dos veces. Sin fcmToken no hay nada
   que enviar ni marca: no falla. Solo el Worker escribe ahí (las reglas niegan todo lo no listado). */
const MESES_ES = ['enero','febrero','marzo','abril','mayo','junio','julio','agosto','septiembre','octubre','noviembre','diciembre'];
function textoRecordatorioPago(dia, mesIdx) {
  if (dia === 1) return `Ya puedes pagar tu cuota de ${MESES_ES[mesIdx]}. Págala antes del día 5 para evitar la suspensión.`;
  if (dia === 3) return 'Te quedan 2 días para pagar tu cuota y evitar la suspensión del acceso vehicular.';
  return null;
}
function antesDeInicioCobro(cfg, ahora) {
  return inicioDiaHermosilloUTC(ahora.getUTCFullYear(), ahora.getUTCMonth(), ahora.getUTCDate()).getTime() < Date.parse(cfg.fechaInicioCobro);
}
/* `ahora`: Date en marco Hermosillo (como ahoraHermosillo()). Solo lee; arma el plan del día. */
async function planRecordatoriosPago(env, at, ahora) {
  const dia = ahora.getUTCDate(), mesIdx = ahora.getUTCMonth(), anio = ahora.getUTCFullYear();
  const fecha = `${anio}-${String(mesIdx + 1).padStart(2, '0')}-${String(dia).padStart(2, '0')}`;
  const texto = textoRecordatorioPago(dia, mesIdx);
  if (!texto) return { fecha, dia, texto: null, casas: [] };
  const cfg = cfgCobranzaDesdeDoc(await getDoc(env, at, 'config/cobranza'));
  // Nunca antes de fechaInicioCobro (además de que el adeudo ya sería 0 por el cálculo común).
  if (antesDeInicioCobro(cfg, ahora)) return { fecha, dia, texto, casas: [] };
  const dia5 = new Date(Date.UTC(anio, mesIdx, 5));
  const { morosas } = await casasConAdeudo(env, at, cfg, dia5);
  const casas = [];
  for (const { jefe, estado } of morosas) {
    const perfil = jefe.uid ? await getPerfil(env, jefe.uid) : null;
    casas.push({ id: jefe.id, nombre: jefe.nombre, domicilio: jefe.domicilio, uid: jefe.uid || null,
      adeudo: estado.adeudo, push: !!perfil?.fcmToken, fcmToken: perfil?.fcmToken || null });
  }
  return { fecha, dia, texto, casas };
}
/* Envío real (cron). Nunca lanza hacia scheduled(): un fallo aquí no debe tumbar la suspensión. */
async function enviarRecordatoriosPago(env, ahora = ahoraHermosillo()) {
  const res = { enviados: [], omitidas: [] };
  try {
    const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
    const plan = await planRecordatoriosPago(env, at, ahora);
    if (!plan.texto || !plan.casas.length) return { ...res, dia: plan.dia };
    let atFcm = null;
    for (const c of plan.casas) {
      if (!c.push) { res.omitidas.push({ id: c.id, motivo: 'sin-push' }); continue; }
      const marca = `recordatorios_pago/${c.id}_${plan.fecha}`;
      const r = await fetch(`${fsBase(env)}:commit`, {
        method:'POST', headers:{ Authorization:'Bearer '+at, 'Content-Type':'application/json' },
        body: JSON.stringify({ writes:[{ update:{ name: docName(env, marca), fields:{
          personaId:{stringValue:c.id}, fecha:{stringValue:plan.fecha}, dia:{integerValue:String(plan.dia)},
          ts:{timestampValue:new Date().toISOString()} } }, currentDocument:{ exists:false } }] }),
      });
      if (r.status === 409 || r.status === 400) { res.omitidas.push({ id: c.id, motivo: 'ya-enviado' }); continue; }
      if (!r.ok) { res.omitidas.push({ id: c.id, motivo: 'error-marca' }); continue; }
      try {
        atFcm = atFcm || await saToken(env, 'https://www.googleapis.com/auth/firebase.messaging');
        const p = await fetch(`https://fcm.googleapis.com/v1/projects/${env.FIREBASE_PROJECT}/messages:send`, {
          method:'POST', headers:{ Authorization:'Bearer '+atFcm, 'Content-Type':'application/json' },
          body: JSON.stringify({ message:{ token:c.fcmToken, notification:{ title:'Cerrada Mojave', body:plan.texto } } }),
        });
        if (!p.ok) throw new Error('fcm ' + p.status);
        res.enviados.push(c.id);
      } catch (e) {
        // No salió: se quita la marca para que un reintento del mismo día sí pueda enviarlo.
        await fetch(`${fsBase(env)}/${marca}`, { method:'DELETE', headers:{ Authorization:'Bearer '+at } }).catch(() => {});
        res.omitidas.push({ id: c.id, motivo: 'fallo-envio' });
      }
    }
    return { ...res, dia: plan.dia };
  } catch (e) {
    console.error('enviarRecordatoriosPago', e);
    return res;
  }
}
/* ============ /cobranza/aviso-pago — residente o familiar, SOLO su propia casa ============
   Solo lectura. Alimenta el aviso amarillo de Puertas en la app (la app NO lo consulta en cada
   apertura). mostrar:true únicamente del día 1 al 4 (Hermosillo), si la casa sería suspendida el
   día 5 (casasConAdeudo evaluado al día 5, el mismo núcleo del corte y del push) y nunca antes de
   fechaInicioCobro. Calcula en cada llamada, así que un pago que salda el adeudo apaga el aviso
   de inmediato para el jefe y todos sus familiares. La casa sale del perfil del token; si el
   cuerpo trae otra casa, 403. Nunca se lee otra casa. */
async function avisoPagoCasa(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!perfil || perfil.rol !== 'residente' || !perfil.casa) throw httpErr(403, 'Solo residentes con casa');
  const domNorm = normDomicilio(perfil.casa);
  const { casa } = await req.json().catch(() => ({}));
  if (casa !== undefined && casa !== null && casa !== '' && normDomicilio(casa) !== domNorm) throw httpErr(403, 'Solo puedes consultar tu propia casa');

  const ahora = ahoraHermosillo();
  const dia = ahora.getUTCDate();
  if (dia < 1 || dia > 4) return json({ ok:true, mostrar:false });
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const cfg = cfgCobranzaDesdeDoc(await getDoc(env, at, 'config/cobranza'));
  if (antesDeInicioCobro(cfg, ahora)) return json({ ok:true, mostrar:false });
  const dia5 = new Date(Date.UTC(ahora.getUTCFullYear(), ahora.getUTCMonth(), 5));
  const { morosas } = await casasConAdeudo(env, at, cfg, dia5, domNorm);
  if (!morosas.length) return json({ ok:true, mostrar:false });
  return json({ ok:true, mostrar:true, mes: MESES_ES[ahora.getUTCMonth()] });
}

/* ============ /admin/simular-recordatorio-pago — SOLO master y admin ============
   Muestra a qué casas se enviaría y con qué texto. No envía ni escribe nada. `fecha` opcional
   (AAAA-MM-DD) para ver cómo saldría otro día (p. ej. el 1 del mes que entra); sin ella, hoy. */
async function simularRecordatorioPago(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!perfil || (perfil.rol !== 'master' && perfil.rol !== 'admin')) throw httpErr(403, 'Solo master y admin');
  const { fecha } = await req.json().catch(() => ({}));
  let ahora = ahoraHermosillo();
  if (fecha !== undefined && fecha !== null && fecha !== '') {
    const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(fecha));
    const d = m && new Date(Date.UTC(+m[1], +m[2] - 1, +m[3]));
    if (!d || isNaN(d) || d.getUTCDate() !== +m[3]) throw httpErr(400, 'fecha inválida (AAAA-MM-DD)');
    ahora = d;
  }
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const plan = await planRecordatoriosPago(env, at, ahora);
  const casas = [];
  for (const c of plan.casas) {
    const ya = plan.texto ? !!(await getDoc(env, at, `recordatorios_pago/${c.id}_${plan.fecha}`)) : false;
    casas.push({ id: c.id, nombre: c.nombre, domicilio: c.domicilio, adeudo: c.adeudo, push: c.push, yaEnviado: ya });
  }
  return json({ ok:true, fecha: plan.fecha, dia: plan.dia, texto: plan.texto, casas });
}

/* Reactivación automática al pagar — la llama registrarFinanza justo después de escribir un
   ingreso de categoría Cuota. Recalcula el adeudo de la casa YA incluyendo ese pago; si queda
   al corriente Y la suspensión actual es por mora (motivoSuspension:'mora'), reactiva con el
   MISMO núcleo que /personas/reactivar (cascada solo a familiares suspendidoPor:'cascada' Y
   motivoSuspension:'mora'). Si está suspendida por cualquier otra razón (motivoSuspension
   ausente = decisión manual de staff), no toca nada — ajeno a este flujo. Nunca lanza: es un
   efecto secundario de mejor esfuerzo sobre un pago que ya se registró con éxito (mismo
   criterio que notificarResidente). */
async function intentarReactivarPorPago(env, casaCanon) {
  try {
    const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
    const domNorm = normDomicilio(casaCanon);
    const all = await personasList(env, at);
    const jefe = all.find(p => esJefe(p) && p.domicilioNorm === domNorm);
    if (!jefe || jefe.estado !== 'suspendido' || jefe.motivoSuspension !== 'mora') return;

    const cfg = await leerConfigCobranza(env);
    const pagos = [];
    for (const doc of await firestoreList(env, 'finanzas')) {
      const d = readDoc(doc.fields);
      if (esCancelado(d)) continue;
      if (d.tipo === 'ingreso' && d.categoria === 'Cuota' && d.casa && normDomicilio(d.casa) === domNorm) {
        pagos.push({ ts: d.ts, monto: d.monto || 0 });
      }
    }
    const estado = calcularEstadoCuenta({ altaCasa: jefe.creadoEn, cfg, pagosCuotaPorCasa: pagos });
    if (estado.adeudo > 0) return;

    await firestoreActualizarCampos(env, `personas/${jefe.id}`, {
      estado:{stringValue:'activo'}, suspendidoPor:{nullValue:null}, motivoSuspension:{nullValue:null},
    }, 'Persona');
    for (const f of all.filter(x => x.jefeId === jefe.id && x.estado === 'suspendido' && x.suspendidoPor === 'cascada' && x.motivoSuspension === 'mora')) {
      await firestoreActualizarCampos(env, `personas/${f.id}`, {
        estado:{stringValue:'activo'}, suspendidoPor:{nullValue:null}, motivoSuspension:{nullValue:null},
      }, 'Persona');
    }
    await resyncFamilia(env, at, jefe.id, true);
    await logBitacora(env, at, { uid:'sistema', nombre:
      `Sistema reactivó a ${jefe.nombre}${jefe.domicilio ? ' ('+jefe.domicilio+')' : ''} tras registrar pago que salda su adeudo` });
  } catch (e) {
    console.error('intentarReactivarPorPago', e);
  }
}

/* ============ /admin/probar-suspension-automatica — staff (master/admin/jefe-admin) ============
   Ejecuta aplicarSuspensionAutomatica(env, modo) bajo demanda: sirve para probar la lógica
   completa sin esperar al día 5 real ni depender del Cron Trigger, y queda permanente como
   botón de emergencia si el cron real llegara a fallar un mes.
   Seguridad por default: cualquier `modo` que NO sea exactamente 'aplicar' (ausente,
   'simular', typo, lo que sea) se trata como 'simular' — nunca escribe nada por accidente. */
async function probarSuspensionAutomatica(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!esStaff(perfil)) throw httpErr(403, 'Solo staff ejecuta esto');
  const { modo } = await req.json();
  const resumen = await aplicarSuspensionAutomatica(env, modo === 'aplicar' ? 'aplicar' : 'simular');
  return json(resumen);
}

/* ============ /config/cobranza — cualquier usuario autenticado lee la cuota vigente ============ */
async function obtenerConfigCobranza(req, env) {
  await requireAuth(req, env);
  const cfg = await leerConfigCobranza(env);
  return json({ ok:true, ...cfg });
}

/* ============ /config/cobranza-actualizar — staff para cuota/fecha, SOLO master para linkPago
   Gating POR CAMPO, no por endpoint: cuotaMensual y fechaInicioCobro son operación del día a
   día (permite staff: master/admin/jefe-admin) — p.ej. resetear fechaInicioCobro a "hoy" el
   día que arranque la cobranza real. linkPago (a dónde apunta el cobro de el proveedor de pago) es lo más
   sensible del endpoint, así que exige master explícitamente: si la petición INCLUYE linkPago
   (aunque sea el mismo valor ya guardado) y quien llama no es master, se rechaza con 403 antes
   de tocar nada — un admin no puede cambiarlo ni de rebote mandando el payload completo. */
async function actualizarConfigCobranza(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!esStaff(perfil)) throw httpErr(403, 'Solo staff edita la configuración de cobranza');

  const { cuotaMensual, fechaInicioCobro, linkPago } = await req.json();
  if (linkPago !== undefined && perfil.rol !== 'master') throw httpErr(403, 'Solo master edita el link de pago');

  const fields = {};
  if (cuotaMensual !== undefined) {
    const c = Number(cuotaMensual);
    if (!(c >= 0)) throw httpErr(400, 'cuotaMensual debe ser un número >= 0');
    fields.cuotaMensual = { doubleValue: c };
  }
  if (fechaInicioCobro !== undefined) {
    const t = Date.parse(fechaInicioCobro);
    if (!Number.isFinite(t)) throw httpErr(400, 'fechaInicioCobro inválida');
    fields.fechaInicioCobro = { timestampValue: new Date(t).toISOString() };
  }
  if (linkPago !== undefined) {
    // '' (borrar el link) se permite explícitamente; cualquier otra cosa DEBE empezar con
    // "https://" — nunca "http://" ni esquemas raros (javascript:, data:, etc.) que el
    // frontend abriría en target="_blank" sin más validación.
    const l = String(linkPago || '').trim();
    if (l && !l.startsWith('https://')) throw httpErr(400, 'linkPago debe empezar con "https://"');
    fields.linkPago = { stringValue: l };
  }
  if (!Object.keys(fields).length) throw httpErr(400, 'Nada que actualizar');

  await leerConfigCobranza(env); // asegura que el doc ya exista (lo siembra si aún no)
  await firestoreActualizarCampos(env, 'config/cobranza', fields, 'Configuración de cobranza');
  const cfg = await leerConfigCobranza(env);
  return json({ ok:true, ...cfg });
}

/* Lee config/cobranza; si el doc no existe TODAVÍA (primera vez que se toca esta feature),
   lo siembra con los defaults (cuota y fecha de inicio PENDIENTE_MOJAVE, sin link de pago) y los
   devuelve. No usa transacción: en la remotísima carrera de dos primeras-lecturas simultáneas,
   gana la última escritura y la diferencia es de milisegundos — sin consecuencia real. */
/* PENDIENTE_MOJAVE_CUOTA / PENDIENTE_MOJAVE_FECHA_INICIO_COBRO: valores neutros hasta definir la cobranza real
   (se cambian desde la app, Configuración de cobranza). Cuota 0 y fecha lejana = no se genera adeudo. */
const CUOTA_DEFAULT = 0;
const FECHA_INICIO_COBRO_DEFAULT = '2099-01-01T00:00:00.000Z';
async function leerConfigCobranza(env) {
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const doc = await getDoc(env, at, 'config/cobranza');
  if (doc) {
    const d = readDoc(doc.fields);
    return {
      cuotaMensual: typeof d.cuotaMensual === 'number' ? d.cuotaMensual : CUOTA_DEFAULT,
      fechaInicioCobro: d.fechaInicioCobro || FECHA_INICIO_COBRO_DEFAULT,
      linkPago: typeof d.linkPago === 'string' ? d.linkPago : '',
    };
  }
  const defaults = { cuotaMensual: CUOTA_DEFAULT, fechaInicioCobro: FECHA_INICIO_COBRO_DEFAULT, linkPago: '' };
  await firestoreSet(env, 'config/cobranza', {
    cuotaMensual: { doubleValue: defaults.cuotaMensual },
    fechaInicioCobro: { timestampValue: defaults.fechaInicioCobro },
    linkPago: { stringValue: defaults.linkPago },
  }, at);
  return defaults;
}

/* ============ /usuarios/crear — solo staff, vía Admin ============ */
async function crearUsuario(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!esStaff(perfil)) throw httpErr(403, 'No autorizado');

  const { nombre, email, password, rol, casa } = await req.json();
  if (!nombre || !email || !password || password.length < 8) throw httpErr(400, 'Datos inválidos');
  // admin NO puede crear master ni admin
  const permitidos = perfil.rol === 'master' ? ['admin','residente'] : ['residente'];
  if (!permitidos.includes(rol)) throw httpErr(403, 'Rol no permitido para tu cuenta');

  const at = await saToken(env, 'https://www.googleapis.com/auth/identitytoolkit https://www.googleapis.com/auth/datastore');
  // Crea la cuenta de Auth vía Identity Toolkit
  const res = await fetch(`https://identitytoolkit.googleapis.com/v1/projects/${env.FIREBASE_PROJECT}/accounts`, {
    method:'POST',
    headers:{ 'Authorization':'Bearer '+at, 'Content-Type':'application/json' },
    body: JSON.stringify({ email, password, displayName: nombre, emailVerified:false }),
  });
  if (!res.ok) throw httpErr(400, 'No se pudo crear la cuenta (¿correo ya existe?)');
  const { localId } = await res.json();

  await firestoreSet(env, `usuarios/${localId}`, {
    nombre:{stringValue:nombre}, email:{stringValue:email},
    rol:{stringValue:rol}, ...(casa?{casa:{stringValue:casa}}:{}),
  }, at);
  return json({ ok:true, uid: localId });
}

/* ===========================================================
   SHELLY
   =========================================================== */
/* ===========================================================
   ShellyGate — Durable Object "portero de fila" (UNA instancia global, nombre fijo).
   - Cola FIFO en memoria; UNA llamada real a Shelly a la vez.
   - Espaciado mínimo entre llamadas reales (SHELLY_MIN_SPACING_MS, contado desde que TERMINA la llamada
     anterior hasta que EMPIEZA la siguiente, así la llegada a Shelly siempre queda espaciada).
   - Si Shelly responde max_req / 429 => UN reintento tras SHELLY_RETRY_DELAY_MS; si falla otra
     vez => 502 "La cerradura no respondió" (igual que antes).
   - Tope de espera en fila (SHELLY_MAX_QUEUE_WAIT_MS): pasado ese tiempo sin llegarle el turno
     se responde 503 controlado (la app muestra el mensaje) y NO se llama a Shelly.
   - Dedupe: misma puerta dentro de SHELLY_DEDUPE_WINDOW_MS Y mientras la primera petición siga
     EN COLA (pulso aún no enviado) => se junta con ella (comparten resultado, una sola llamada
     real). Si el pulso ya salió, la petición nueva genera su propio pulso.
   - Lee SHELLY_HOST / SHELLY_AUTH_KEY de SU env (secrets del Worker). Jamás los devuelve ni los
     escribe en logs; los logs solo llevan el nombre de la puerta ("residentes"…), nunca el
     deviceId, ni la llave, ni el cuerpo de la respuesta de Shelly.
   Los valores se ajustan en wrangler.toml [vars]; los números de abajo son solo el respaldo.
   =========================================================== */
export class ShellyGate {
  constructor(state, env) {
    this.env = env;
    this.queue = [];          // trabajos esperando turno (FIFO)
    this.running = false;     // hay un drain() activo
    this.lastCallAt = 0;      // FIN de la última llamada real a Shelly
    this.recent = new Map();  // deviceId -> { at, job } (dedupe; solo une jobs aún en cola)
  }

  cfg(name) {
    return shellyCfg(this.env, name);
  }

  async fetch(req) {
    let deviceId, label, gen, offSec;
    try { ({ deviceId, label, gen, offSec } = await req.json()); } catch (e) {}
    if (typeof deviceId !== 'string' || !deviceId) return json({ ok:false, status:400, error:'Puerta no válida' });
    return json(await this.enqueue(deviceId, String(label || 'desconocida'), gen, offSec));
  }

  enqueue(deviceId, label, gen, offSec) {
    const now = Date.now();
    const dedupeMs = this.cfg('SHELLY_DEDUPE_WINDOW_MS');
    for (const [k, v] of this.recent) if (now - v.at >= dedupeMs) this.recent.delete(k);
    // Solo se une a un pulso que AÚN NO sale (job en cola). Si ya se disparó, esta petición
    // genera su propio pulso, espaciado como cualquier otro.
    const dup = this.recent.get(deviceId);
    if (dup && !dup.job.started) { console.log(`[shelly-gate] dedupe puerta=${label}`); return dup.job.promise; }

    const job = { deviceId, label, gen, offSec, at: now, started: false };
    job.promise = new Promise(resolve => { job.resolve = resolve; });
    this.recent.set(deviceId, { at: now, job });

    job.timer = setTimeout(() => {
      if (job.started) return;
      const i = this.queue.indexOf(job);
      if (i >= 0) this.queue.splice(i, 1);
      console.warn(`[shelly-gate] TIMEOUT en fila puerta=${label} esperó>=${this.cfg('SHELLY_MAX_QUEUE_WAIT_MS')}ms en_fila=${this.queue.length}`);
      this.finish(job, { ok:false, status:503, error:'La cerradura está muy ocupada en este momento, reintenta en unos segundos' });
    }, this.cfg('SHELLY_MAX_QUEUE_WAIT_MS'));

    this.queue.push(job);
    if (!this.running) { this.running = true; this.drain(); }
    return job.promise;
  }

  finish(job, result) {
    // Un fallo no se junta con reintentos posteriores: el siguiente intento es una llamada nueva.
    if (!result.ok && this.recent.get(job.deviceId)?.job === job) this.recent.delete(job.deviceId);
    job.resolve(result);
  }

  async drain() {
    try {
      while (this.queue.length) {
        const wait = this.lastCallAt + this.cfg('SHELLY_MIN_SPACING_MS') - Date.now();
        if (wait > 0) { await shellySleep(wait); continue; }  // re-evalúa: la cola pudo cambiar (timeouts)
        const job = this.queue.shift();
        job.started = true;
        clearTimeout(job.timer);
        console.log(`[shelly-gate] llamada puerta=${job.label} espera_en_fila=${Date.now() - job.at}ms restantes=${this.queue.length}`);
        let result;
        try { result = await this.callShelly(job); }
        catch (e) { result = { ok:false, status:502, error:'La cerradura no respondió' }; }
        this.finish(job, result);
      }
    } finally {
      this.running = false;
    }
  }

  async callShelly(job) {
    // Delega en callShellyOnce (arriba, junto a SHELLY_DEFAULTS) — es la MISMA función que usa
    // el modo "directo" (SHELLY_GATE_ENABLED="0"). El método (Gen1 form-urlencoded vs Gen2+ JSON)
    // lo decide la generación del dispositivo, que viaja con el job.
    try {
      return await callShellyOnce(this.env, { id: job.deviceId, gen: job.gen, offSec: job.offSec }, job.label);
    } finally {
      // El espaciado (drain(), abajo) cuenta desde que TERMINA esta llamada, tuviera que
      // reintentar por max_req/429 o no — así la siguiente llegada a Shelly siempre queda
      // espaciada, sin importar latencia ni conexión fría.
      this.lastCallAt = Date.now();
    }
  }
}

/* ===========================================================
   FIREBASE AUTH — verificación de ID token (JWKS)
   =========================================================== */
let JWKS_CACHE = { keys:null, exp:0 };
/* ===========================================================
   VOTACIONES (FASE V2) — endpoints del Worker.
   Garantías (ver el bloque votaciones/control de firestore.rules y el diseño aprobado):
   - MASTER NO GESTIONA: crear/cerrar solo admin y jefe-admin (403 al master). No basta
     esStaff() porque incluye al master; se excluye explícitamente con puedeGestionarVot().
   - Solo el JEFE (con casa) vota; casaId se DERIVA del perfil verificado en Firestore.
   - Un voto por casa: el id del doc participacion/{casaKey} es el candado (transacción).
   - Anonimato: la liga casa->opción vive solo en _privado/voto__{casaKey} (read:false) y se
     borra al congelar; participacion NO guarda opción; conteo es agregado.
   - Bloque de 5 estricto: nunca se libera un bloque incompleto (ni al cerrar). Nombres en
     orden aleatorio, sin orden ni timestamps. Candados (bloque + 1/hora) SOLO en el Worker.
   - Hora de SERVIDOR (reloj del Worker) en todo; el dispositivo nunca decide.
   =========================================================== */
const HORA_MS = 3600 * 1000;
const UMBRAL_MIN = 5;   // mínimo de participantes para mostrar el marcador
const BLOQUE = 5;       // los nombres se liberan solo en bloques completos de 5

// Gestionar (crear/cerrar) = admin puro o jefe-admin ACTIVO. NUNCA master. staff() no basta.
function puedeGestionarVot(p) {
  if (!p || p.rol === 'master') return false;
  if (p.rol === 'admin') return true;
  return p.esAdmin === true && (p.estado || 'activo') === 'activo';
}
// Jefe = residente sin jefeId y con casa. Admin puro / master / familiar => NO votan.
function esJefePerfil(p) {
  return !!p && p.rol === 'residente' && !p.jefeId && !!(p.casa && String(p.casa).trim());
}
// Clave de doc estable y URL-safe por casa: hash del domicilio normalizado (sin espacios/acentos).
async function casaKeyDe(domicilio) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(normDomicilio(domicilio)));
  return [...new Uint8Array(buf)].slice(0, 16).map(b => b.toString(16).padStart(2, '0')).join('');
}
function docName(env, path) { return `projects/${env.FIREBASE_PROJECT}/databases/(default)/documents/${path}`; }
function mapaInts(obj) { const fields = {}; for (const [k, v] of Object.entries(obj)) fields[k] = { integerValue: String(v) }; return { mapValue: { fields } }; }
function arrOpciones(ops) { return { arrayValue: { values: ops.map(o => ({ mapValue: { fields: { id: { stringValue: o.id }, texto: { stringValue: o.texto } } } })) } }; }
function barajar(a) { for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; } return a; }

// GET simple (sin transacción). Devuelve el doc crudo {name,fields} o null.
async function getDoc(env, at, path) {
  const r = await fetch(`${fsBase(env)}/${path}`, { headers: { Authorization: 'Bearer ' + at } });
  if (r.status === 404) return null;
  if (!r.ok) throw httpErr(500, 'Firestore get falló');
  return r.json();
}
// Firestore -> objeto de votación, incluyendo opciones (array) y conteo (map), que readDoc no maneja.
function parseVotacion(doc) {
  if (!doc || !doc.fields) return null;
  const f = doc.fields;
  const base = readDoc(f) || {};
  base.opciones = (f.opciones?.arrayValue?.values || []).map(v => ({
    id: v.mapValue?.fields?.id?.stringValue, texto: v.mapValue?.fields?.texto?.stringValue,
  }));
  const cf = f.conteo?.mapValue?.fields;
  base.conteo = cf ? Object.fromEntries(Object.entries(cf).map(([k, v]) => [k, +(v.integerValue || 0)])) : null;
  base.id = doc.name.split('/').pop();
  return base;
}

// ---- transacción read-modify-write serializable (para doble voto y "una sola activa") ----
async function txBegin(env, at) {
  const r = await fetch(`${fsBase(env)}:beginTransaction`, {
    method: 'POST', headers: { Authorization: 'Bearer ' + at, 'Content-Type': 'application/json' },
    body: JSON.stringify({ options: { readWrite: {} } }),
  });
  if (!r.ok) throw httpErr(500, 'No se pudo iniciar la transacción');
  return (await r.json()).transaction;
}
async function txGet(env, at, path, tx) {
  const r = await fetch(`${fsBase(env)}/${path}?transaction=${encodeURIComponent(tx)}`, { headers: { Authorization: 'Bearer ' + at } });
  if (r.status === 404) return null;
  if (!r.ok) throw httpErr(500, 'Firestore read (tx) falló');
  const d = await r.json();
  return d.fields ? d : null;
}
async function txCommit(env, at, tx, writes) {
  const r = await fetch(`${fsBase(env)}:commit`, {
    method: 'POST', headers: { Authorization: 'Bearer ' + at, 'Content-Type': 'application/json' },
    body: JSON.stringify({ transaction: tx, writes }),
  });
  return r.ok;   // false => conflicto (ABORTED): el caller reintenta
}
// Ejecuta fn(at, tx) -> { writes, value }; commitea con reintentos ante conflicto de concurrencia.
async function conTx(env, fn, tries = 4) {
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  for (let i = 0; i < tries; i++) {
    const tx = await txBegin(env, at);
    let out;
    try {
      out = await fn(at, tx);
    } catch (e) {
      await fetch(`${fsBase(env)}:rollback`, {
        method: 'POST', headers: { Authorization: 'Bearer ' + at, 'Content-Type': 'application/json' },
        body: JSON.stringify({ transaction: tx }),
      }).catch(() => {});
      throw e;   // error de negocio (403/409): no reintentar, propagar
    }
    if (await txCommit(env, at, tx, out.writes || [])) return out.value;
  }
  throw httpErr(409, 'Conflicto de concurrencia, reintenta');
}

// # de casas (jefes) activas del padrón — mismo criterio que /personas/listar.
async function contarCasasActivas(env, at) {
  const all = await personasList(env, at);
  return all.filter(p => esJefe(p) && (p.estado || 'activo') === 'activo').length;
}
// Borra la liga privada. soloVotos=true: solo voto__* (al congelar, conservando tally y throttles).
// soloVotos=false: TODO _privado (al cerrar). Best-effort, fuera de transacción.
async function borrarPrivado(env, at, votacionId, soloVotos) {
  let docs = [];
  try { docs = await firestoreList(env, `votaciones/${votacionId}/_privado`); } catch { return; }
  for (const d of docs) {
    const id = d.name.split('/').pop();
    if (soloVotos && !id.startsWith('voto__')) continue;
    await fetch(`${fsBase(env)}/votaciones/${votacionId}/_privado/${id}`, {
      method: 'DELETE', headers: { Authorization: 'Bearer ' + at },
    }).catch(() => {});
  }
}
// Reconciliación PEREZOSA del congelamiento (sin cron): en la 1a llamada tras congelaAt marca
// 'congelada' y BORRA la liga votante->opción. La liga es ilegible por cliente (read:false);
// solo la vería quien tenga la SA, y esta ventana la cierra el borrado. cerrar() borra el resto.
async function reconciliarFreeze(env, at, vot) {
  if (vot && vot.estado === 'abierta' && vot.congelaAt && Date.now() >= Date.parse(vot.congelaAt)) {
    await firestoreUpdate(env, `votaciones/${vot.id}`, { estado: { stringValue: 'congelada' } }, ['estado']);
    await borrarPrivado(env, at, vot.id, /* soloVotos */ true);
    vot.estado = 'congelada';
  }
  return vot;
}

/* ---- POST /votaciones/crear — admin o jefe-admin (403 al master) ---- */
async function crearVotacion(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!puedeGestionarVot(perfil)) throw httpErr(403, 'Solo un administrador puede crear votaciones');

  const body = await req.json();
  const titulo = String(body.titulo || '').trim();
  const descripcion = String(body.descripcion || '').trim();
  if (titulo.length < 3) throw httpErr(400, 'El título es muy corto');
  const textos = Array.isArray(body.opciones) ? body.opciones.map(s => String(s || '').trim()).filter(Boolean) : [];
  if (textos.length < 2 || textos.length > 10) throw httpErr(400, 'Se requieren entre 2 y 10 opciones');
  const cierra = Date.parse(body.cierraAt);
  if (!Number.isFinite(cierra)) throw httpErr(400, 'Fecha de cierre inválida');
  const ahora = Date.now();
  // Debe haber ventana de congelamiento: el cierre a más de 24h en el futuro (si no, congelaAt < ahora).
  if (cierra - ahora <= 24 * HORA_MS) throw httpErr(400, 'El cierre debe ser a más de 24h en el futuro (para la ventana de congelamiento)');
  const congela = cierra - 24 * HORA_MS;
  const umbral = Math.max(UMBRAL_MIN, +body.umbralConteo || UMBRAL_MIN);
  const opciones = textos.map((t, i) => ({ id: `op${i + 1}`, texto: t }));

  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const totalCasas = await contarCasasActivas(env, at);
  const id = crypto.randomUUID();

  const votacionId = await conTx(env, async (atx, tx) => {
    const ctrl = await txGet(env, atx, 'control/votaciones', tx);
    const activaId = ctrl?.fields?.activaId?.stringValue || null;
    if (activaId) {
      const vdoc = await txGet(env, atx, `votaciones/${activaId}`, tx);
      const estado = vdoc?.fields?.estado?.stringValue;
      if (estado === 'abierta' || estado === 'congelada') throw httpErr(409, 'Ya hay una votación activa');
    }
    const fields = {
      titulo: { stringValue: titulo }, descripcion: { stringValue: descripcion },
      opciones: arrOpciones(opciones),
      estado: { stringValue: 'abierta' }, activa: { booleanValue: true },
      creadaPor: { stringValue: user.uid },
      createdAt: { timestampValue: new Date(ahora).toISOString() },
      cierraAt: { timestampValue: new Date(cierra).toISOString() },
      congelaAt: { timestampValue: new Date(congela).toISOString() },
      totalCasasSnapshot: { integerValue: String(totalCasas) },
      umbralConteo: { integerValue: String(umbral) },
      participaronCount: { integerValue: '0' },
      // sin campo "conteo" hasta que participaronCount >= umbral (umbral aplicado en datos)
    };
    return {
      writes: [
        { update: { name: docName(env, `votaciones/${id}`), fields }, currentDocument: { exists: false } },
        { update: { name: docName(env, 'control/votaciones'), fields: { activaId: { stringValue: id } } }, updateMask: { fieldPaths: ['activaId'] } },
      ],
      value: id,
    };
  });
  return json({ ok: true, votacionId });
}

/* ---- POST /votaciones/cerrar — admin o jefe-admin (403 al master) ---- */
async function cerrarVotacion(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!puedeGestionarVot(perfil)) throw httpErr(403, 'Solo un administrador puede cerrar votaciones');
  const { votacionId } = await req.json();
  if (!votacionId || typeof votacionId !== 'string') throw httpErr(400, 'Falta votacionId');

  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const vot = parseVotacion(await getDoc(env, at, `votaciones/${votacionId}`));
  if (!vot) throw httpErr(404, 'Votación no encontrada');
  if (vot.estado === 'cerrada') throw httpErr(409, 'La votación ya está cerrada');

  // FASE V2.5 — al cerrar, la votación queda como ACTA permanente. Fijamos el conteo final
  // desde _privado/tally (necesario si tuvo <umbral votos y el conteo público nunca se
  // publicó) y en el MISMO commit borramos TODO _privado, para que el acta jamás conserve
  // la liga votante->opción. Snapshot del AGREGADO (tally), nunca de voto__*.
  const privados = await firestoreList(env, `votaciones/${votacionId}/_privado`).catch(() => []);
  const tally = {};
  const tf = privados.find(d => d.name.endsWith('/tally'))?.fields?.conteo?.mapValue?.fields;
  if (tf) for (const [k, v] of Object.entries(tf)) tally[k] = +(v.integerValue || 0);

  await conTx(env, async () => ({
    writes: [
      { update: { name: docName(env, `votaciones/${votacionId}`), fields: {
          estado: { stringValue: 'cerrada' }, activa: { booleanValue: false },
          conteo: mapaInts(tally),
          cerradaAt: { timestampValue: new Date().toISOString() },
          cerradaPor: { stringValue: user.uid },
        } }, updateMask: { fieldPaths: ['estado', 'activa', 'conteo', 'cerradaAt', 'cerradaPor'] } },
      { update: { name: docName(env, 'control/votaciones'), fields: { activaId: { nullValue: null } } }, updateMask: { fieldPaths: ['activaId'] } },
      ...privados.map(d => ({ delete: docName(env, `votaciones/${votacionId}/_privado/${d.name.split('/').pop()}`) })),
    ],
  }));

  // Defensa: ya cerrada, votar() rechaza nuevos votos, así que no aparecen más ligas. Si una se
  // coló entre el list y el commit, su voto__* no estaba en la lista borrada -> se limpia aquí,
  // de forma terminal. El acta NO se considera completa mientras _privado no quede VACÍO.
  let resto = await firestoreList(env, `votaciones/${votacionId}/_privado`).catch(() => []);
  for (let i = 0; i < 3 && resto.length; i++) { await borrarPrivado(env, at, votacionId, false); resto = await firestoreList(env, `votaciones/${votacionId}/_privado`).catch(() => []); }
  if (resto.length) throw httpErr(500, 'No se pudo limpiar la liga privada al archivar');

  return json({ ok: true, votacionId, conteoFinal: tally, participaronCount: vot.participaronCount || 0 });
}

/* ---- POST /votaciones/historial — lista de votaciones CERRADAS (actas). Cualquier residente ----
   Solo el agregado + metadata; los nombres van en /votaciones/participantes. */
async function historialVotaciones(req, env) {
  await requireAuth(req, env);   // cualquier residente autenticado; sin sesión -> 401
  const docs = await firestoreList(env, 'votaciones');
  const cerradas = docs.map(parseVotacion).filter(v => v && v.estado === 'cerrada');
  cerradas.sort((a, b) => Date.parse(b.cerradaAt || b.cierraAt || 0) - Date.parse(a.cerradaAt || a.cierraAt || 0));
  const votaciones = cerradas.map(v => ({
    id: v.id, titulo: v.titulo, descripcion: v.descripcion, opciones: v.opciones,
    conteo: v.conteo || {}, participaronCount: v.participaronCount || 0,
    totalCasas: v.totalCasasSnapshot || 0, cerradaAt: v.cerradaAt || null, cierraAt: v.cierraAt || null,
  }));
  return json({ ok: true, votaciones });
}

/* ---- POST /votaciones/participantes — lista COMPLETA de una votación CERRADA. Cualquier residente ----
   Sin bloque de 5 ni throttle: la liga ya no existe y el marcador ya no se mueve, así que el
   bloque no protegería nada (es el acta). Sobre una votación ABIERTA -> 409 (usa /participacion). */
async function participantesVotacion(req, env) {
  await requireAuth(req, env);   // cualquier residente autenticado; sin sesión -> 401
  const { votacionId } = await req.json();
  if (!votacionId || typeof votacionId !== 'string') throw httpErr(400, 'Falta votacionId');
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const vot = parseVotacion(await getDoc(env, at, `votaciones/${votacionId}`));
  if (!vot) throw httpErr(404, 'Votación no encontrada');
  if (vot.estado !== 'cerrada') throw httpErr(409, 'La lista completa solo está disponible en el historial (votaciones cerradas)');

  const docs = await firestoreList(env, `votaciones/${votacionId}/participacion`);
  const nombres = docs.map(d => readDoc(d.fields)).map(p => ({ nombre: p.nombre || '', casa: p.casa || '' }));
  nombres.sort((a, b) => (a.casa || '').localeCompare(b.casa || '', 'es', { numeric: true }));   // orden legible por casa (anonimato ya no depende del orden)
  return json({ ok: true, votacionId, titulo: vot.titulo, conteo: vot.conteo || {}, participaronCount: vot.participaronCount || 0, totalCasas: vot.totalCasasSnapshot || 0, nombres });
}

/* ---- POST /votaciones/votar — SOLO el jefe con casa (emitir o cambiar) ---- */
async function votarVotacion(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!esJefePerfil(perfil)) throw httpErr(403, 'Solo el jefe de una casa puede votar');
  if (perfil.suspendido || (perfil.estado || 'activo') !== 'activo') throw httpErr(403, 'La casa está suspendida');
  const { opcion } = await req.json();
  if (!opcion || typeof opcion !== 'string') throw httpErr(400, 'Falta la opción');

  const casaKey = await casaKeyDe(perfil.casa);
  const casaDisplay = String(perfil.casa).trim().replace(/\s+/g, ' ');
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');

  const ctrl = await getDoc(env, at, 'control/votaciones');
  const activaId = ctrl?.fields?.activaId?.stringValue || null;
  if (!activaId) throw httpErr(409, 'No hay una votación activa');
  let vot = parseVotacion(await getDoc(env, at, `votaciones/${activaId}`));
  if (!vot) throw httpErr(409, 'No hay una votación activa');
  vot = await reconciliarFreeze(env, at, vot);   // congela + borra liga si ya pasó congelaAt

  const ahora = Date.now();
  if (vot.estado === 'cerrada' || ahora >= Date.parse(vot.cierraAt)) throw httpErr(409, 'La votación está cerrada');
  if (!vot.opciones.some(o => o.id === opcion)) throw httpErr(400, 'Opción inválida');
  const congelado = ahora >= Date.parse(vot.congelaAt);

  const value = await conTx(env, async (atx, tx) => {
    const part = await txGet(env, atx, `votaciones/${activaId}/participacion/${casaKey}`, tx);
    const votDoc = await txGet(env, atx, `votaciones/${activaId}`, tx);
    const tallyDoc = await txGet(env, atx, `votaciones/${activaId}/_privado/tally`, tx);
    const participaron = +(votDoc?.fields?.participaronCount?.integerValue || 0);
    const umbral = +(votDoc?.fields?.umbralConteo?.integerValue || UMBRAL_MIN);
    const tally = {};
    const tf = tallyDoc?.fields?.conteo?.mapValue?.fields;
    if (tf) for (const [k, v] of Object.entries(tf)) tally[k] = +(v.integerValue || 0);

    const writes = [];
    let nuevoParticiparon = participaron;

    if (part) {
      // CAMBIO — bloqueado si ya se congeló.
      if (congelado) throw httpErr(409, 'El voto ya está congelado: a 24h del cierre no se puede cambiar');
      const votoPrev = await txGet(env, atx, `votaciones/${activaId}/_privado/voto__${casaKey}`, tx);
      const prev = votoPrev?.fields?.opcionActual?.stringValue;
      if (prev && prev !== opcion) {
        tally[prev] = Math.max(0, (tally[prev] || 0) - 1);
        tally[opcion] = (tally[opcion] || 0) + 1;
      }
      writes.push({ update: { name: docName(env, `votaciones/${activaId}/_privado/voto__${casaKey}`), fields: { opcionActual: { stringValue: opcion } } }, updateMask: { fieldPaths: ['opcionActual'] } });
    } else {
      // PRIMERA VEZ — el id del doc participacion/{casaKey} es el candado anti-doble-voto.
      nuevoParticiparon = participaron + 1;
      tally[opcion] = (tally[opcion] || 0) + 1;
      writes.push({ update: { name: docName(env, `votaciones/${activaId}/participacion/${casaKey}`), fields: { orden: { integerValue: String(nuevoParticiparon) }, nombre: { stringValue: perfil.nombre || '' }, casa: { stringValue: casaDisplay } } }, currentDocument: { exists: false } });
      // liga privada SOLO mientras se pueda cambiar (pre-freeze); post-freeze no se guarda liga alguna.
      if (!congelado) writes.push({ update: { name: docName(env, `votaciones/${activaId}/_privado/voto__${casaKey}`), fields: { opcionActual: { stringValue: opcion } } } });
    }
    // tally interno (Worker-only) siempre al día.
    writes.push({ update: { name: docName(env, `votaciones/${activaId}/_privado/tally`), fields: { conteo: mapaInts(tally) } }, updateMask: { fieldPaths: ['conteo'] } });
    // doc público: participaronCount + espejo de conteo SOLO si se alcanzó el umbral.
    const votUpdate = { participaronCount: { integerValue: String(nuevoParticiparon) } };
    const mask = ['participaronCount'];
    if (nuevoParticiparon >= umbral) { votUpdate.conteo = mapaInts(tally); mask.push('conteo'); }
    writes.push({ update: { name: docName(env, `votaciones/${activaId}`), fields: votUpdate }, updateMask: { fieldPaths: mask } });

    return { writes, value: { yaVotaste: true, miOpcionActual: opcion, puedeCambiar: !congelado } };
  });
  return json({ ok: true, ...value });
}

/* ---- POST /votaciones/estado — cualquier vecino: marcador en vivo + si YO ya voté ---- */
async function estadoVotacion(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');

  const ctrl = await getDoc(env, at, 'control/votaciones');
  const activaId = ctrl?.fields?.activaId?.stringValue || null;
  if (!activaId) return json({ activa: null });
  let vot = parseVotacion(await getDoc(env, at, `votaciones/${activaId}`));
  if (!vot) return json({ activa: null });
  vot = await reconciliarFreeze(env, at, vot);

  const ahora = Date.now();
  const cerrada = vot.estado === 'cerrada' || ahora >= Date.parse(vot.cierraAt);
  const congelado = ahora >= Date.parse(vot.congelaAt);

  const resp = {
    activa: {
      id: vot.id, titulo: vot.titulo, descripcion: vot.descripcion, opciones: vot.opciones,
      estado: cerrada ? 'cerrada' : (congelado ? 'congelada' : 'abierta'),
      cierraAt: vot.cierraAt, congelaAt: vot.congelaAt,
      participaronCount: vot.participaronCount || 0, totalCasas: vot.totalCasasSnapshot || 0,
      umbralConteo: vot.umbralConteo || UMBRAL_MIN,
      conteo: vot.conteo || null,          // solo presente si participaronCount >= umbral
      conteoOculto: !vot.conteo,
    },
  };
  // Vista PERSONAL del jefe (solo su propia casa). Nadie ve la opción de nadie más.
  if (esJefePerfil(perfil)) {
    const casaKey = await casaKeyDe(perfil.casa);
    const part = await getDoc(env, at, `votaciones/${activaId}/participacion/${casaKey}`);
    const yaVotaste = !!part;
    let miOpcionActual = null;
    if (yaVotaste && !congelado) {
      const voto = await getDoc(env, at, `votaciones/${activaId}/_privado/voto__${casaKey}`);
      miOpcionActual = voto?.fields?.opcionActual?.stringValue || null;
    }
    resp.yo = { esJefe: true, yaVotaste, miOpcionActual, puedeCambiar: yaVotaste && !congelado && !cerrada };
  } else {
    resp.yo = { esJefe: false };   // admin puro / master / familiar no votan
  }
  return json(resp);
}

/* ---- POST /votaciones/participacion — lista nominal, con los DOS candados en el Worker ----
   Lectura permitida a staff (master incluido: master LEE todo, no gestiona). Jefe/familiar => 403.
   Candado 1: bloque de 5 estricto (nunca un bloque incompleto). Candado 2: 1 consulta/hora por
   cuenta, con hora de servidor. Ambos aquí; manipular el front no los burla (recibe 403). */
async function participacionVotacion(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!esStaff(perfil)) throw httpErr(403, 'Solo el staff consulta la lista de participación');
  const { votacionId } = await req.json();
  if (!votacionId || typeof votacionId !== 'string') throw httpErr(400, 'Falta votacionId');

  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');

  // Candado 2 — 1/hora por cuenta (hora de servidor), bucket independiente por uid.
  const accPath = `votaciones/${votacionId}/_privado/admin__${user.uid}`;
  const acc = await getDoc(env, at, accPath);
  const ultimo = acc?.fields?.ultimoAccesoAt?.timestampValue ? Date.parse(acc.fields.ultimoAccesoAt.timestampValue) : 0;
  if (Date.now() - ultimo < HORA_MS) throw httpErr(403, 'Solo puedes consultar la lista una vez por hora');
  await firestoreSet(env, accPath, { ultimoAccesoAt: { timestampValue: new Date().toISOString() } }, at);

  const vot = parseVotacion(await getDoc(env, at, `votaciones/${votacionId}`));
  if (!vot) throw httpErr(404, 'Votación no encontrada');
  const participaron = vot.participaronCount || 0;
  // Candado 1 — bloque de 5 estricto: solo bloques COMPLETOS, nunca el remanente (ni al cerrar).
  const reveladosCount = Math.floor(participaron / BLOQUE) * BLOQUE;

  let nombres = [];
  if (reveladosCount > 0) {
    const docs = await firestoreList(env, `votaciones/${votacionId}/participacion`);
    nombres = docs.map(d => readDoc(d.fields))
      .filter(p => (p.orden || 0) <= reveladosCount)
      .map(p => ({ nombre: p.nombre || '', casa: p.casa || '' }));   // sin orden, sin timestamps
    barajar(nombres);   // orden aleatorio dentro del bloque
  }
  return json({ ok: true, participaronCount: participaron, reveladosCount, pendientesSinDesglosar: participaron - reveladosCount, nombres });
}

async function requireAuth(req, env) {
  const h = req.headers.get('Authorization') || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) throw httpErr(401, 'Falta token');
  return verifyIdToken(token, env);
}

/* Validación del ID token. Contrato de errores: TODO token inválido responde 401 con un mensaje
   fijo y genérico — nunca un 500 ni el texto de una excepción interna. Las excepciones inesperadas
   se registran (solo el nombre, sin token ni secretos) y se responden 401 "No autorizado". */
async function verifyIdToken(token, env) {
  try {
    return await verifyIdTokenInterno(token, env);
  } catch (e) {
    if (e && e.status) throw e;   // httpErr controlado: ya lleva su mensaje fijo
    console.error('[auth] excepción inesperada al validar el token:', e && e.name);
    throw httpErr(401, 'No autorizado');
  }
}

async function verifyIdTokenInterno(token, env) {
  // Parseo defensivo: 3 partes, base64url válido y JSON de objeto; si no, 401 (no una excepción => 500).
  let h, p, s, header, claims;
  try {
    const partes = token.split('.');
    if (partes.length !== 3) throw new Error('partes');
    [h, p, s] = partes;
    if (!h || !p || !s) throw new Error('vacío');
    header = JSON.parse(b64urlToStr(h));
    claims = JSON.parse(b64urlToStr(p));
    const esObjeto = o => o !== null && typeof o === 'object' && !Array.isArray(o);
    if (!esObjeto(header) || !esObjeto(claims)) throw new Error('no-objeto');
  } catch (e) {
    throw httpErr(401, 'Token malformado');
  }

  const proj = env.FIREBASE_PROJECT;
  if (claims.aud !== proj) throw httpErr(401, 'aud inválido');
  if (claims.iss !== `https://securetoken.google.com/${proj}`) throw httpErr(401, 'iss inválido');
  // exp OBLIGATORIO y numérico: válido solo si exp*1000 > ahora (sin exp => NaN => rechazado).
  if (typeof claims.exp !== 'number' || !Number.isFinite(claims.exp)) throw httpErr(401, 'No autorizado');
  if (!(claims.exp * 1000 > Date.now())) throw httpErr(401, 'Token expirado');

  const key = await getGooglePublicKey(header.kid);
  let ok = false;
  try {
    ok = await crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5', key,
      b64urlToBytes(s), new TextEncoder().encode(`${h}.${p}`)
    );
  } catch (e) { ok = false; }   // firma con base64 inválido o longitud rara => firma inválida, no 500
  if (!ok) throw httpErr(401, 'Firma inválida');

  const uid = claims.user_id || claims.sub;
  if (typeof uid !== 'string' || !uid) throw httpErr(401, 'No autorizado');   // sub obligatorio
  return { uid, email: claims.email };
}

async function getGooglePublicKey(kid) {
  if (!JWKS_CACHE.keys || Date.now() > JWKS_CACHE.exp) {
    let motivo = 'error de red o JSON ilegible';
    try {
      const r = await fetch('https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com');
      // Solo se usa/cachea una respuesta EXITOSA con el formato esperado (objeto con al menos un
      // certificado PEM). Si no, NO se cachea (la caché no se envenena) y el siguiente intento reintenta.
      if (!r.ok) { motivo = `HTTP ${r.status}`; throw new Error(motivo); }
      const certs = await r.json();
      const esObjeto = certs !== null && typeof certs === 'object' && !Array.isArray(certs);
      if (!esObjeto || !Object.values(certs).some(v => typeof v === 'string' && v.includes('BEGIN CERTIFICATE'))) {
        motivo = 'formato inesperado (sin certificados)'; throw new Error(motivo);
      }
      const maxAge = +(r.headers.get('cache-control')||'').match(/max-age=(\d+)/)?.[1] || 3600;
      JWKS_CACHE = { keys: certs, exp: Date.now() + maxAge*1000 };
    } catch (e) {
      // Falla de infraestructura (no del token): mensaje fijo al cliente; el detalle va al log.
      console.error('[auth] no se pudieron obtener certificados válidos de Google:', motivo, e && e.name);
      throw httpErr(503, 'Autenticación no disponible, reintenta');
    }
  }
  // kid a prueba de prototipo: solo claves PROPIAS del mapa ('constructor', 'toString'… no cuentan).
  if (typeof kid !== 'string' || !Object.hasOwn(JWKS_CACHE.keys, kid)) throw httpErr(401, 'No autorizado');
  const pem = JWKS_CACHE.keys[kid];
  if (typeof pem !== 'string' || !pem) throw httpErr(401, 'No autorizado');
  return importX509(pem);
}

/* ===========================================================
   SERVICE ACCOUNT — token OAuth para Firestore/Identity (Admin)
   =========================================================== */
/* Credenciales de la cuenta de servicio: SA_EMAIL/SA_PRIVATE_KEY, o el JSON GOOGLE_CREDENTIALS. */
function saCreds(env) {
  if (env.SA_EMAIL && env.SA_PRIVATE_KEY) return { email: env.SA_EMAIL, key: env.SA_PRIVATE_KEY };
  const c = JSON.parse(env.GOOGLE_CREDENTIALS);
  return { email: c.client_email, key: c.private_key };
}
async function saToken(env, scope) {
  const creds = saCreds(env);
  const now = Math.floor(Date.now()/1000);
  const jwtHeader = b64url(JSON.stringify({ alg:'RS256', typ:'JWT' }));
  const jwtClaim = b64url(JSON.stringify({
    iss: creds.email, scope, aud:'https://oauth2.googleapis.com/token',
    iat: now, exp: now+3600,
  }));
  const key = await importPKCS8(creds.key.replace(/\\n/g,'\n'));
  const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, new TextEncoder().encode(`${jwtHeader}.${jwtClaim}`));
  const assertion = `${jwtHeader}.${jwtClaim}.${bytesToB64url(new Uint8Array(sig))}`;
  const r = await fetch('https://oauth2.googleapis.com/token', {
    method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:`grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${assertion}`,
  });
  const d = await r.json();
  if (!d.access_token) throw httpErr(500, 'SA token falló');
  return d.access_token;
}

/* ===========================================================
   FIRESTORE REST helpers (con service account)
   =========================================================== */
function fsBase(env){ return `https://firestore.googleapis.com/v1/projects/${env.FIREBASE_PROJECT}/databases/(default)/documents`; }

async function getPerfil(env, uid) {
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const r = await fetch(`${fsBase(env)}/usuarios/${uid}`, { headers:{ Authorization:'Bearer '+at } });
  if (!r.ok) return null;
  const d = await r.json();
  return readDoc(d.fields);
}
/* Lista completa de una colección (paginada) — usada por /finanzas/resumen y vecinos. */
async function firestoreList(env, coleccion) {
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const docs = [];
  let pageToken;
  do {
    const url = new URL(`${fsBase(env)}/${coleccion}`);
    url.searchParams.set('pageSize', '300');
    if (pageToken) url.searchParams.set('pageToken', pageToken);
    const r = await fetch(url, { headers:{ Authorization:'Bearer '+at } });
    if (!r.ok) throw httpErr(500, 'Firestore list falló');
    const d = await r.json();
    (d.documents||[]).forEach(doc => docs.push(doc));
    pageToken = d.nextPageToken;
  } while (pageToken);
  return docs;
}
/* Busca una invitación de visita por el HASH de su token opaco (modelo QR sin datos).
   Equality sobre un solo campo → Firestore lo indexa solo, sin índice compuesto. Devuelve
   el doc con su id (jti) para poder actualizar usosRestantes, o null si no existe. */
async function getInvitacionPorTokenHash(env, tokenHash) {
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const r = await fetch(`${fsBase(env)}:runQuery`, {
    method:'POST', headers:{ Authorization:'Bearer '+at, 'Content-Type':'application/json' },
    body: JSON.stringify({ structuredQuery: {
      from: [{ collectionId: 'invitaciones' }],
      where: { fieldFilter: { field: { fieldPath: 'tokenHash' }, op: 'EQUAL', value: { stringValue: tokenHash } } },
      limit: 1,
    }}),
  });
  if (!r.ok) throw httpErr(500, 'Firestore query falló');
  const rows = await r.json();
  const hit = (rows || []).find(x => x.document);
  if (!hit) return null;
  return { id: hit.document.name.split('/').pop(), ...readDoc(hit.document.fields) };
}
/* Igual que getInvitacionPorTokenHash pero por el PIN de respaldo — mismo patrón de query
   de igualdad sobre un solo campo, sin índice compuesto. */
async function getInvitacionPorPinHash(env, pinHash) {
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const r = await fetch(`${fsBase(env)}:runQuery`, {
    method:'POST', headers:{ Authorization:'Bearer '+at, 'Content-Type':'application/json' },
    body: JSON.stringify({ structuredQuery: {
      from: [{ collectionId: 'invitaciones' }],
      where: { fieldFilter: { field: { fieldPath: 'pinHash' }, op: 'EQUAL', value: { stringValue: pinHash } } },
      limit: 1,
    }}),
  });
  if (!r.ok) throw httpErr(500, 'Firestore query falló');
  const rows = await r.json();
  const hit = (rows || []).find(x => x.document);
  if (!hit) return null;
  return { id: hit.document.name.split('/').pop(), ...readDoc(hit.document.fields) };
}

/* ---- Candado de fuerza bruta del PIN, por LECTOR (controlPin/{readerId}) ----
   Un PIN incorrecto no pertenece a ninguna invitación (no se sabe cuál intentaba abrir quien
   lo tecleó mal), así que el candado vive en su propia colección, no colgado de invitaciones/
   {jti}. Mismo mecanismo de incremento atómico que siguienteFolioRecibo (updateTransforms,
   sin transacción explícita, sin condición de carrera entre intentos casi simultáneos del
   mismo lector). controlPin NUNCA es legible/escribible desde el cliente (ver firestore.rules)
   — solo el Worker, vía service account. */
const PIN_LOCK_MAX_FALLOS = 5;
const PIN_LOCK_MS = 5 * 60 * 1000;

async function checarCandadoPin(env, at, readerId) {
  const doc = await getDoc(env, at, `controlPin/${readerId}`);
  const bloqueadoHasta = doc?.fields?.bloqueadoHasta?.timestampValue
    ? Date.parse(doc.fields.bloqueadoHasta.timestampValue) : 0;
  if (bloqueadoHasta > Date.now()) {
    const segundos = Math.ceil((bloqueadoHasta - Date.now()) / 1000);
    throw httpErr(403, `Demasiados intentos fallidos. Intenta de nuevo en ${segundos} segundos.`);
  }
}
async function registrarFalloPin(env, at, readerId) {
  const base = `projects/${env.FIREBASE_PROJECT}/databases/(default)`;
  const r = await fetch(`https://firestore.googleapis.com/v1/${base}/documents:commit`, {
    method:'POST', headers:{ Authorization:'Bearer '+at, 'Content-Type':'application/json' },
    body: JSON.stringify({
      writes: [{
        // update con máscara vacía = merge que crea el doc si no existe; el increment va
        // aparte en updateTransforms (atómico, mismo patrón que siguienteFolioRecibo).
        update: { name: `${base}/documents/controlPin/${readerId}`, fields: {} },
        updateMask: { fieldPaths: [] },
        updateTransforms: [{ fieldPath: 'fallidos', increment: { integerValue: '1' } }],
      }],
    }),
  });
  if (!r.ok) return;   // best-effort: si el conteo falla, igual responde 'PIN inválido' arriba
  const d = await r.json();
  const n = Number(d.writeResults?.[0]?.transformResults?.[0]?.integerValue);
  if (n >= PIN_LOCK_MAX_FALLOS) {
    // firestoreSet REEMPLAZA el documento completo: deja fallidos:0 y bloqueadoHasta como
    // ÚNICOS campos, sin necesidad de borrar nada aparte.
    await firestoreSet(env, `controlPin/${readerId}`, {
      fallidos: { integerValue: '0' },
      bloqueadoHasta: { timestampValue: new Date(Date.now() + PIN_LOCK_MS).toISOString() },
    }, at);
  }
}
async function resetearCandadoPin(env, at, readerId) {
  // firestoreSet REEMPLAZA el documento completo: dejar solo fallidos:0 también borra
  // bloqueadoHasta si existía.
  await firestoreSet(env, `controlPin/${readerId}`, { fallidos: { integerValue: '0' } }, at);
}

async function firestoreSet(env, path, fields, atOverride) {
  const at = atOverride || await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const r = await fetch(`${fsBase(env)}/${path}`, {
    method:'PATCH', headers:{ Authorization:'Bearer '+at, 'Content-Type':'application/json' },
    body: JSON.stringify({ fields }),
  });
  if (!r.ok) throw httpErr(500, 'Firestore set falló');
}
async function firestoreUpdate(env, path, fields, mask) {
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const qs = mask.map(m=>`updateMask.fieldPaths=${m}`).join('&');
  await fetch(`${fsBase(env)}/${path}?${qs}`, {
    method:'PATCH', headers:{ Authorization:'Bearer '+at, 'Content-Type':'application/json' },
    body: JSON.stringify({ fields }),
  });
}
/* Como firestoreUpdate pero estricto: máscara derivada de los campos, exige que el
   documento exista (no crea fantasmas si el id es inválido) y truena con error claro. */
async function firestoreActualizarCampos(env, path, fields, label = 'Documento') {
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const qs = Object.keys(fields).map(f=>`updateMask.fieldPaths=${encodeURIComponent(f)}`).join('&');
  const r = await fetch(`${fsBase(env)}/${path}?${qs}&currentDocument.exists=true`, {
    method:'PATCH', headers:{ Authorization:'Bearer '+at, 'Content-Type':'application/json' },
    body: JSON.stringify({ fields }),
  });
  if (r.status === 404 || r.status === 400) throw httpErr(404, `${label} no existe`);
  if (!r.ok) throw httpErr(500, 'Firestore update falló');
}
async function logApertura(env, o) {
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  await fetch(`${fsBase(env)}/aperturas`, {
    method:'POST', headers:{ Authorization:'Bearer '+at, 'Content-Type':'application/json' },
    body: JSON.stringify({ fields: {
      uid:{stringValue:o.uid}, nombre:{stringValue:o.nombre||'Usuario'},
      puerta:{stringValue:o.puerta}, hogar:{stringValue:o.hogar},
      tipo:{stringValue:o.tipo}, ts:{timestampValue:new Date().toISOString()},
    }}),
  });
}
async function notificarResidente(env, residenteUid, mensaje) {
  const perfil = await getPerfil(env, residenteUid);
  if (!perfil?.fcmToken) return;
  const at = await saToken(env, 'https://www.googleapis.com/auth/firebase.messaging');
  await fetch(`https://fcm.googleapis.com/v1/projects/${env.FIREBASE_PROJECT}/messages:send`, {
    method:'POST', headers:{ Authorization:'Bearer '+at, 'Content-Type':'application/json' },
    body: JSON.stringify({ message:{ token: perfil.fcmToken,
      notification:{ title:'Cerrada Mojave', body: mensaje } } }),
  }).catch(()=>{});
}

/* Convierte fields Firestore → objeto plano (solo los tipos que usamos) */
function readDoc(fields) {
  if (!fields) return null;
  const o = {};
  for (const [k,v] of Object.entries(fields)) {
    if ('stringValue' in v) o[k]=v.stringValue;
    else if ('integerValue' in v) o[k]=+v.integerValue;
    else if ('doubleValue' in v) o[k]=+v.doubleValue;
    else if ('booleanValue' in v) o[k]=v.booleanValue;
    else if ('timestampValue' in v) o[k]=v.timestampValue;
    else if ('nullValue' in v) o[k]=null;
  }
  return o;
}

/* ===========================================================
   Pre-sync al lector
   =========================================================== */
async function presyncReader(env, item){
  if (!env.READER_SYNC_URL) return;   // endpoint local del lector (cuando se defina el modelo)
  await fetch(env.READER_SYNC_URL, {
    method:'POST', headers:{ 'Content-Type':'application/json', 'X-Reader-Key': env.READER_KEY || '' },
    body: JSON.stringify(item),
  });
}

/* ===========================================================
   CRYPTO / BASE64 helpers
   =========================================================== */
function b64url(str){ return bytesToB64url(new TextEncoder().encode(str)); }
function bytesToB64url(bytes){
  let bin=''; for (const b of bytes) bin+=String.fromCharCode(b);
  return btoa(bin).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function b64urlToBytes(s){
  s=s.replace(/-/g,'+').replace(/_/g,'/'); while(s.length%4) s+='=';
  const bin=atob(s); const out=new Uint8Array(bin.length);
  for(let i=0;i<bin.length;i++) out[i]=bin.charCodeAt(i); return out;
}
function b64urlToStr(s){ return new TextDecoder().decode(b64urlToBytes(s)); }

// Lee un TLV DER en `offset`: soporta longitud corta y larga (suficiente para certs X.509).
function derReadTLV(bytes, offset){
  const tag = bytes[offset];
  const lenByte = bytes[offset+1];
  let length, lenOffset = offset+2;
  if (lenByte & 0x80){
    const numBytes = lenByte & 0x7f;
    length = 0;
    for (let i=0;i<numBytes;i++) length = (length<<8) | bytes[lenOffset+i];
    lenOffset += numBytes;
  } else {
    length = lenByte;
  }
  return { tag, contentStart: lenOffset, totalLen: (lenOffset-offset)+length };
}
// Certificate ::= SEQUENCE { tbsCertificate, sigAlg, sig }
// tbsCertificate ::= SEQUENCE { [0] version?, serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo, ... }
// El SPKI que necesita crypto.subtle.importKey('spki', ...) está anidado ahí adentro, hay que extraerlo.
function extractSpkiFromX509(der){
  const cert = derReadTLV(der, 0);
  const tbs = derReadTLV(der, cert.contentStart);
  let p = tbs.contentStart;
  let el = derReadTLV(der, p);
  if (el.tag === 0xA0) p += el.totalLen; // version [0] EXPLICIT, opcional
  for (let i=0; i<5; i++){ el = derReadTLV(der, p); p += el.totalLen; } // serialNumber, signature, issuer, validity, subject
  el = derReadTLV(der, p); // subjectPublicKeyInfo
  return der.slice(p, p + el.totalLen);
}
async function importX509(pem){
  const der = pemToDer(pem);
  try {
    const spki = extractSpkiFromX509(der);
    return await crypto.subtle.importKey('spki', spki, { name:'RSASSA-PKCS1-v1_5', hash:'SHA-256' }, false, ['verify']);
  } catch (e) {
    throw httpErr(500, 'No se pudo importar la clave de Google');
  }
}
async function importPKCS8(pem){
  const der = pemToDer(pem);
  return crypto.subtle.importKey('pkcs8', der, { name:'RSASSA-PKCS1-v1_5', hash:'SHA-256' }, false, ['sign']);
}
function pemToDer(pem){
  const b64 = pem.replace(/-----[^-]+-----/g,'').replace(/\s+/g,'');
  return b64urlToBytes(b64.replace(/\+/g,'-').replace(/\//g,'_'));
}

/* ===========================================================
   HTTP utils
   =========================================================== */
function json(obj, status=200){ return new Response(JSON.stringify(obj), { status, headers:{'Content-Type':'application/json'} }); }
function httpErr(status, msg){ const e=new Error(msg); e.status=status; return e; }
function cors(res, origin){
  const h = new Headers(res.headers);
  h.set('Access-Control-Allow-Origin', origin);
  h.set('Access-Control-Allow-Headers', 'Authorization, Content-Type, X-Firebase-AppCheck, X-Reader-Key');
  h.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
  return new Response(res.body, { status:res.status, headers:h });
}
