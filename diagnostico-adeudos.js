/* ===========================================================
   Diagnóstico de adeudos por casa, de SOLO LECTURA.
   Este script NUNCA escribe ni borra nada en Firestore — solo lee "personas",
   "finanzas" y "config/cobranza", y calcula el adeudo de cada jefe de familia
   con EXACTAMENTE la misma lógica que calcularEstadoCuenta() en worker.js
   (Hermosillo UTC-7 fijo, fechaEfectiva, mesesTranscurridos, cuota fija).

   Pensado para responder, sin tocar nada: "si aplicarSuspensionAutomatica corriera
   HOY, ¿a quién suspendería y con qué adeudo?" — antes de usar el botón real.

   Uso:
     node run-with-sa.js <ruta-al-json-de-la-service-account> diagnostico-adeudos.js

   Requiere las mismas variables de entorno que respaldo-diagnostico.js:
     FIREBASE_PROJECT, SA_EMAIL, SA_PRIVATE_KEY
   =========================================================== */

const { saToken, listCollection, fsBase, fsFields, fsDocToPlain } = require('./firestore-sa');

const HERMOSILLO_OFFSET_MS = 7 * 60 * 60 * 1000;
function aHermosillo(instante) { return new Date(new Date(instante).getTime() - HERMOSILLO_OFFSET_MS); }
function ahoraHermosillo() { return aHermosillo(Date.now()); }

function normDomicilio(s) { return String(s || '').trim().replace(/\s+/g, ' ').toUpperCase(); }
function esJefe(p) { return p.rol === 'residente' && !p.jefeId; }

// Copia exacta de calcularEstadoCuenta() en worker.js — mismo cálculo, cero migración.
function calcularEstadoCuenta({ altaCasa, cfg, pagosCuotaPorCasa }) {
  const inicioCobro = new Date(cfg.fechaInicioCobro);
  const alta = altaCasa ? new Date(altaCasa) : inicioCobro;
  const fechaEfectiva = (alta instanceof Date && !isNaN(alta) && alta > inicioCobro) ? alta : inicioCobro;

  const ahora = ahoraHermosillo();
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

function fmtMonto(m) { return typeof m === 'number' ? m.toLocaleString('es-MX', { style: 'currency', currency: 'MXN' }) : String(m); }

async function main() {
  for (const v of ['FIREBASE_PROJECT', 'SA_EMAIL', 'SA_PRIVATE_KEY']) {
    if (!process.env[v]) { console.error(`Falta la variable de entorno ${v}. Ver instrucciones al inicio del archivo.`); process.exit(1); }
  }

  console.log('🔎 Diagnóstico de adeudos por casa (solo lectura, no se escribe nada en Firestore).');
  console.log('');

  const token = await saToken();

  // config/cobranza — un solo doc, no es una colección; fetch directo.
  const cfgRes = await fetch(`${fsBase()}/config/cobranza`, { headers: { Authorization: 'Bearer ' + token } });
  if (!cfgRes.ok) { console.error('No se pudo leer config/cobranza:', cfgRes.status, await cfgRes.text()); process.exit(1); }
  const cfgDoc = await cfgRes.json();
  const cfgFields = fsFields(cfgDoc.fields || {});
  const cfg = {
    cuotaMensual: typeof cfgFields.cuotaMensual === 'number' ? cfgFields.cuotaMensual : 0,
    fechaInicioCobro: cfgFields.fechaInicioCobro || '2099-01-01T00:00:00.000Z',
  };
  console.log(`config/cobranza → cuotaMensual: ${fmtMonto(cfg.cuotaMensual)} · fechaInicioCobro: ${cfg.fechaInicioCobro}`);
  console.log(`ultimoMesProcesado guardado: ${cfgFields.ultimoMesProcesado || '(sin valor — nunca ha corrido el cron)'}`);
  console.log('');

  const personas = (await listCollection(token, 'personas')).map(fsDocToPlain);
  const finanzas = (await listCollection(token, 'finanzas')).map(fsDocToPlain);

  const pagosPorCasa = new Map();
  for (const d of finanzas) {
    if (d.tipo !== 'ingreso' || d.categoria !== 'Cuota' || !d.casa) continue;
    const dn = normDomicilio(d.casa);
    if (!pagosPorCasa.has(dn)) pagosPorCasa.set(dn, []);
    pagosPorCasa.get(dn).push({ ts: d.ts, monto: d.monto || 0 });
  }

  const jefes = personas.filter(esJefe);
  console.log(`Jefes de familia en el padrón: ${jefes.length}`);
  console.log('');

  const filas = jefes.map(jefe => {
    const estado = calcularEstadoCuenta({ altaCasa: jefe.creadoEn, cfg, pagosCuotaPorCasa: pagosPorCasa.get(jefe.domicilioNorm) });
    return {
      nombre: jefe.nombre || '(sin nombre)',
      domicilio: jefe.domicilio || '(sin domicilio)',
      estadoActual: jefe.estado || 'activo',
      motivoSuspension: jefe.motivoSuspension || '(ausente)',
      ...estado,
    };
  }).sort((a, b) => b.adeudo - a.adeudo);

  console.log('=== Adeudo por casa (mayor a menor) ===');
  console.log('');
  filas.forEach(f => {
    console.log(`${f.nombre}  |  ${f.domicilio}  |  estado: ${f.estadoActual}  |  motivoSuspension: ${f.motivoSuspension}  |  meses: ${f.mesesTranscurridos}  |  adeudo: ${fmtMonto(f.adeudo)}`);
  });
  console.log('');

  const seSuspenderian = filas.filter(f => f.estadoActual === 'activo' && f.adeudo > 0);
  console.log(`=== Si aplicarSuspensionAutomatica corriera HOY en modo 'aplicar' ===`);
  console.log('');
  if (!seSuspenderian.length) {
    console.log('Ninguna casa activa tiene adeudo > 0 — hoy NO se suspendería a nadie.');
  } else {
    console.log(`Se suspenderían ${seSuspenderian.length} casa(s):`);
    seSuspenderian.forEach(f => console.log(`  ${f.nombre} (${f.domicilio}) — adeudo ${fmtMonto(f.adeudo)}`));
  }

  console.log('');
  console.log('Nada se escribió en Firestore. Este script es solo de lectura.');
}

main().catch(e => { console.error('Error:', e.message || e); process.exit(1); });
