/* ===========================================================
   Migración única: finanzas_borrados → finanzas_log

   Antes de "Finanzas protegidas" el master podía BORRAR movimientos; el Worker
   copiaba cada uno a finanzas_borrados/{id} con borradoPor/borradoNombre/borradoTs.
   Este script pasa esos respaldos a la bitácora nueva (finanzas_log) como entradas
   accion:'borrar', para que aparezcan en la vista "Historial" de la app.

   - NO toca finanzas ni finanzas_borrados (solo LEE esos dos y ESCRIBE en finanzas_log).
   - Idempotente: cada entrada usa el id fijo "borrado-<idDelMovimiento>" y se crea con
     la precondición "no existe" → correrlo dos veces no duplica nada.

   ⚠️  NO SE EJECUTA AUTOMÁTICAMENTE. Por defecto es DRY-RUN; escribir requiere --execute.

   Uso:
     node migrar-borrados-a-log.js             # dry-run: muestra qué migraría
     node migrar-borrados-a-log.js --execute   # escribe en finanzas_log

   Requiere las mismas variables de entorno que los otros scripts:
     FIREBASE_PROJECT, SA_EMAIL, SA_PRIVATE_KEY   (o bien: node run-with-sa.js <clave.json> migrar-borrados-a-log.js)
   =========================================================== */

const { saToken, fsBase, listCollection, fsFields } = require('./firestore-sa');

const EXECUTE = process.argv.includes('--execute');
const CAMPOS_BORRADO = ['borradoPor', 'borradoNombre', 'borradoTs'];

function resumen(id, d){
  const ref = d.folioRecibo || ('#' + id.slice(0, 6).toUpperCase());
  const signo = d.tipo === 'ingreso' ? '+' : '−';
  return `Borró ${ref} · ${signo}$${d.monto} · ${d.categoria || 'Otro'} · ${d.concepto || ''}${d.casa ? ' · ' + d.casa : ''}`;
}

async function main(){
  for (const v of ['FIREBASE_PROJECT', 'SA_EMAIL', 'SA_PRIVATE_KEY']){
    if (!process.env[v]) { console.error(`Falta la variable de entorno ${v}. Ver instrucciones al inicio del archivo.`); process.exit(1); }
  }
  console.log(EXECUTE ? '⚠️  MODO EJECUCIÓN — se va a escribir en finanzas_log.' : '🔎 MODO DRY-RUN — no se escribe nada.');

  const token = await saToken('https://www.googleapis.com/auth/datastore');
  const docs = await listCollection(token, 'finanzas_borrados');
  console.log(`Documentos en finanzas_borrados: ${docs.length}\n`);

  let creados = 0, yaEstaban = 0;
  for (const doc of docs){
    const id = doc.name.split('/').pop();
    const f = doc.fields || {};
    const d = fsFields(f);
    const antes = {};
    for (const k of Object.keys(f)) if (!CAMPOS_BORRADO.includes(k)) antes[k] = f[k];
    const texto = resumen(id, d);
    console.log(`  ${id}  |  ${d.borradoTs || '(sin fecha)'}  |  ${d.borradoNombre || '(sin nombre)'}  |  ${texto}`);
    if (!EXECUTE) continue;

    const fields = {
      movId: { stringValue: id },
      accion: { stringValue: 'borrar' },
      uid: { stringValue: d.borradoPor || '' },
      nombre: { stringValue: d.borradoNombre || '' },
      rol: { stringValue: 'master' },   // /finanzas/borrar solo lo permitía al master
      ts: f.borradoTs || { timestampValue: new Date().toISOString() },
      resumen: { stringValue: texto },
      motivo: { stringValue: '(borrado antes de existir "cancelar con motivo" — sin motivo registrado)' },
      antes: { mapValue: { fields: antes } },
      migrado: { booleanValue: true },
    };
    const r = await fetch(`${fsBase()}:commit`, {
      method: 'POST', headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
      body: JSON.stringify({ writes: [{
        update: { name: `projects/${process.env.FIREBASE_PROJECT}/databases/(default)/documents/finanzas_log/borrado-${id}`, fields },
        currentDocument: { exists: false },
      }] }),
    });
    if (r.ok) { creados++; continue; }
    const txt = await r.text();
    if (r.status === 409 || /ALREADY_EXISTS|FAILED_PRECONDITION/.test(txt)) { yaEstaban++; continue; }
    throw new Error(`Falló ${id}: ${r.status} ${txt}`);
  }

  console.log('');
  if (!EXECUTE) console.log('Dry-run terminado. Nada se escribió. Para aplicar: node migrar-borrados-a-log.js --execute');
  else console.log(`Listo. ${creados} entrada(s) nueva(s) en finanzas_log; ${yaEstaban} ya existían (sin cambios).`);
}

main().catch(e => { console.error('Error:', e.message || e); process.exit(1); });
