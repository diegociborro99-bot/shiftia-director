const express = require('express');
const { matchWorker, normalizeName } = require('../engine/name-matcher');

// ============================================================================
// Shiftia Import — endpoint para subir planillas anuales en lote desde la
// extensión (o cualquier cliente). El parsing de PDFs se hace en el cliente;
// aquí solo recibimos el JSON estructurado, hacemos matching V2 con los
// workers existentes y mergeamos en data.workerMeta + data.scheduleData.
//
// Idempotente: re-subir el mismo PDF actualiza el plan del mes sin duplicar
// trabajadores. Si el matcher devuelve confidence < 70 marcamos el item como
// 'pending' y se lo devolvemos al cliente para que el gestor confirme.
// ============================================================================

function buildImportRouter({ pool, authMiddleware }) {
  const router = express.Router();
  router.use(express.json({ limit: '5mb' }));
  router.use(authMiddleware);

  router.post('/pdf-batch', async (req, res) => {
    if (!req.body || !Array.isArray(req.body.schedules)) {
      return res.status(400).json({ error: 'Falta schedules[]' });
    }
    const schedules = req.body.schedules;
    if (schedules.length === 0) return res.json({ ok: true, summary: 'sin planillas', items: [] });

    let data;
    try {
      const result = await pool.query('SELECT data FROM schedule_data WHERE user_id = $1', [req.user.id]);
      data = result.rows[0]?.data || {};
    } catch (err) {
      console.error('[import.pdf-batch] load:', err);
      return res.status(500).json({ error: 'No se pudo cargar la data del usuario' });
    }

    if (!data.workerMeta) data.workerMeta = [];
    if (!data.scheduleData) data.scheduleData = {};

    let nextId = data.workerMeta.reduce((m, w) => Math.max(m, parseInt(w.id, 10) || 0), 0) + 1;
    const items = [];

    for (const sched of schedules) {
      const item = processSchedule(data, sched, () => nextId++);
      items.push(item);
    }

    try {
      await pool.query(
        `INSERT INTO schedule_data (user_id, data) VALUES ($1, $2)
         ON CONFLICT (user_id) DO UPDATE SET data = $2`,
        [req.user.id, data]
      );
    } catch (err) {
      console.error('[import.pdf-batch] save:', err);
      return res.status(500).json({ error: 'No se pudo guardar la data del usuario' });
    }

    const summary = {
      processed: items.length,
      updated: items.filter(i => i.status === 'updated').length,
      created: items.filter(i => i.status === 'created').length,
      pending: items.filter(i => i.status === 'pending').length,
      failed: items.filter(i => i.status === 'failed').length
    };
    res.json({ ok: true, summary, items });
  });

  return router;
}

function processSchedule(data, sched, nextIdFn) {
  // Estructura esperada del cliente:
  // { filename, workerName, year, role, plantaHint, actaisId,
  //   scheduleByMonth: { 0: ['','','M7H',...], 1: [...], ... } }
  if (!sched || !sched.workerName || !sched.year || !sched.scheduleByMonth) {
    return { filename: sched?.filename, status: 'failed', reason: 'Datos incompletos' };
  }
  const monthsKeys = Object.keys(sched.scheduleByMonth);
  if (monthsKeys.length === 0) return { filename: sched.filename, status: 'failed', reason: 'Sin meses' };

  // Matching V2 contra workerMeta existente
  const matchResult = matchWorker(sched.workerName, data.workerMeta);

  let worker = matchResult.match;
  let status;

  if (worker) {
    // Match seguro: actualizar el worker existente
    status = 'updated';
    if (sched.actaisId) worker.actaisId = sched.actaisId;
    if (sched.role && !worker.role) worker.role = sched.role;
    if (sched.plantaHint && !worker.planta) worker.planta = sched.plantaHint;
  } else if (matchResult.confidence >= 40 && matchResult.candidates.length > 0) {
    // Match dudoso: devolver al cliente para confirmar manualmente
    return {
      filename: sched.filename,
      status: 'pending',
      workerName: sched.workerName,
      confidence: matchResult.confidence,
      candidates: matchResult.candidates.map(c => ({
        id: c.worker.id, name: c.worker.name, score: c.score
      }))
    };
  } else {
    // Sin match: crear worker nuevo
    worker = {
      id: nextIdFn(),
      name: sched.workerName,
      role: sched.role || 'enf',
      planta: sched.plantaHint || null,
      flotante: false,
      modalidad: 'fijo',
      rules: {},
      scheduleImported: true
    };
    if (sched.actaisId) worker.actaisId = sched.actaisId;
    data.workerMeta.push(worker);
    status = 'created';
  }

  // Merge de la planilla mes a mes
  const year = sched.year;
  let cellsMerged = 0;
  for (const monthStr of monthsKeys) {
    const month = parseInt(monthStr, 10);
    if (Number.isNaN(month) || month < 0 || month > 11) continue;
    const monthArr = sched.scheduleByMonth[monthStr];
    if (!Array.isArray(monthArr)) continue;
    const key = `${year}-${month}`;
    if (!data.scheduleData[key]) data.scheduleData[key] = {};
    data.scheduleData[key][worker.id] = monthArr.slice(0, 31);
    cellsMerged += monthArr.filter(Boolean).length;
  }

  return {
    filename: sched.filename,
    status,
    workerId: worker.id,
    workerName: worker.name,
    confidence: matchResult.confidence,
    cellsMerged
  };
}

module.exports = { buildImportRouter };
