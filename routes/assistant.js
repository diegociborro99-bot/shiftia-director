const express = require('express');

// ============================================================================
// Shiftia Assistant — endpoints deterministas (sin LLM, sin coste por consulta)
// Replica server-side la lógica mínima del motor IA que vive en public/index.html.
// Cada endpoint recibe { cell, context } desde la extensión y consulta el blob
// `data` (scheduleData + workers + crossPlantAssignments) del usuario.
// ============================================================================

const SP_RULES = {
  maxNightsPerMonth: 2,
  maxConsecutiveDays: 6,
  minWeeklyRestDays: 1
};

const PLANT_NAMES = {
  p1n: '1º Norte', p2n: '2º Norte', p2e: '2º Este', p3e: '3º Este',
  endo: 'Endoscopias', urg: 'Urgencias', refuerzo: 'Refuerzo'
};

const PLANT_COVERAGE = {
  p1n: { M: 2, T: 2, N: 2 }, p2n: { M: 2, T: 2, N: 2 },
  p2e: { M: 2, T: 2, N: 2 }, p3e: { M: 2, T: 2, N: 2 },
  endo: { M: 2, T: 2, N: 0 }, urg: { M: 3, T: 3, N: 2 },
  refuerzo: { M: 0, T: 0, N: 0 }
};

const SHIFT_CODES = ['M', 'T', 'N'];

// ===== Helpers =====
function ymKey(year, month) { return `${year}-${month}`; }
function cellOf(data, year, month, wId, day) {
  const arr = data?.scheduleData?.[ymKey(year, month)]?.[wId];
  if (!Array.isArray(arr) || day < 0 || day >= arr.length) return '';
  return arr[day] ?? '';
}
function workerById(data, id) {
  const all = (data?.workerMeta || data?.workers || []);
  // Match by id (legacy SARA autoincrement) OR by actaisId (cross-ref with Actais hospital ID)
  return all.find(w => String(w.id) === String(id) || String(w.actaisId || '') === String(id));
}
function getEffectivePlanta(data, wId, year, month, day) {
  const override = data?.crossPlantAssignments?.[ymKey(year, month)]?.[wId]?.[day];
  if (override) return override;
  return workerById(data, wId)?.planta || null;
}

// ===== Legality (versión reducida — para validación rápida server-side) =====
function checkLegality(data, worker, year, month, day, shift) {
  const reasons = [];
  let legal = true;

  if (!worker) return { legal: false, reasons: ['Trabajador no encontrado'] };

  // Regla 1: restricciones individuales
  if (worker.rules?.noNights && shift === 'N') {
    legal = false; reasons.push('No realiza noches (regla individual)');
  }
  if (worker.rules?.noCover) {
    legal = false; reasons.push('Trabajador marcado como "no cubre"');
  }

  // Regla 2: adyacencia N → M/T (post-noche)
  const prev = cellOf(data, year, month, worker.id, day - 1);
  if (prev === 'N' && (shift === 'M' || shift === 'T')) {
    legal = false; reasons.push(`Día anterior fue N: no se permite ${shift} (descanso post-noche)`);
  }

  // Regla 3: T → M día siguiente
  if (prev === 'T' && shift === 'M') {
    legal = false; reasons.push('Día anterior fue T: no se permite M (descanso mínimo)');
  }

  // Regla 4: noches/mes máximo
  if (shift === 'N') {
    const month_shifts = data?.scheduleData?.[ymKey(year, month)]?.[worker.id] || [];
    const nightCount = month_shifts.filter(s => s === 'N').length;
    const max = worker.rules?.maxNightsPerMonth ?? SP_RULES.maxNightsPerMonth;
    if (nightCount >= max) {
      legal = false; reasons.push(`Ya alcanzó ${nightCount}/${max} noches este mes`);
    }
  }

  // Regla 5: días consecutivos
  const monthSchedule = data?.scheduleData?.[ymKey(year, month)]?.[worker.id] || [];
  let consec = 0;
  for (let i = day; i >= 0 && monthSchedule[i] && !['L', 'D', 'VAC', 'LD'].includes(monthSchedule[i]); i--) consec++;
  if (consec > SP_RULES.maxConsecutiveDays) {
    legal = false; reasons.push(`Ya lleva ${consec} días consecutivos (máx ${SP_RULES.maxConsecutiveDays})`);
  }

  if (legal) reasons.push('Cumple las reglas evaluadas');
  return { legal, reasons };
}

// ===== Scoring básico (reutiliza concepto de scoreCandidate del cliente) =====
function scoreCandidate(data, worker, year, month, day, shift, targetPlanta) {
  let score = 0;
  const breakdown = [];

  if (worker.planta === targetPlanta) { score += 30; breakdown.push('Misma planta +30'); }
  else if (worker.flotante) { score += 20; breakdown.push('Flotante +20'); }
  else { score += 5; breakdown.push('Otra planta +5'); }

  const monthSchedule = data?.scheduleData?.[ymKey(year, month)]?.[worker.id] || [];
  const workedDays = monthSchedule.filter(s => SHIFT_CODES.includes(s)).length;
  const fatigue = Math.max(0, 30 - workedDays);
  score += fatigue; breakdown.push(`Carga del mes (descanso) +${fatigue}`);

  if (worker.rules?.preferredShift === shift) { score += 15; breakdown.push('Turno preferido +15'); }
  if (worker.rules?.conciliacion && shift === 'N') { score -= 20; breakdown.push('Conciliación familiar (noche) −20'); }

  const nightCount = monthSchedule.filter(s => s === 'N').length;
  if (shift === 'N') { score -= nightCount * 8; breakdown.push(`Noches ya hechas: −${nightCount * 8}`); }

  return { score: Math.max(0, Math.round(score)), breakdown };
}

// ===== detectFragilePlantas reducido =====
function detectFragilePlantas(data, todayY, todayM, todayD, daysAhead = 7) {
  const result = {};
  for (let offset = 0; offset < daysAhead; offset++) {
    const date = new Date(todayY, todayM, todayD + offset);
    const y = date.getFullYear();
    const m = date.getMonth();
    const d = date.getDate() - 1;
    const monthSchedules = data?.scheduleData?.[ymKey(y, m)] || {};

    for (const plantaId of Object.keys(PLANT_COVERAGE)) {
      if (plantaId === 'refuerzo') continue;
      for (const shift of SHIFT_CODES) {
        const required = PLANT_COVERAGE[plantaId][shift] || 0;
        if (required === 0) continue;
        let assigned = 0;
        for (const wId of Object.keys(monthSchedules)) {
          const cellShift = monthSchedules[wId][d];
          if (cellShift !== shift) continue;
          const effective = getEffectivePlanta(data, wId, y, m, d);
          if (effective === plantaId) assigned++;
        }
        const deficit = required - assigned;
        if (deficit > 0) {
          if (!result[plantaId]) result[plantaId] = { plantaId, name: PLANT_NAMES[plantaId], score: 0, gaps: [] };
          result[plantaId].score += deficit * 10 + (shift === 'N' ? 20 : 0);
          result[plantaId].gaps.push({ date: date.toISOString().slice(0, 10), shift, deficit });
        }
      }
    }
  }
  return Object.values(result).sort((a, b) => b.score - a.score);
}

// ===== Plantillas Secretario =====
function tplWhatsApp(worker, dateISO, shift, plantaId, requester) {
  const plantName = PLANT_NAMES[plantaId] || plantaId;
  const shiftName = { M: 'mañana', T: 'tarde', N: 'noche' }[shift] || shift;
  return `Hola ${worker?.name || ''}, ¿podrías cubrir el turno de ${shiftName} del ${dateISO} en ${plantName}? Gracias.
— ${requester || 'Supervisión'}`;
}

function tplReplacementRequest(workerOut, workerIn, dateISO, shift) {
  const shiftName = { M: 'Mañana', T: 'Tarde', N: 'Noche' }[shift] || shift;
  return `Solicitud de cambio de turno

Trabajador que se ausenta: ${workerOut?.name || '—'}
Trabajador que cubre: ${workerIn?.name || '—'}
Fecha: ${dateISO}
Turno: ${shiftName}

Motivo: [completar]
Validación de convenio: pendiente de revisión.`;
}

// ===== Helpers de routing =====
function parseCell(body) {
  const cell = body?.cell || {};
  return {
    year: Number.isFinite(cell.year) ? cell.year : new Date().getFullYear(),
    month: Number.isFinite(cell.month) ? cell.month : new Date().getMonth(),
    day: Number.isFinite(cell.day) ? cell.day : 0,
    shift: cell.shift || null,
    workerId: cell.workerId ?? cell.workerHint ?? null,
    workerName: cell.worker || null,
    plantaId: cell.plantaId || null
  };
}

async function loadData(pool, userId) {
  const result = await pool.query('SELECT data FROM schedule_data WHERE user_id = $1', [userId]);
  return result.rows[0]?.data || {};
}

function resolveWorker(data, parsed) {
  if (parsed.workerId) return workerById(data, parsed.workerId);
  if (parsed.workerName) {
    const norm = parsed.workerName.toUpperCase().normalize('NFD').replace(/[̀-ͯ]/g, '');
    return (data.workers || []).find(w => {
      const wn = (w.name || '').toUpperCase().normalize('NFD').replace(/[̀-ͯ]/g, '');
      return norm.includes(wn) || wn.includes(norm);
    });
  }
  return null;
}

// ============================================================================
// Router
// ============================================================================
function buildAssistantRouter({ pool, authMiddleware }) {
  const router = express.Router();
  router.use(express.json({ limit: '50kb' }));
  router.use(authMiddleware);

  router.post('/canChange', async (req, res) => {
    try {
      const data = await loadData(pool, req.user.id);
      const p = parseCell(req.body);
      const worker = resolveWorker(data, p);
      if (!worker) return res.json({ ok: false, reasons: ['No se pudo identificar al trabajador'] });
      const targetShift = p.shift || 'M';
      const result = checkLegality(data, worker, p.year, p.month, p.day, targetShift);
      res.json({ ok: result.legal, reasons: result.reasons, worker: worker.name, date: { year: p.year, month: p.month, day: p.day }, shift: targetShift });
    } catch (err) { res.status(500).json({ error: 'Error interno' }); console.error('[assistant.canChange]', err); }
  });

  router.post('/validateConvenio', async (req, res) => {
    try {
      const data = await loadData(pool, req.user.id);
      const p = parseCell(req.body);
      const worker = resolveWorker(data, p);
      if (!worker) return res.json({ legal: false, reasons: ['Trabajador no identificado'] });
      res.json(checkLegality(data, worker, p.year, p.month, p.day, p.shift || 'M'));
    } catch (err) { res.status(500).json({ error: 'Error interno' }); console.error('[assistant.validateConvenio]', err); }
  });

  router.post('/whoCovers', async (req, res) => {
    try {
      const data = await loadData(pool, req.user.id);
      const p = parseCell(req.body);
      const absentWorker = resolveWorker(data, p);
      const targetPlanta = p.plantaId || absentWorker?.planta;
      const targetShift = p.shift || 'M';
      if (!targetPlanta) return res.json({ candidates: [], note: 'Falta planta destino' });

      const candidates = (data.workers || [])
        .filter(w => w.id !== absentWorker?.id)
        .map(w => {
          const legality = checkLegality(data, w, p.year, p.month, p.day, targetShift);
          if (!legality.legal) return null;
          const scoring = scoreCandidate(data, w, p.year, p.month, p.day, targetShift, targetPlanta);
          return {
            workerId: w.id, name: w.name, planta: w.planta, flotante: !!w.flotante,
            crossPlant: w.planta !== targetPlanta,
            score: scoring.score, breakdown: scoring.breakdown
          };
        })
        .filter(Boolean)
        .sort((a, b) => b.score - a.score)
        .slice(0, 5);

      res.json({ targetPlanta, targetShift, candidates });
    } catch (err) { res.status(500).json({ error: 'Error interno' }); console.error('[assistant.whoCovers]', err); }
  });

  router.post('/suggestReplacement', async (req, res) => {
    // Alias semantico de whoCovers — extraido como funcion para evitar
    // depender de router.handle (que requiere next y rompe el contrato Express).
    req.url = '/whoCovers';
    return router.handle(req, res, () => {});
  });

  router.post('/librar', async (req, res) => {
    try {
      const data = await loadData(pool, req.user.id);
      const p = parseCell(req.body);
      const worker = resolveWorker(data, p);
      if (!worker) return res.json({ ok: false, error: 'Trabajador no identificado' });

      const originalShift = cellOf(data, p.year, p.month, worker.id, p.day);
      const targetPlanta = worker.planta;
      const monthSchedules = data?.scheduleData?.[ymKey(p.year, p.month)] || {};
      let coveringNow = 0;
      for (const wId of Object.keys(monthSchedules)) {
        const arr = monthSchedules[wId] || [];
        if (arr[p.day] === originalShift && getEffectivePlanta(data, wId, p.year, p.month, p.day) === targetPlanta) coveringNow++;
      }
      const required = PLANT_COVERAGE[targetPlanta]?.[originalShift] ?? 0;
      const willBecomeCritical = (coveringNow - 1) < required;

      res.json({
        ok: true, worker: worker.name, originalShift, plantaAffected: PLANT_NAMES[targetPlanta] || targetPlanta,
        currentCoverage: coveringNow, requiredCoverage: required,
        wouldGenerateGap: willBecomeCritical,
        suggestion: willBecomeCritical ? 'Librarle dejará un hueco crítico. Considera primero asignar sustituto.' : 'Se puede librar sin generar hueco.'
      });
    } catch (err) { res.status(500).json({ error: 'Error interno' }); console.error('[assistant.librar]', err); }
  });

  router.post('/vacaciones', async (req, res) => {
    try {
      const data = await loadData(pool, req.user.id);
      const p = parseCell(req.body);
      const days = Array.isArray(req.body?.days) ? req.body.days : [p.day];
      const worker = resolveWorker(data, p);
      if (!worker) return res.json({ ok: false, error: 'Trabajador no identificado' });
      const impacted = [];
      for (const d of days) {
        const shift = cellOf(data, p.year, p.month, worker.id, d);
        if (!SHIFT_CODES.includes(shift)) continue;
        impacted.push({ day: d, shift });
      }
      res.json({ ok: true, worker: worker.name, daysCount: days.length, workShiftsAffected: impacted, note: 'Pendiente sugerir sustitutos día a día — usa "¿Quién cubre?" en cada uno.' });
    } catch (err) { res.status(500).json({ error: 'Error interno' }); console.error('[assistant.vacaciones]', err); }
  });

  router.post('/cambio', async (req, res) => {
    try {
      const data = await loadData(pool, req.user.id);
      const p = parseCell(req.body);
      const worker = resolveWorker(data, p);
      if (!worker) return res.json({ ok: false, error: 'Trabajador no identificado' });
      const monthSchedules = data?.scheduleData?.[ymKey(p.year, p.month)] || {};
      const targetShift = p.shift || cellOf(data, p.year, p.month, worker.id, p.day);
      const swapPartners = (data?.workerMeta || data?.workers || [])
        .filter(w => w.id !== worker.id)
        .map(w => {
          const arr = monthSchedules[w.id] || [];
          const otherShift = arr[p.day];
          if (!otherShift || !SHIFT_CODES.includes(otherShift) || otherShift === targetShift) return null;
          const legA = checkLegality(data, worker, p.year, p.month, p.day, otherShift);
          const legB = checkLegality(data, w, p.year, p.month, p.day, targetShift);
          if (!legA.legal || !legB.legal) return null;
          return { partner: w.name, partnerId: w.id, currentShift: otherShift };
        })
        .filter(Boolean)
        .slice(0, 5);
      res.json({ targetShift, candidates: swapPartners });
    } catch (err) { res.status(500).json({ error: 'Error interno' }); console.error('[assistant.cambio]', err); }
  });

  router.post('/alternativas', async (req, res) => {
    try {
      const data = await loadData(pool, req.user.id);
      const p = parseCell(req.body);
      const planA = await getCandidates(data, p, 'multi');
      const planB = await getCandidates(data, p, 'balance');
      res.json({ planA, planB });
    } catch (err) { res.status(500).json({ error: 'Error interno' }); console.error('[assistant.alternativas]', err); }
  });

  async function getCandidates(data, p, strategy) {
    const worker = resolveWorker(data, p);
    const targetPlanta = p.plantaId || worker?.planta;
    const targetShift = p.shift || 'M';
    return (data.workers || [])
      .filter(w => w.id !== worker?.id)
      .map(w => {
        const legality = checkLegality(data, w, p.year, p.month, p.day, targetShift);
        if (!legality.legal) return null;
        const scoring = scoreCandidate(data, w, p.year, p.month, p.day, targetShift, targetPlanta);
        const extra = strategy === 'balance' ? -Math.abs((data?.scheduleData?.[ymKey(p.year, p.month)]?.[w.id] || []).filter(Boolean).length - 20) : 0;
        return { name: w.name, score: scoring.score + extra, breakdown: scoring.breakdown };
      })
      .filter(Boolean)
      .sort((a, b) => b.score - a.score)
      .slice(0, 3);
  }

  router.post('/fragilePlantas', async (req, res) => {
    try {
      const data = await loadData(pool, req.user.id);
      const now = new Date();
      const daysAhead = Number.isFinite(req.body?.daysAhead) ? req.body.daysAhead : 7;
      const fragile = detectFragilePlantas(data, now.getFullYear(), now.getMonth(), now.getDate(), daysAhead);
      res.json({ daysAhead, fragile });
    } catch (err) { res.status(500).json({ error: 'Error interno' }); console.error('[assistant.fragilePlantas]', err); }
  });

  router.post('/draftWhatsApp', async (req, res) => {
    try {
      const data = await loadData(pool, req.user.id);
      const p = parseCell(req.body);
      const worker = resolveWorker(data, p);
      // p.day llega 0-based (detector ya envia day-1). El constructor Date()
      // tambien usa day 1-based en su tercer argumento, asi que sumamos +1.
      const dateISO = new Date(p.year, p.month, p.day + 1).toISOString().slice(0, 10);
      const text = tplWhatsApp(worker, dateISO, p.shift || 'M', p.plantaId || worker?.planta, req.user?.name);
      res.json({ text });
    } catch (err) { res.status(500).json({ error: 'Error interno' }); console.error('[assistant.draftWhatsApp]', err); }
  });

  router.post('/draftReplacementRequest', async (req, res) => {
    try {
      const data = await loadData(pool, req.user.id);
      const p = parseCell(req.body);
      const workerOut = resolveWorker(data, p);
      const workerIn = req.body?.replacementId ? workerById(data, req.body.replacementId) : null;
      const dateISO = new Date(p.year, p.month, p.day + 1).toISOString().slice(0, 10);
      res.json({ text: tplReplacementRequest(workerOut, workerIn, dateISO, p.shift || 'M') });
    } catch (err) { res.status(500).json({ error: 'Error interno' }); console.error('[assistant.draftReplacementRequest]', err); }
  });

  router.post('/weeklySummary', async (req, res) => {
    try {
      const data = await loadData(pool, req.user.id);
      const now = new Date();
      const fragile = detectFragilePlantas(data, now.getFullYear(), now.getMonth(), now.getDate(), 7);
      const totalDeficit = fragile.reduce((sum, p) => sum + p.gaps.reduce((s, g) => s + g.deficit, 0), 0);
      res.json({
        weekStarts: now.toISOString().slice(0, 10),
        plantsAtRisk: fragile.length,
        totalGaps: totalDeficit,
        topRisks: fragile.slice(0, 3).map(f => ({ name: f.name, score: f.score, gapsCount: f.gaps.length }))
      });
    } catch (err) { res.status(500).json({ error: 'Error interno' }); console.error('[assistant.weeklySummary]', err); }
  });

  router.post('/conv_maxNights', (req, res) => res.json({ value: SP_RULES.maxNightsPerMonth, label: 'Máximo de noches por mes', source: 'Convenio interno (configurable por trabajador)' }));
  router.post('/conv_weeklyRest', (req, res) => res.json({ value: SP_RULES.minWeeklyRestDays, label: 'Días de descanso semanal mínimo', source: 'Convenio' }));
  router.post('/conv_consecDays', (req, res) => res.json({ value: SP_RULES.maxConsecutiveDays, label: 'Días consecutivos trabajados máximo', source: 'Convenio' }));

  router.post('/historyOnCase', (req, res) => {
    res.json({ note: 'Función pendiente: aún no hay corpus histórico indexado. En esta versión devuelve vacío.', cases: [] });
  });

  return router;
}

module.exports = { buildAssistantRouter };
