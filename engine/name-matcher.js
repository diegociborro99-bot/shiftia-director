// ============================================================================
// Shiftia — name matcher V2 (server-side port)
// Originalmente en public/index.html (matchWorkerFromPDFNameV2). Portado aquí
// para que el endpoint /api/import/pdf-batch pueda hacer matching sin depender
// del cliente. Lógica idéntica: normalización + tokens + Levenshtein +
// Jaro-Winkler + initial bonus. Devuelve { match, confidence, candidates }.
// ============================================================================

function normalizeName(str) {
  if (!str) return '';
  return str
    .toLowerCase()
    .normalize('NFD').replace(/[̀-ͯ]/g, '')
    .replace(/[\.,;:\-_/\\()\[\]]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function tokenizeName(normalized) {
  const stop = new Set(['de', 'del', 'la', 'los', 'las', 'y', 'da', 'do', 'dos', 'das']);
  const raw = normalized.split(' ').filter(Boolean);
  const tokens = raw.filter(t => !stop.has(t));
  const compounds = [];
  for (let i = 0; i < raw.length - 1; i++) {
    if (stop.has(raw[i]) && raw[i + 1] && !stop.has(raw[i + 1])) {
      compounds.push(raw[i] + raw[i + 1]);
    }
  }
  return { tokens, compounds, all: [...new Set([...tokens, ...compounds])] };
}

function levenshtein(a, b) {
  if (a === b) return 0;
  if (!a.length) return b.length;
  if (!b.length) return a.length;
  let prev = new Array(b.length + 1);
  let curr = new Array(b.length + 1);
  for (let j = 0; j <= b.length; j++) prev[j] = j;
  for (let i = 1; i <= a.length; i++) {
    curr[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(curr[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost);
    }
    [prev, curr] = [curr, prev];
  }
  return prev[b.length];
}

function jaroWinkler(a, b) {
  if (a === b) return 1;
  if (!a.length || !b.length) return 0;
  const matchDist = Math.floor(Math.max(a.length, b.length) / 2) - 1;
  const aMatches = new Array(a.length).fill(false);
  const bMatches = new Array(b.length).fill(false);
  let matches = 0;
  for (let i = 0; i < a.length; i++) {
    const start = Math.max(0, i - matchDist);
    const end = Math.min(b.length, i + matchDist + 1);
    for (let j = start; j < end; j++) {
      if (bMatches[j] || a[i] !== b[j]) continue;
      aMatches[i] = true; bMatches[j] = true; matches++; break;
    }
  }
  if (!matches) return 0;
  let k = 0, transpositions = 0;
  for (let i = 0; i < a.length; i++) {
    if (!aMatches[i]) continue;
    while (!bMatches[k]) k++;
    if (a[i] !== b[k]) transpositions++;
    k++;
  }
  const m = matches;
  const jaro = (m / a.length + m / b.length + (m - transpositions / 2) / m) / 3;
  let prefix = 0;
  for (let i = 0; i < Math.min(4, a.length, b.length); i++) {
    if (a[i] === b[i]) prefix++; else break;
  }
  return jaro + prefix * 0.1 * (1 - jaro);
}

function matchWorker(pdfName, workers) {
  if (!pdfName || !workers?.length) {
    return { match: null, confidence: 0, candidates: [], pdfNorm: '' };
  }
  const pdfNorm = normalizeName(pdfName);
  const pdfTok = tokenizeName(pdfNorm);

  const scored = workers.map(w => {
    const wNorm = normalizeName(w.name || '');
    const wTok = tokenizeName(wNorm);
    let score = 0;
    const reasons = [];

    if (pdfNorm === wNorm) { score += 200; reasons.push('exacto'); }
    else if (pdfNorm.includes(wNorm) || wNorm.includes(pdfNorm)) { score += 100; reasons.push('contains'); }

    const sharedExact = pdfTok.all.filter(t => wTok.all.includes(t) && t.length >= 3);
    sharedExact.forEach(t => {
      const bonus = pdfTok.compounds.includes(t) || wTok.compounds.includes(t) ? 30 : 20;
      score += bonus;
      reasons.push(`token "${t}" +${bonus}`);
    });

    for (const pt of pdfTok.tokens) {
      if (pt.length < 4 || sharedExact.includes(pt)) continue;
      for (const wt of wTok.tokens) {
        if (wt.length < 4 || sharedExact.includes(wt)) continue;
        const dist = levenshtein(pt, wt);
        const sim = 1 - dist / Math.max(pt.length, wt.length);
        if (sim >= 0.85) { score += 15; reasons.push(`fuzzy "${pt}"~"${wt}" ${Math.round(sim*100)}%`); break; }
        if (sim >= 0.7) { score += 8; reasons.push(`fuzzy "${pt}"~"${wt}" ${Math.round(sim*100)}%`); break; }
      }
    }

    const jw = jaroWinkler(pdfNorm.replace(/ /g, ''), wNorm.replace(/ /g, ''));
    if (jw >= 0.92) { score += 30; reasons.push(`jw ${jw.toFixed(2)}`); }
    else if (jw >= 0.82) { score += 15; reasons.push(`jw ${jw.toFixed(2)}`); }

    for (const pt of pdfTok.tokens) {
      if (pt.length !== 1) continue;
      const initialMatch = wTok.tokens.find(wt => wt.startsWith(pt));
      if (initialMatch) { score += 10; reasons.push(`inicial ${pt}.→${initialMatch}`); break; }
    }

    return { worker: w, score: Math.round(score), reasons };
  });

  scored.sort((a, b) => b.score - a.score);
  const top = scored.slice(0, 3);
  const best = top[0];
  const confidence = best ? Math.min(100, best.score) : 0;
  const match = confidence >= 70 ? best.worker : null;

  return { match, confidence, candidates: top, pdfNorm };
}

module.exports = { matchWorker, normalizeName };
