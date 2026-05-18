// ============================================================================
// Shiftia — parser para PDFs de planificación anual de Actais (Hospital de
// Jove). Toma el texto plano que devuelve `pdf-parse` y reconstruye la
// planilla del año en JSON estructurado.
//
// Formato del PDF (verificado con varios trabajadores):
//
//   APELLIDOS, NOMBRE          <- línea 1
//   SANITARIO - PLANTA - ROL   <- línea 2
//   2026                       <- año (línea 3 o cerca)
//   ...
//   MES 1 2 3 ... 31 Horas     <- header de tabla
//   Enero                      <- nombre del mes
//   J  D  V  CJ  S  N  ... 31 dias×2 tokens  88.00
//   Febrero
//   D  D  L  M  ...                          72.00
//   ...
//
// Cada mes intercala: día_semana (L/M/X/J/V/S/D, 1 char) + código_turno
// (1-4 chars). El último token del mes es decimal "XX.YY" (horas totales).
// El número de días depende del mes (28-31).
// ============================================================================

const DAY_OF_WEEK = new Set(['L', 'M', 'X', 'J', 'V', 'S', 'D']);
const MONTHS_ES = [
  'Enero', 'Febrero', 'Marzo', 'Abril', 'Mayo', 'Junio',
  'Julio', 'Agosto', 'Septiembre', 'Octubre', 'Noviembre', 'Diciembre'
];
const MONTH_TO_INDEX = MONTHS_ES.reduce((m, n, i) => { m[n.toLowerCase()] = i; return m; }, {});
const DAYS_IN_MONTH = (year, monthIdx) => new Date(year, monthIdx + 1, 0).getDate();

// Códigos de turno válidos (catálogo del calendario Actais).
// Si encontramos un token desconocido lo guardamos tal cual (mejor preservar
// que descartar). Solo descartamos cuando es claramente día de semana.
const HOURS_RE = /^\d+\.\d{2}$/;

function parsePlanningPdfText(rawText) {
  if (!rawText || typeof rawText !== 'string') {
    return { ok: false, error: 'Texto vacío' };
  }

  // pdf-parse separa con \n. Algunos PDFs (Actais) ponen "Enero J" en una sola
  // línea, así que aplanamos lineas + split por whitespace para tokenizar.
  const lines = rawText
    .split('\n')
    .map(l => l.trim())
    .filter(l => l.length > 0);

  // ===== 1. Cabecera: nombre, categoría, año =====
  if (lines.length < 4) return { ok: false, error: 'PDF demasiado corto' };

  const workerName = lines[0].trim();
  if (!/[A-ZÁÉÍÓÚÑa-záéíóúñ]/.test(workerName)) {
    return { ok: false, error: `No se reconoce el nombre en la línea 1: "${workerName}"` };
  }

  const categoryLine = lines[1] || '';
  // "SANITARIO - HEMATOLOGIA - DUE" -> { categoria: SANITARIO, plantaHint: HEMATOLOGIA, role: DUE }
  const catMatch = categoryLine.match(/^([^-]+?)\s*-\s*([^-]+?)\s*-\s*([^-]+)$/);
  let categoria = null, plantaHint = null, role = null;
  if (catMatch) {
    categoria = catMatch[1].trim();
    plantaHint = catMatch[2].trim();
    role = catMatch[3].trim();
  }

  // Año: línea con solo 4 dígitos
  let year = null;
  for (let i = 2; i < Math.min(10, lines.length); i++) {
    if (/^\d{4}$/.test(lines[i])) { year = parseInt(lines[i], 10); break; }
  }
  if (!year) return { ok: false, error: 'No se encontró el año en las primeras líneas' };

  // ===== 2. Encontrar el inicio de la tabla: "MES 1 2 3 ..." =====
  let tableStart = -1;
  for (let i = 0; i < lines.length; i++) {
    if (/^MES\s+1\s+2\s+3/.test(lines[i])) { tableStart = i + 1; break; }
  }
  if (tableStart === -1) return { ok: false, error: 'No se encontró la cabecera "MES 1 2 3 ..."' };

  // ===== 3. Tokenizar TODO desde tableStart hasta encontrar fin de tabla =====
  //
  // El fin de la tabla es donde aparece otra sección (Nº Noches Realizadas,
  // COMPUTO DE JORNADA, etc) o el final del documento.
  const TABLE_END_MARKERS = [
    /^N[ºo°]\s*Noches\s*Realizadas/i,
    /^COMPUTO\s*DE\s*JORNADA/i,
    /^Variables\s*de\s*convenio/i,
    /^Horarios/i,
    /^Resumen\s*de\s*d[íi]as/i,
    /^Relaciones\s*Laborales/i
  ];
  let tableEnd = lines.length;
  for (let i = tableStart; i < lines.length; i++) {
    if (TABLE_END_MARKERS.some(re => re.test(lines[i]))) { tableEnd = i; break; }
  }

  // Aplanar y re-tokenizar por whitespace (Actais a veces junta tokens).
  const tableTokens = [];
  for (const line of lines.slice(tableStart, tableEnd)) {
    const toks = line.split(/\s+/).filter(Boolean);
    tableTokens.push(...toks);
  }
  const tableLines = tableTokens;

  // ===== 4. Parsear cada mes =====
  //
  // Estado: leemos tokens secuencialmente. Cuando encontramos el nombre de un
  // mes, inicia un nuevo mes. Recogemos N días * 2 tokens + 1 horas. Si en
  // medio aparece otro nombre de mes, cerramos el anterior y abrimos el
  // siguiente.
  const scheduleByMonth = {};
  let currentMonth = null;     // 0-11
  let currentDayIndex = 0;     // 0-30
  let tokenSlot = 'dow';       // 'dow' (día semana) o 'shift' (turno)
  let monthHours = null;

  function commitMonth() {
    if (currentMonth == null) return;
    // Aseguramos array de 31 con relleno por '' si faltan
    if (!scheduleByMonth[currentMonth]) scheduleByMonth[currentMonth] = new Array(31).fill('');
  }

  for (const line of tableLines) {
    const token = line.trim();
    if (!token) continue;

    // ¿Nuevo mes?
    const monthIdx = MONTH_TO_INDEX[token.toLowerCase()];
    if (monthIdx != null) {
      commitMonth();
      currentMonth = monthIdx;
      currentDayIndex = 0;
      tokenSlot = 'dow';
      scheduleByMonth[currentMonth] = new Array(31).fill('');
      continue;
    }
    if (currentMonth == null) continue;

    // ¿Es total de horas (decimal)?
    if (HOURS_RE.test(token)) {
      // Asumimos que es el cierre del mes
      monthHours = parseFloat(token);
      // No reseteamos currentMonth porque puede que aparezca el siguiente Enero
      // sin haber acabado los 31 días (febrero solo tiene 28).
      currentDayIndex = 31; // marcamos cerrado
      continue;
    }

    // Token regular: día de semana o código de turno
    if (tokenSlot === 'dow') {
      // Esperamos día de semana (1 char L/M/X/J/V/S/D). Si NO es uno, asumimos
      // que se saltó algún token y lo tratamos como código.
      if (token.length === 1 && DAY_OF_WEEK.has(token.toUpperCase())) {
        tokenSlot = 'shift';
        continue;
      }
      // Token inesperado: lo registramos como código por tolerancia
      // pero seguimos el ciclo dow→shift
    }

    // tokenSlot === 'shift': es el código del turno
    if (currentDayIndex < 31) {
      scheduleByMonth[currentMonth][currentDayIndex] = token.toUpperCase();
      currentDayIndex++;
    }
    tokenSlot = 'dow';
  }
  commitMonth();

  // ===== 5. Recortar días extra de cada mes según el año =====
  for (const m of Object.keys(scheduleByMonth)) {
    const monthIdx = parseInt(m, 10);
    const days = DAYS_IN_MONTH(year, monthIdx);
    scheduleByMonth[m] = scheduleByMonth[m].slice(0, days).concat(new Array(31 - days).fill(''));
  }

  // ===== 6. Sanity check =====
  const monthsWithData = Object.values(scheduleByMonth).filter(arr =>
    arr.some(c => c && c !== '')
  ).length;

  if (monthsWithData === 0) {
    return { ok: false, error: 'No se extrajo ningún turno del PDF' };
  }

  return {
    ok: true,
    workerName,
    categoria,
    plantaHint,
    role,
    year,
    scheduleByMonth,
    monthsWithData
  };
}

module.exports = { parsePlanningPdfText };
