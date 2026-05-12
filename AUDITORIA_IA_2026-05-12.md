# Auditoría IA — Shiftia Director

**Fecha**: 2026-05-12
**Versión analizada**: v7.3.0
**Archivos**: `server.js` (1.626 LOC), `public/index.html` (~31.987 LOC).

> **Nota previa importante**: el `server.js` declara `multer` y `nodemailer` en deps, pero en realidad **no se usa nada de import en el backend** (no hay endpoint `/api/import/*`, ni multer mounted, ni xlsx). Toda la inteligencia vive en el cliente, en `public/index.html`. El servidor solo persiste el `schedule_data` como JSONB por usuario (`/api/data` → tabla `schedule_data`, `server.js:302-309`). Esto define muchas de las limitaciones que verás abajo.

---

## A. Estado actual

### 1. Sistema de import de planillas

Existe, pero **solo acepta PDFs** del formato propio del Hospital de Jove (planificación anual). No hay soporte de Excel ni CSV en absoluto:

- Entry point: `handleImport()` en `index.html:16656`. Solo escucha `accept=".pdf"` (`index.html:9164`).
- Parser real: `parsePDFFile()` en `index.html:15971`, basado en `pdf.js` (no hay `xlsx`/`sheetjs` cargados).
- El parser hace algo bastante artesanal pero ingenioso: extrae los items de texto con sus coordenadas `x/y`, agrupa por filas (`yBuckets`), localiza la columna "MES" y mapea cada celda a un día por proximidad de `x` (`xToDay`, línea 16111). Para cada mes detecta la fila válida puntuando candidatas: bonus por códigos de turno raros (T, N, MR…), penalty por filas que parecen días de la semana o headers numéricos (`index.html:16194-16241`).
- Página 2 del PDF se parsea con regex sueltos para sacar noches, cómputo, vacaciones, libre disposición, formación y horarios (`index.html:16272-16308`).

**Lo bueno**: maneja dos modos pdf.js (char-by-char vs pre-grouped), tiene logging diagnóstico potente, normaliza variantes de "Sin Planificar" → "SP".

**Lo frágil**: el algoritmo entero asume el layout exacto del PDF de Jove. Si el header "MES" no está, devuelve sin nada (línea 16080).

### 2. Detección automática de planta

**No existe**. La planta se asigna a mano en un modal cada vez que se importa una planilla:

- `showImportConfigModal(detectedName, matchedWorker)` en `index.html:16744` pide al director planta + rol + flotante + modalidad.
- El worker se persiste con `planta: importConfig.flotante ? null : importConfig.planta` (`index.html:16761`).
- En el header del PDF solo se intenta extraer la "categoría" (DUE/TCAE) buscando palabras como `SANITARIO|HEMATOLOGIA|LABORATORIO`, no se infiere planta (`parseRoleFromHeader`, `index.html:15963`).

Los nombres de planta están hardcoded para Jove (`index.html:9527`):
```
1º Norte, 2º Norte, 2º Este, 3º Este, Endoscopias, Urgencias, Plantilla Refuerzo
```

### 3. Matching del trabajador

`matchWorkerFromPDFName()` (`index.html:15895`) hace fuzzy match decente:
- Normaliza (uppercase + sin tildes).
- Si el nombre del PDF contiene/es contenido por uno existente → 100 puntos.
- Si no, suma 15 puntos por cada apellido (>=6 chars) que aparezca como palabra entera en ambos sentidos.
- Umbral mínimo: 15 puntos.

Es un matching simple pero efectivo para apellidos. Falla con nombres compuestos cortos o tildes raras.

### 4. Algoritmo de scheduling — Simulated Annealing v7.0

Vive en un IIFE en `index.html:30510-31200` ("SCHEDULE GENERATOR"). Resumen técnico:

- **Parámetros**: T0=100, Tmin=2, alpha = (Tmin/T0)^(1/iter), iter=2500 (1500 en mobile). Cooling exponencial. (`index.html:30725-30727`).
- **Vecinos** (`randomAssign`, línea 30685): elige worker aleatorio + día aleatorio + valor del pool {M, T, N, L}. Si hay plantilla seleccionada (Clásico, Solo M-T, Pack noches, Libre), 60% sesgo al patrón. NO toca celdas ya importadas que no sean SP (línea 30692, importante).
- **Función de coste** (`computeCost`, línea 30602):
  - **Cobertura**: `(min - working) * weights.coverage` por hueco. Comparación contra `PLANT_COVERAGE` por planta+turno+día.
  - **Equidad**: varianza de `loads`, `nights`, `weekends` × `weights.equity` (con multiplicadores 1.0/1.2/0.8).
  - **Convenio**: penalty muy fuerte (500-800 puntos) por adyacencias N→M, T→M, exceso de noches/mes (`SP_RULES.maxNightsPerMonth=2`) y exceso de días consecutivos (`maxConsecutiveDays=6`).
- **Aceptación**: clásica Metropolis: si `delta < 0` o `random() < exp(-delta/T)` se acepta, si no se revierte (`index.html:30742-30750`).
- **Async-friendly**: yield cada 16ms (60fps) con `setTimeout(step, 0)` para no bloquear la UI.
- KPIs después: cobertura %, equity 0-100 (varianza inversa), conflictos (adyacencias prohibidas), gaps absolutos.

Es un SA decente para 2500 iter en local. La ausencia de **reheat**, **vecindario tipo "swap"** y **constraint propagation** son las mejoras obvias (las dejo en el bloque C).

### 5. Sugerencia de coberturas — hay TRES sistemas distintos

Esto es importante porque hay duplicación:

**Sistema A — `suggestCoverageAssignment()`** (`index.html:9671`): muy básico. Filtra workers con SP ese día + tipo enfermera, suma bonus 100 si misma planta, 80 si flotante, +random. Devuelve top 3. Sin chequeo de convenio.

**Sistema B — Gestor SP (`renderSPManagerContent`)** (`index.html:12166`): enseña los SP por planta y para cada candidato calcula `getValidShifts()` que sí valida adyacencias (N→M, M→N), max noches/mes, max 6 consecutivos, descanso semanal. Calcula un `equityScore` con `getMultiMonthEquity` + `getAccumulatedFatigue` + penalización por SP-extras previos (`index.html:12286-12300`). Sortea por equidad.

**Sistema C — Generación de "Planes A/B/C/D"** (lógica de cobertura de bajas, `index.html:26000-26700`+): la más sofisticada. Construye un `virtualSchedule` (deep copy que se va actualizando) y para cada día rota por todos los workers con `isLegalAssignment()` que valida 7 reglas incluyendo cross-month (mira último día del mes anterior y primer día del siguiente para adyacencias N), max noches consecutivas bidireccional, whitelist de turnos válidos tras N. Si nadie es legal, intenta **reasignación bidireccional de turnos** (M→N, T→N, etc.) buscando excedentes en otros turnos del mismo día. Plan A=óptimo, B=alternativo, C=trade-offs, D=emergencia (rompe reglas, mínimas violaciones).

**Sistema D — `openSPAutoSuggest`** (`index.html:22600+`): cruza huecos de cobertura con SP workers en dos fases (Fase 1: cubrir mínimos por prioridad, Fase 2: distribuir SP restantes como refuerzo). Score considera burnout, equity, totalShifts, plant matching.

### 6. Restricciones de convenio implementadas

Dos bloques de constantes con valores **distintos** (deuda técnica clara):

```
RULES (index.html:10194)
  MAX_CONSECUTIVE_NIGHTS: 2
  MIN_REST_HOURS: 12  ← declarado pero nunca usado
  ANNUAL_HOURS: 1519
  NIGHT_COMPUTO_HOURS: 2.1

SP_RULES (index.html:12143)
  maxNightsPerMonth: 2
  maxNightsEmergency: 3
  maxConsecutiveDays: 6
  minWeeklyRestDays: 1
```

Reglas validadas en al menos 4 sitios distintos (`canAssignShift`, `getValidShifts`, `isLegalAssignment`, `computeCost`), con criterios ligeramente distintos. El `MIN_REST_HOURS` declarado nunca se calcula directamente — se aproxima vía adyacencias prohibidas (N→M, T→M).

### 7. Modelo de datos en Postgres (`server.js:233-332`)

- `users` (id, email, password_hash, name, company, plan, plan_status, workers_limit, next_billing_date).
- `schedule_data` (user_id UNIQUE, **data JSONB**, updated_at) — aquí va TODO el workspace de Sara como blob.
- `audit_logs` (user_id, action, details JSONB, ip).
- `schedule_backups` (user_id, data JSONB, backup_type).
- `support_tickets`, `bookings`, `contact_leads` (CRM/marketing).

**Punto clave**: no hay tablas separadas para `workers`, `plantas`, `shifts`, `coverage_rules`. Todo va serializado en `schedule_data.data`. Esto hace que el frontend tenga que cargar el JSON entero y no permite consultas analíticas, ni learning cross-cliente, ni feedback estructurado.

---

## B. Limitaciones de la IA actual

### Bloque 1 — Import de planillas

**Robustez a formatos**: nula fuera de Jove. No hay soporte Excel, CSV, ni de otros hospitales. Si Diego quiere vender Shiftia a otros clientes, tiene cero portabilidad.

**Detección de nombre**: razonable. La heurística `parsePDFFile` busca líneas con coma (formato "APELLIDO, NOMBRE") o líneas todo-mayúsculas que no sean keywords (`index.html:16053-16069`). Funciona en Jove. Falsos negativos: PDFs sin nombre en el header, nombres con tildes raras, formato distinto.

**Detección de planta**: cero. Se pide manualmente al director cada vez. Es la fricción más obvia que reduce velocidad de import.

**Códigos de turno no estándar**: rígido. `VALID_SHIFTS` está hardcoded con 28 códigos del convenio Jove (M, T, N, MR, M7H, M6R, M55, etc.). Si llegara M+, MN, T1 los descartaría sin avisar — silently dropped.

**Falsos positivos típicos**:
- Pre-grouped vs char-by-char detection puede fallar con nuevas versiones de pdf.js.
- Si el header del mes está mal alineado, devuelve cero turnos sin error claro.
- El score de fila válida (`bestScore`) puede confundir filas de header con filas de turnos en planillas con muchos M/D.

### Bloque 2 — Detección de errores de cobertura

**Cálculo**: bien implementado en `getCoverageGaps()` (`index.html:9631`) y `findCoverageGaps` del SA (`index.html:31174`). Cruzan `PLANT_COVERAGE[planta][shift].min` contra workers con `planta === planta.id` y turno match (con normalización M-variants → M).

**Mínimos por planta**: existen (línea 9550) pero hardcoded en JS. No hay UI para que el director los edite por planta+día+festivo+categoría desde la app — solo hay un override fin-de-semana global (`COVERAGE_WEEKEND`, línea 10202). Si Cardio necesita 4 enfermeras los lunes pero 2 los sábados, no se puede expresar.

**Categorías**: distingue `enf` vs `tec`/`tcae` vagamente, pero `PLANT_COVERAGE` solo cuenta total sin separar por categoría. La regla "2 enfermeras + 1 TCAE" no se puede modelar.

**Hipótesis no consideradas**: vacaciones futuras planificadas afectando cobertura, ratio paciente/enfermera dinámico, pico de carga estacional.

### Bloque 3 — Sugerencia inteligente de coberturas

Aquí Shiftia tiene lo mejor y lo peor de la app a la vez.

**Lo bueno**: el sistema de Planes A/B/C/D + virtual schedule + cross-month + reasignación bidireccional es genuinamente sofisticado y poco común en SaaS de turnos. Respeta convenio con bastante seriedad. La idea de que el plan D rompe reglas explícitamente y lo etiqueta es honesta y útil para el director.

**Lo malo**:
- **Tres sistemas de scoring distintos** sin un único criterio. Misma situación → tres rankings diferentes según qué pantalla mires.
- **Equidad superficial**: `equityScore` es ad-hoc (-15 si nightsDelta>2, -10 si hoursDelta>15). No usa indices reconocidos (Gini, varianza normalizada, etc.).
- **Preferencias de planta**: se respetan a nivel binario (misma planta → +100 puntos en suggestA, +20 en autoSuggest). No hay concepto de "planta hermana" graduado.
- **Sin learning de feedback**: cuando el director acepta o rechaza una sugerencia se loguea en `coverageHistory` (línea 9566) pero **nunca se lee para reentrenar**. No hay feature de "el director casi siempre rechaza a Marta para noches → bájala en el ranking". El feedback existe como dato muerto.
- **Sin explicación natural**: las razones son strings tipo `"Plan D — rompe 2 reglas"`. Útil pero plano. Un LLM puede hacerlo mucho mejor.
- **Sin consideración de skills/competencias**: no se modelan certificaciones (UCI vs planta, manejo de respiradores), antigüedad, mentor de residentes, etc.

---

## C. Propuesta de mejoras

### Bloque 1 — Import de planillas

**Quick wins (1-3h)**:

1. **Aceptar XLSX/CSV además de PDF**. Cargar `SheetJS` desde CDN (200KB), añadir branch en `handleImport()` que detecte extensión y use `XLSX.read()`. El parser puede ser más simple porque el layout de Excel es 2D nativo. Resuelve la limitación más bloqueante para vender fuera de Jove. Riesgo: bajo. Coste: 2h.

2. **Whitelist de códigos extensible**. Mover `VALID_SHIFTS` a un objeto editable por usuario en `schedule_data.data.customShiftCodes`. Añadir UI para mapear "M+" → "M" antes de procesar. Resuelve falsos positivos silenciosos. Coste: 2h.

3. **Modal de revisión post-import**. Antes de persistir, mostrar al director una previsualización tipo grid del calendario extraído con celdas en rojo si el parser no estaba seguro (score bajo). Permite corregir 5 celdas ambiguas vs reescribir todo. Coste: 3h.

**Mejoras estructurales (1-2 días)**:

4. **Detección automática de planta por contexto**. Si en el PDF aparece `HEMATOLOGIA` o `2 NORTE` o `URGENCIAS`, mapear a `planta.id` con un diccionario. Si no, comparar el nombre de archivo contra alias de planta. Si tampoco, **inferir por compañeros**: si los demás workers con apellidos vecinos (ya importados) son todos de "2N", proponer 2N por defecto en el modal. Coste: 1 día. Reduce 70% de la fricción del modal.

5. **Generic Excel template descargable**. Diego define un Excel "Shiftia Standard": filas=trabajadores, columnas=días, primera fila metadata (planta, mes, año). Los hospitales que no tienen planilla automatizada llenan ese template y lo suben. Multiplica por 5 los hospitales objetivo. Coste: 1 día (frontend + parser determinista).

**Salto cualitativo (rewrite parcial)**:

6. **Llamar a Claude/GPT-4o para parsear PDFs no estructurados**. Cuando `parsePDFFile` devuelve <10 turnos extraídos (señal de fallo), enviar el texto crudo del PDF al backend que lo pasa a un LLM con un prompt estructurado: "extrae nombre, año, planta inferida, calendario JSON". Caché por hash del PDF. Coste: 2 días + ~0.05€/PDF en API. Riesgo: privacidad — Diego, estás en hospital, tienes que filtrar PII antes de mandar al LLM o usar un modelo on-premise. Mi recomendación: mantenlo opcional, off por defecto, y solo para hospitales que firmen consentimiento.

### Bloque 2 — Detección de errores de cobertura

**Quick wins**:

7. **UI para editar `PLANT_COVERAGE` por planta+día-de-semana+festivo+categoría**. Hoy está hardcoded en línea 9550. Convertirlo en JSON editable por director, con interfaz tipo matriz 7x3 (días × turnos). Coste: 3h. Resuelve el "Cardio necesita 4 los lunes pero 2 los sábados".

8. **Separar coberturas por categoría enf/tec/tcae**. Cambiar el shape de `PLANT_COVERAGE[planta][shift]` de `{min: N}` a `{enf: N, tec: M, tcae: P}`. Adaptar `workingCount` (línea 30587) para contar por categoría. Coste: 3h. Hace los cálculos verdaderos en lugar de aproximados.

**Estructurales (1-2 días)**:

9. **Heatmap predictivo de riesgo de cobertura a 30 días**. Ya existe un gauge a 7 días (`renderCoverageRiskGauge`, línea 9694). Extenderlo a 30 días con visualización tipo GitHub contributions: cada día coloreado por `gap_count`. Permite ver patrones (lunes siempre rojos, agosto entero crítico). Coste: 1 día.

10. **Detección proactiva de "cobertura frágil"**: días donde la cobertura justo se cumple pero una sola baja la rompe. Cruzar plantilla actual con probabilidad histórica de bajas (incidencia mensual del worker pool). Etiquetar días "estables" / "frágiles" / "rotos". Coste: 1.5 días.

### Bloque 3 — Sugerencia inteligente de coberturas

**Quick wins**:

11. **Unificar los 3 sistemas de scoring** en una función `scoreCandidate(workerId, gap, context)` que devuelva `{score, breakdown[]}`. Llamarla desde `suggestCoverageAssignment`, `renderSPManagerContent` y planes A-D. Resuelve la inconsistencia de rankings. Coste: 3h. Refactor puro, no añade features pero te quita un dolor de cabeza enorme cuando Sara te pregunte por qué Marta sale primera en una pantalla y tercera en otra.

12. **Aprovechar el `coverageHistory` muerto**. Cuando se acepta o rechaza una sugerencia ya se loguea (línea 9566). Añadir factor "rejectionRate" al score: si Marta ha sido rechazada 5 de las últimas 8 veces que se le sugirió noche → penalty -20. Coste: 2h. Es learning trivial pero útil.

**Estructurales**:

13. **Modelo de equidad cuantificado**. Reemplazar el equity ad-hoc por un índice tipo coeficiente de Gini sobre 3 ejes (horas, noches, fines de semana) con ventana móvil de 90 días. Mostrar al director "índice de equidad: 0.18 (excelente) / 0.34 (aceptable) / >0.45 (problema)". Coste: 1 día. Te da un número defendible cuando un trabajador se queje.

14. **Modelo de skills/competencias por worker**. Añadir `worker.skills = ['UCI', 'respirador', 'mentor']`. Cada planta declara skills requeridas mínimas. El score de cobertura penaliza fuerte si la planta-objetivo requiere skill que el candidato no tiene. Coste: 1.5 días + tiempo de Sara para llenarlo (UI tipo chips toggle).

15. **Migrar `schedule_data` JSONB → tablas relacionales**. Crear `workers`, `plantas`, `shift_assignments`, `coverage_rules`, `feedback_events`. Permite analytics, queries SQL, indexes. Es trabajo gordo pero te desbloquea todo lo demás (ML real, dashboards multi-tenant, soporte de equipo). Coste: 2 días. Hazlo cuando vayas a por el segundo cliente.

**Salto cualitativo**:

16. **Generación de explicaciones con LLM**. Cuando se proponga una asignación, un endpoint backend manda al LLM contexto estructurado (`{worker, gap, history_last_30d, fairness_metrics, rules_violated}`) y el LLM devuelve 2-3 frases en español natural: "Sugiero a María porque lleva 3 fines de semana sin trabajar, vive cerca y ya cubrió este turno hace 2 meses sin queja." Coste: 1 día. Cambia la percepción del producto: pasa de "asistente algorítmico" a "consultor". Riesgo: alucinaciones — siempre incluir el breakdown numérico debajo de la explicación textual.

17. **Constraint solver real (OR-Tools/MiniZinc) opcional para mes completo**. El SA actual es OK pero se atasca en óptimos locales. Para meses con >40 trabajadores y >15 reglas, integrar un endpoint que use Google OR-Tools (Python microservicio) para resolver el problema como CP-SAT. Coste: 3 días + un microservicio en Python. Solo justificable si hay clientes grandes (>50 enfermeras).

18. **Reinforcement learning del scoring**. Entrenar offline un modelo (XGBoost simple primero) que aprenda de `coverageHistory` qué características predicen aceptación: `[same_plant, fairness_delta, recent_workload, day_of_week, ...]` → `accepted: 0/1`. Reemplazar los pesos hardcoded por el modelo. Coste: 3 días. No lo haría hasta tener 1000+ eventos de feedback acumulados.

---

## Top 5 priorizado (1 semana de Diego)

Pensado para máximo impacto/coste con tu nivel y tu stack actual:

**1. Refactor `scoreCandidate(workerId, gap, ctx)` único** — propuesta 11 (3h). Antes de añadir nada, deja de tener 3 IAs distintas peleándose. Es el unblocker para todo lo demás. Sin esto, cualquier mejora se va a desviar entre los 3 sistemas.

**2. Aprovechar `coverageHistory` para feedback loop** — propuesta 12 (2h). Tienes el dato, no lo usas. Penalty por rechazos repetidos. Es la diferencia entre IA "estática" e IA "que aprende" sin tocar arquitectura.

**3. Aceptar XLSX + template Shiftia descargable** — propuestas 1 + 5 (1 día). Sin esto, tu mercado es Hospital de Jove. Con esto, tu mercado es España.

**4. UI editable de `PLANT_COVERAGE` por planta+día+categoría** — propuestas 7 + 8 (medio día). Sin esto, cada vez que un cliente nuevo llegue tienes que tocarle el código. Con esto, onboarding es self-service.

**5. Modal de revisión post-import + heatmap 30 días** — propuestas 3 + 9 (1.5 días). Las dos pantallas que más confianza generan en el director: "veo lo que la IA leyó" y "veo dónde voy a tener problemas el mes que viene".

Todo esto cabe holgado en 5 días sin tocar el backend. El día sobrante lo dedicaría a empezar la propuesta 13 (equidad cuantificada) o a sentar las bases del 16 (explicaciones LLM con un prompt prototype).

Lo que **NO haría aún**: migrar a tablas relacionales (15), CP-SAT (17) o RL (18). Son grandes inversiones que no compran nada hasta que tengas tracción comercial. Hoy no es lo que te falta.

---

**Una observación final, sin azúcar**: el código tiene mucho músculo (sobre todo Planes A/B/C/D y el SA), pero el problema número uno no es algorítmico sino arquitectónico — la redundancia de 3 sistemas de scoring sin un único contrato. Cualquier mejora algorítmica que metas se va a fragmentar entre los 3 sitios. Refactoriza primero, sofistica después.
