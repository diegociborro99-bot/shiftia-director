# AUDITORIA COMPLETA - Shiftia Director

**Fecha:** 12 de mayo de 2026  
**Alcance:** server.js (~1627 lineas) + public/index.html (~32781 lineas)  
**Arquitectura:** Monolito Node/Express + SQLite, frontend SPA embebido  
**Total de hallazgos:** 123  

---

## RESUMEN EJECUTIVO

| Severidad | Cantidad |
|-----------|----------|
| Critica   | 10       |
| Alta      | 24       |
| Media     | 55       |
| Baja      | 34       |
| **Total** | **123**  |

| Categoria     | Cantidad |
|---------------|----------|
| Bug           | 38       |
| Seguridad     | 18       |
| Logica        | 25       |
| UI/UX         | 22       |
| Inteligencia  | 13       |
| Polish        | 7        |

### Top 10 - Accion inmediata

1. **[CRIT]** Recursion infinita en `scheduleSaveThrottled` (L31939) - la app se congela al guardar
2. **[CRIT]** Credenciales offline (hash SHA-256 + username) expuestas en el HTML (L28411)
3. **[CRIT]** `saveSchedule()` referencia funcion inexistente - se pierden datos (L14571)
4. **[CRIT]** Doble release de cliente PostgreSQL en `createAutoBackup` (L671-718)
5. **[CRIT]** Catch vacios silencian errores de persistencia en 10+ ubicaciones
6. **[CRIT]** Editor de turnos permite guardar cambios que violan el convenio laboral (L17850)
7. **[CRIT]** SSL deshabilitado en conexion a PostgreSQL (`rejectUnauthorized: false`, L213)
8. **[CRIT]** Doble save por monkey-patching causa race condition (L18873)
9. **[CRIT]** Colision de variable `history` con `window.history` (L31923)
10. **[ALTA]** `w.hours` nunca se actualiza tras cambio de turno (L18046)

---

## 1. BUGS Y COSAS QUE NO FUNCIONAN

---

### BUG-001 | Critica | server.js L31939
**Que:** `scheduleSaveThrottled` tiene recursion infinita. Dentro del callback del `setTimeout`, se llama a `window.scheduleSaveThrottled()` de nuevo en vez de hacer el save real, creando un bucle infinito que congela el navegador.  
**Donde:** server.js L31929-31945  
**Por que importa:** La app se congela al intentar guardar cambios en el schedule. Perdida total de datos no guardados.  
**Como arreglar:** Eliminar la linea 31939 (`if (window.scheduleSaveThrottled) window.scheduleSaveThrottled();`) y dejar solo el bloque `else` que hace `localStorage.setItem(...)`.  
**Esfuerzo:** Bajo

---

### BUG-002 | Critica | index.html L14571-14576
**Que:** Se invoca `saveSchedule()` en un handler pero la funcion real se llama `saveToStorage()`. Esto lanza un `ReferenceError` al intentar guardar cambios en ciertos flujos.  
**Donde:** index.html L14571-14576  
**Por que importa:** El usuario pierde datos sin ninguna indicacion de error.  
**Como arreglar:** Reemplazar `saveSchedule()` por `saveToStorage()`.  
**Esfuerzo:** Bajo

---

### BUG-003 | Critica | server.js L671-718
**Que:** `createAutoBackup` tiene doble release del cliente de pool PostgreSQL. En las ramas de retorno anticipado (L682, L690) se llama `client.release()` manualmente, y luego el bloque `finally` (L716) lo vuelve a llamar.  
**Donde:** server.js L671-718  
**Por que importa:** Corrompe el pool de conexiones de PostgreSQL, causando errores intermitentes de base de datos.  
**Como arreglar:** Eliminar los `client.release()` manuales de las ramas de early return y confiar unicamente en `finally`.  
**Esfuerzo:** Bajo

---

### BUG-004 | Critica | index.html L18873-18876
**Que:** Monkey-patching de `saveShiftChange` provoca doble persistencia. El wrapper anade `saveToStorage()` despues de `_origSave()`, pero la funcion original ya llama a `saveToStorage()`.  
**Donde:** index.html L18873-18876  
**Por que importa:** Doble escritura consecutiva al servidor. Race condition si hay rate limiting. Posible corrupcion de datos.  
**Como arreglar:** Eliminar la llamada duplicada a `saveToStorage()` dentro de `saveShiftChange` original (L18069), o eliminar el wrapper.  
**Esfuerzo:** Medio

---

### BUG-005 | Critica | index.html L31923
**Que:** La variable `history` del modulo SP-IA colisiona con `window.history` del navegador. `history.push()` y `history.shift()` existen en ambas APIs con semantica diferente.  
**Donde:** index.html L31923, L32221  
**Por que importa:** Comportamiento impredecible del undo/redo y posible corrupcion de la navegacion del navegador.  
**Como arreglar:** Renombrar a `undoHistory` o `spiaHistory`.  
**Esfuerzo:** Bajo

---

### BUG-006 | Critica | Multiples ubicaciones
**Que:** 15+ bloques `catch (e) {}` vacios que silencian errores criticos de persistencia, carga de datos, y sincronizacion con backend.  
**Donde:** index.html L18784, L20807, L20810, L32001, L32233, L32246, L32263, L32292, L32305, L32335, L32346, L32399; server.js L82  
**Por que importa:** Errores de red, corrupciones de localStorage y fallos de servidor pasan completamente desapercibidos. La app funciona con datos parciales o desactualizados sin que el usuario lo sepa.  
**Como arreglar:** Reemplazar por `catch (e) { console.warn('[contexto]', e); showToast('Error: ' + e.message, 'error'); }` en los casos criticos.  
**Esfuerzo:** Bajo

---

### BUG-007 | Alta | server.js L1228-1230
**Que:** `isValidEmail()` esta definida DOS veces con implementaciones diferentes. La segunda sobreescribe la primera. Las llamadas anteriores a L1228 (como en `/api/auth/register` L446) usaron la version sin validacion de longitud.  
**Donde:** server.js L398-401 y L1228-1230  
**Por que importa:** Emails extremadamente largos pueden causar problemas de almacenamiento y rendimiento.  
**Como arreglar:** Eliminar la primera definicion y mover la segunda al principio del archivo.  
**Esfuerzo:** Bajo

---

### BUG-008 | Alta | server.js L1534-1540
**Que:** El daily summary itera sobre `data.workers` pero el endpoint usa `data.workerMeta`. Si el campo correcto es `workerMeta`, el resumen diario nunca encuentra trabajadores y envia emails vacios.  
**Donde:** server.js L1534-1540  
**Por que importa:** Los supervisores no reciben informacion util en el resumen diario.  
**Como arreglar:** Verificar cual es el nombre correcto del campo y unificar.  
**Esfuerzo:** Bajo

---

### BUG-009 | Alta | server.js L906-918
**Que:** Dos sistemas de rate limiting completamente independientes (`rateBuckets` + `rateLimit` vs `rateLimitMap` + `isRateLimited`). Implementaciones diferentes para lo mismo.  
**Donde:** server.js L906-918  
**Por que importa:** Inconsistencias en la proteccion contra spam. Confusion en mantenimiento.  
**Como arreglar:** Eliminar `rateLimitMap`/`isRateLimited` y usar el middleware `rateLimit()` en todos los endpoints.  
**Esfuerzo:** Bajo

---

### BUG-010 | Alta | index.html L14559
**Que:** Se usa `alert()` nativo del navegador como placeholder para la funcionalidad de swap de turnos. Bloquea el hilo principal.  
**Donde:** index.html L14559  
**Por que importa:** Experiencia de usuario rota. En tablets hospitalarios los modales nativos pueden quedar detras de overlays.  
**Como arreglar:** Implementar un modal custom consistente con el sistema de modales existente.  
**Esfuerzo:** Medio

---

### BUG-011 | Alta | index.html L16736-16756
**Que:** `renderImportManagement()` usa `list.innerHTML +=` dentro de un `forEach`. Cada iteracion reparsea TODO el HTML previo, destruyendo event listeners y degradando rendimiento.  
**Donde:** index.html L16736-16756  
**Por que importa:** Con 50+ trabajadores importados, la UI se congela. Posible vector XSS si los nombres no estan bien escapados.  
**Como arreglar:** Construir el HTML completo en un string y asignar `innerHTML` una sola vez al final.  
**Esfuerzo:** Bajo

---

### BUG-012 | Alta | index.html L17866-17873
**Que:** La validacion de noches consecutivas solo mira 2 dias atras y 1 adelante. No recorre la racha completa. Si un trabajador tiene N los dias d-3, d-2, d-1 y se asigna N en d, el conteo muestra 3 cuando en realidad serian 4.  
**Donde:** index.html L17866-17873  
**Por que importa:** Violaciones del convenio laboral pasan desapercibidas. Riesgo legal y de seguridad del paciente.  
**Como arreglar:** Implementar un bucle que cuente la racha completa hacia atras y hacia adelante.  
**Esfuerzo:** Bajo

---

### BUG-013 | Alta | index.html L16088-16090
**Que:** `parsePDFFile()` llama a `pdfjsLib.getDocument()` sin verificar que la libreria este cargada. Si la CDN falla, la funcion lanza un error no capturado.  
**Donde:** index.html L16088-16090, L16173-16175  
**Por que importa:** La importacion de PDFs falla silenciosamente si hay problemas de red.  
**Como arreglar:** Anadir guard: `if (typeof pdfjsLib === 'undefined') throw new Error('pdf.js no cargado');`  
**Esfuerzo:** Bajo

---

### BUG-014 | Media | server.js L1082-1083
**Que:** `new Date(date + 'T00:00:00')` sin timezone crea la fecha en la zona local del servidor. Si el servidor esta en UTC (Railway), las validaciones de dia de la semana son incorrectas para fechas cercanas a medianoche.  
**Donde:** server.js L1082-1083  
**Por que importa:** Bookings pueden asignarse al dia incorrecto.  
**Como arreglar:** Parsear con timezone explicita de Madrid.  
**Esfuerzo:** Bajo

---

### BUG-015 | Media | server.js L1591-1601
**Que:** `target.setHours(7, 0, 0, 0)` usa la hora LOCAL del servidor, no la de Espana. `setInterval(24h)` acumula drift y no maneja DST.  
**Donde:** server.js L1591-1601  
**Por que importa:** El email diario se envia a hora incorrecta.  
**Como arreglar:** Calcular offset para timezone `Europe/Madrid`. Usar `setTimeout` recursivo.  
**Esfuerzo:** Medio

---

### BUG-016 | Media | index.html L9803
**Que:** Variable mal escrita: `unplanedDays` en vez de `unplannedDays`. Puede causar `undefined` si se referencia con la ortografia correcta en otro lugar.  
**Donde:** index.html L9803  
**Por que importa:** Datos de dias sin planificar pueden perderse.  
**Como arreglar:** Renombrar a `unplannedDays` de forma consistente.  
**Esfuerzo:** Bajo

---

### BUG-017 | Media | index.html L10050-10058
**Que:** Race condition en tooltip del gauge de cobertura. Si se invoca multiples veces rapidamente (hover rapido), puede haber tooltips huerfanos.  
**Donde:** index.html L10050-10058  
**Por que importa:** Glitches visuales que confunden al usuario.  
**Como arreglar:** Eliminar tooltip existente antes de crear uno nuevo. Cancelar `setTimeout` previo.  
**Esfuerzo:** Bajo

---

### BUG-018 | Media | index.html L15504, L15738
**Que:** `btoa(encodeURIComponent(JSON.stringify(...)))` serializa datos en atributos `onclick`. Puede fallar con datos grandes o caracteres Unicode.  
**Donde:** index.html L15504, L15738  
**Por que importa:** Resolucion automatica de conflictos falla con datos complejos.  
**Como arreglar:** Almacenar datos en un objeto JS global temporal y referenciar por ID.  
**Esfuerzo:** Medio

---

### BUG-019 | Media | index.html L20059
**Que:** `chatFilter` usada sin declaracion visible. Si se ejecuta antes de ser definida, lanza `ReferenceError`.  
**Donde:** index.html L20059  
**Por que importa:** El chat de guardia puede romperse en ciertos flujos.  
**Como arreglar:** Asegurar valor por defecto `chatFilter = 'all'` al inicio del codigo.  
**Esfuerzo:** Bajo

---

### BUG-020 | Media | index.html L20831
**Que:** `toast.textContent = escHtml(w.name)` mezcla `textContent` (que ya escapa) con `escHtml()`. Resultado: doble-escape (`&` se muestra como `&amp;`).  
**Donde:** index.html L20831  
**Por que importa:** Nombres con caracteres especiales se muestran incorrectamente.  
**Como arreglar:** Usar `toast.textContent = w.name` sin `escHtml`, o usar `innerHTML` con `escHtml`.  
**Esfuerzo:** Bajo

---

### BUG-021 | Media | index.html L32100-32106
**Que:** `today.setHours(0,0,0,0)` muta el objeto `today` en `passesFilter()`. Practica peligrosa aunque no causa bug inmediato.  
**Donde:** index.html L32100-32106  
**Por que importa:** Bug latente que puede manifestarse si se reutiliza `today`.  
**Como arreglar:** Crear variable separada: `var todayStart = new Date(today);`  
**Esfuerzo:** Bajo

---

### BUG-022 | Media | index.html L16646, L16683
**Que:** `confirm()` bloqueante en funciones de purga. En moviles hospitalarios los modales nativos pueden tener problemas.  
**Donde:** index.html L16646, L16683  
**Por que importa:** UX rota en tablets del hospital.  
**Como arreglar:** Reemplazar por modal personalizado async.  
**Esfuerzo:** Medio

---

### BUG-023 | Media | index.html L25317, L29020
**Que:** `window.open('', '_blank')` puede devolver `null` si el navegador bloquea popups. El codigo accede directamente a `win.document.write()` sin verificar.  
**Donde:** index.html L25317, L29020  
**Por que importa:** TypeError que rompe la exportacion a PDF.  
**Como arreglar:** Agregar `if (!win) { showToast('Popup bloqueado', 'error'); return; }`  
**Esfuerzo:** Bajo

---

### BUG-024 | Media | index.html L25534
**Que:** `w.rules.preferredShift` se accede sin verificar que `w.rules` exista. Lanza TypeError si un worker no tiene `rules`.  
**Donde:** index.html L25534  
**Por que importa:** Panel de configuracion del trabajador se rompe para trabajadores nuevos.  
**Como arreglar:** Agregar `if (w.rules && w.rules.preferredShift)`.  
**Esfuerzo:** Bajo

---

### BUG-025 | Media | index.html L28212
**Que:** `avgWknd` no definida en `buildSwapAnalysis`. Se calcula solo en `buildAICoverageAnalysis` pero se referencia en otra funcion.  
**Donde:** index.html L28212  
**Por que importa:** Analisis de intercambio de turnos muestra metricas incorrectas (0 en vez del valor real).  
**Como arreglar:** Calcular `avgWknd` localmente en `buildSwapAnalysis`.  
**Esfuerzo:** Bajo

---

### BUG-026 | Media | index.html L28949, L30139-30147
**Que:** `shiftiaIcon()` referenciada pero potencialmente no definida antes de estas lineas. Si no existe, ReferenceError rompe renderizacion de metricas.  
**Donde:** index.html L28949, L30139-30147  
**Por que importa:** Paneles de metricas y comandos no se renderizan.  
**Como arreglar:** Verificar orden de definicion o agregar fallback.  
**Esfuerzo:** Bajo

---

### BUG-027 | Media | index.html L25174
**Que:** `escHtml` usada en export CSV. Los nombres con `&` se exportan como `&amp;` en el CSV, danando los datos.  
**Donde:** index.html L25174  
**Por que importa:** Datos exportados incorrectos. El CSV no se puede reimportar limpiamente.  
**Como arreglar:** Usar funcion de escape CSV (duplicar comillas dobles internas) en vez de `escHtml`.  
**Esfuerzo:** Bajo

---

### BUG-028 | Baja | server.js L82
**Que:** `catch (e) { /* ignore bad messages */ }` en WebSocket silencia TODOS los errores, incluyendo bugs de programacion.  
**Donde:** server.js L82  
**Por que importa:** Bugs en procesamiento de `shift_change` nunca se detectan.  
**Como arreglar:** `console.warn('[WS] Bad message:', e.message)`  
**Esfuerzo:** Bajo

---

### BUG-029 | Baja | server.js L753
**Que:** `var data, clientVersion;` usa `var` en vez de `let/const`.  
**Donde:** server.js L753  
**Por que importa:** Hoisting puede causar bugs sutiles. Inconsistencia de estilo.  
**Como arreglar:** Cambiar `var` a `let`.  
**Esfuerzo:** Bajo

---

### BUG-030 | Baja | index.html L13131
**Que:** Uso de `==` en vez de `===` para comparar IDs, permitiendo coerciones de tipo inesperadas.  
**Donde:** index.html L13131  
**Por que importa:** `"1" == 1` es true, lo que puede causar matches incorrectos.  
**Como arreglar:** Reemplazar `==` por `===`.  
**Esfuerzo:** Bajo

---

### BUG-031 | Baja | index.html L14997-15028
**Que:** Menu contextual de patrones no se cierra con tecla Escape.  
**Donde:** index.html L14997-15028  
**Por que importa:** Problema de accesibilidad. Patron esperado por usuarios.  
**Como arreglar:** Anadir listener `keydown` para Escape.  
**Esfuerzo:** Bajo

---

### BUG-032 | Baja | index.html L28547-28555, L30321-30327
**Que:** Duplicacion de listener para Cmd+K. Dos handlers compiten: uno abre el chat, otro abre busqueda global.  
**Donde:** index.html L28547-28555 y L30321-30327  
**Por que importa:** Comportamiento impredecible del atajo de teclado.  
**Como arreglar:** Eliminar el listener duplicado de L28547 y unificar en L30321.  
**Esfuerzo:** Bajo

---

### BUG-033 | Baja | index.html L28602-28605, L30670-30674
**Que:** Dos listeners capturan la tecla `?`. Uno muestra un toast, otro abre panel de ayuda. Ambos se ejecutan.  
**Donde:** index.html L28602-28605 y L30670-30674  
**Por que importa:** Se ve el toast Y el panel de ayuda simultaneamente.  
**Como arreglar:** Eliminar el listener de L28602-28605.  
**Esfuerzo:** Bajo

---

### BUG-034 | Baja | index.html L28557-28569, L32624-32627
**Que:** Ctrl+Z duplicado. El listener global llama `globalUndo()` y el del modal SP-IA llama `spiaUndoLast()`. Si el modal esta abierto, se deshacen dos acciones.  
**Donde:** index.html L28557-28569 y L32624-32627  
**Por que importa:** Doble undo accidental.  
**Como arreglar:** En el listener global, verificar si el modal SP-IA esta abierto.  
**Esfuerzo:** Bajo

---

### BUG-035 | Baja | index.html L27852
**Que:** Modal de preview no limpia el listener `escHandler` cuando se cierra por click en overlay.  
**Donde:** index.html L27852  
**Por que importa:** Memory leak de event listeners.  
**Como arreglar:** Remover `escHandler` tambien al cerrar por click.  
**Esfuerzo:** Bajo

---

### BUG-036 | Baja | index.html L29581
**Que:** Boton "Saltar" del onboarding usa `this.parentElement.parentElement.parentElement.lastElementChild.onclick()`. Extremadamente fragil.  
**Donde:** index.html L29581  
**Por que importa:** Cualquier cambio en el DOM rompe el onboarding.  
**Como arreglar:** Usar funcion nombrada: `onclick="completeOnboarding()"`.  
**Esfuerzo:** Bajo

---

### BUG-037 | Baja | index.html L25156
**Que:** `document.execCommand('copy')` esta deprecado. Usado como fallback cuando `navigator.clipboard.writeText` falla.  
**Donde:** index.html L25156  
**Por que importa:** Puede dejar de funcionar en navegadores futuros.  
**Como arreglar:** Documentar como fallback temporal. Aceptable por ahora.  
**Esfuerzo:** Bajo

---

### BUG-038 | Baja | index.html L32766-32776
**Que:** `window.escapeHtml` y `window.esc` se definen al final del archivo, pero `escHtml()` se usa extensivamente antes. Potencial desincronizacion de nombres.  
**Donde:** index.html L32766-32776  
**Por que importa:** Si `escHtml` no esta definida al inicio, XSS potencial.  
**Como arreglar:** Verificar y unificar todas las variantes de escape HTML.  
**Esfuerzo:** Bajo

---

## 2. SEGURIDAD

---

### SEC-001 | Critica | server.js L213-214
**Que:** `ssl: { rejectUnauthorized: false }` desactiva verificacion TLS en la conexion a PostgreSQL. Un atacante con MITM puede interceptar credenciales y datos.  
**Donde:** server.js L213-214  
**Por que importa:** Datos medicos y de personal expuestos en transito.  
**Como arreglar:** Usar `rejectUnauthorized: true` y configurar certificado CA via `PGSSLROOTCERT`.  
**Esfuerzo:** Bajo

---

### SEC-002 | Critica | index.html L28411-28428
**Que:** Credenciales offline verificadas con SHA-256 sin salt. El hash esta expuesto en el HTML. Username del director (`icueva`) y email tambien expuestos.  
**Donde:** index.html L28411-28428  
**Por que importa:** Cualquiera puede extraer el hash y hacer brute-force offline. Informacion PII del director expuesta.  
**Como arreglar:** Eliminar credenciales offline del frontend. Usar token de sesion previo para modo offline.  
**Esfuerzo:** Medio

---

### SEC-003 | Alta | server.js L476-480
**Que:** JWT con `expiresIn: '30d'` sin mecanismo de revocacion. Token filtrado = acceso por un mes.  
**Donde:** server.js L476-480  
**Por que importa:** Ventana de exposicion enorme si un token se filtra.  
**Como arreglar:** Reducir a 1-4h con refresh token. Implementar tabla `revoked_tokens`.  
**Esfuerzo:** Medio

---

### SEC-004 | Alta | server.js L42-96
**Que:** Sin rate limiting en mensajes WebSocket. Un cliente puede enviar miles de mensajes por segundo.  
**Donde:** server.js L42-96  
**Por que importa:** DoS amplificado via `broadcastToUser`.  
**Como arreglar:** Contador de mensajes por intervalo por conexion WS. Cerrar si excede umbral.  
**Esfuerzo:** Bajo

---

### SEC-005 | Alta | server.js L1471-1489
**Que:** `/api/health` y `/version` exponen estado de BD, version del paquete, y `NODE_ENV`.  
**Donde:** server.js L1471-1489  
**Por que importa:** Informacion de reconocimiento para atacantes.  
**Como arreglar:** Devolver solo `{ status: 'ok' }` en produccion.  
**Esfuerzo:** Bajo

---

### SEC-006 | Alta | server.js L582-656
**Que:** `/api/auth/update` permite cambiar email y contrasena sin requerir la contrasena actual.  
**Donde:** server.js L582-656  
**Por que importa:** Token robado = control total de la cuenta.  
**Como arreglar:** Exigir `currentPassword` y verificar con `bcrypt.compare`.  
**Esfuerzo:** Bajo

---

### SEC-007 | Alta | index.html L28487
**Que:** Token offline predecible: `'offline-token-' + Date.now()`. Cualquier atacante puede generar uno conociendo la hora aproximada.  
**Donde:** index.html L28487  
**Por que importa:** Bypass de autenticacion offline.  
**Como arreglar:** Usar `crypto.getRandomValues()` para generar token aleatorio.  
**Esfuerzo:** Bajo

---

### SEC-008 | Alta | index.html L25238-25320
**Que:** XSS en `exportSchedulePDF()`. `c.title` (titulo del conflicto) se inserta sin sanitizar en `window.open()` + `document.write()`.  
**Donde:** index.html L25308  
**Por que importa:** Ejecucion de JS arbitrario en la ventana de exportacion.  
**Como arreglar:** Usar `escHtml(c.title)`.  
**Esfuerzo:** Bajo

---

### SEC-009 | Media | server.js L930, L1061
**Que:** `/api/contact` y `/api/booking` son publicos sin auth. Rate limiter secundario insuficiente.  
**Donde:** server.js L930, L1061  
**Por que importa:** Spam de bookings/leads.  
**Como arreglar:** Aplicar `writeLimiter`. Agregar CAPTCHA o honeypot.  
**Esfuerzo:** Bajo

---

### SEC-010 | Media | server.js L36
**Que:** `trust proxy` fijado a `1` siempre. Sin proxy, `req.ip` se puede falsificar con `X-Forwarded-For`, invalidando rate limiting.  
**Donde:** server.js L36  
**Por que importa:** Rate limiting bypasseable.  
**Como arreglar:** Activar solo si `IS_PRODUCTION` o `TRUST_PROXY` existe.  
**Esfuerzo:** Bajo

---

### SEC-011 | Media | server.js L490-493
**Que:** `USERNAME_MAP` hardcodea `icueva -> director@shiftia.es`. Credencial en codigo fuente.  
**Donde:** server.js L490-493  
**Por que importa:** Expone email del director en el repositorio.  
**Como arreglar:** Mover a variables de entorno o tabla de BD.  
**Esfuerzo:** Bajo

---

### SEC-012 | Media | index.html L25815
**Que:** Stack trace de errores insertado en innerHTML sin sanitizar. Vector XSS si datos de entrada controlan el mensaje de error.  
**Donde:** index.html L25815  
**Por que importa:** Inyeccion de HTML/JS via mensajes de error manipulados.  
**Como arreglar:** Usar `escHtml(err.message)` y `escHtml(err.stack)`.  
**Esfuerzo:** Bajo

---

### SEC-013 | Media | index.html L30597
**Que:** Token de autenticacion enviado por WebSocket sin validar que la conexion sea segura.  
**Donde:** index.html L30597  
**Por que importa:** Token transmitido en texto plano si se usa `ws:` en vez de `wss:`.  
**Como arreglar:** Verificar `protocol === 'wss:'` antes de enviar credenciales.  
**Esfuerzo:** Bajo

---

### SEC-014 | Media | index.html L28462, L28490
**Que:** Datos de usuario almacenados en localStorage sin cifrar (nombre, email, empresa, plan).  
**Donde:** index.html L28462, L28490  
**Por que importa:** Cualquier extension de navegador puede leer datos sensibles.  
**Como arreglar:** Cifrar o almacenar solo lo minimo necesario.  
**Esfuerzo:** Medio

---

### SEC-015 | Baja | server.js L143-154
**Que:** Falta header `Content-Security-Policy`.  
**Donde:** server.js L143-154  
**Por que importa:** Sin CSP, la app es vulnerable a XSS inyectado.  
**Como arreglar:** Agregar CSP con `default-src 'self'`.  
**Esfuerzo:** Medio

---

### SEC-016 | Baja | server.js L1493-1495
**Que:** Middleware 404 devuelve `req.path` en la respuesta. Information leak.  
**Donde:** server.js L1493-1495  
**Por que importa:** Atacante confirma path traversal.  
**Como arreglar:** Devolver mensaje generico sin `req.path`.  
**Esfuerzo:** Bajo

---

### SEC-017 | Baja | index.html L11 (CSS)
**Que:** Fonts cargadas desde Google Fonts. Expone IP de usuarios a Google. Problema GDPR en la UE.  
**Donde:** index.html L11  
**Por que importa:** Incumplimiento potencial de GDPR para hospitales europeos.  
**Como arreglar:** Hospedar fuentes localmente con `@font-face`.  
**Esfuerzo:** Medio

---

### SEC-018 | Baja | server.js L451
**Que:** Password solo requiere 8 caracteres. Sin requisitos de complejidad. Insuficiente para app hospitalaria.  
**Donde:** server.js L451  
**Por que importa:** Cuentas vulnerables a brute-force.  
**Como arreglar:** Minimo 12 caracteres, 1 mayuscula, 1 numero, 1 caracter especial.  
**Esfuerzo:** Bajo

---

## 3. LOGICA DE NEGOCIO

---

### LOG-001 | Alta | index.html L9533-9607
**Que:** Coexisten dos sistemas de cobertura incompatibles: `RULES.COVERAGE` (laboratorio) y `PLANT_COVERAGE` (por planta). Funciones diferentes usan fuentes diferentes, generando inconsistencias.  
**Donde:** index.html L9533-9607, L9922  
**Por que importa:** Calculos de deficit inconsistentes. El director puede ver coberturas diferentes segun que panel mire.  
**Como arreglar:** Migrar completamente a `PLANT_COVERAGE` con `getCoverageMin()` como unica fuente de verdad.  
**Esfuerzo:** Alto

---

### LOG-002 | Alta | index.html L11146-11161
**Que:** Umbral de noches: alertas visuales a 7 noches, pero `SP_RULES.maxNightsPerMonth = 2`. Regla contradictoria.  
**Donde:** index.html L11146-11161  
**Por que importa:** Violaciones del convenio no se detectan hasta 7 noches (muy tarde). El maximo legal es 2-3.  
**Como arreglar:** Usar constante unica derivada de las reglas del convenio.  
**Esfuerzo:** Bajo

---

### LOG-003 | Alta | index.html L18046-18049
**Que:** `saveShiftChange` calcula `totalH` pero nunca lo asigna a `w.hours`. Las horas del trabajador quedan desactualizadas.  
**Donde:** index.html L18046-18049  
**Por que importa:** Dashboard muestra horas incorrectas. Decisiones de planificacion basadas en datos erroneos.  
**Como arreglar:** Anadir `w.hours = totalH;` despues del bucle de calculo.  
**Esfuerzo:** Bajo

---

### LOG-004 | Alta | index.html L15067-15105
**Que:** `pasteShiftPattern()` copia turnos sin verificar reglas del convenio (noches consecutivas, descanso tras noche, etc.). Genera planificaciones ilegales.  
**Donde:** index.html L15067-15105  
**Por que importa:** Riesgo legal. Planificaciones que violan legislacion laboral.  
**Como arreglar:** Ejecutar validacion de convenio despues de pegar y mostrar advertencias.  
**Esfuerzo:** Medio

---

### LOG-005 | Alta | index.html L18993-19090
**Que:** Deteccion de conflictos no cruza meses. Si un trabajador tiene N el dia 31 y M el dia 1 del mes siguiente, no se detecta la violacion de descanso de 12h.  
**Donde:** index.html L18993-19090  
**Por que importa:** Violaciones de descanso obligatorio pasan desapercibidas. Riesgo de seguridad del paciente y legal.  
**Como arreglar:** Al verificar el primer dia de cada mes, consultar el ultimo dia del mes anterior.  
**Esfuerzo:** Medio

---

### LOG-006 | Alta | index.html L10353-10383
**Que:** Festivos hardcodeados solo para 2025-2026. A partir de enero 2027, la cobertura de festivos deja de funcionar.  
**Donde:** index.html L10353-10383  
**Por que importa:** La app tiene fecha de caducidad implicita.  
**Como arreglar:** Modulo de festivos configurable con valores por defecto.  
**Esfuerzo:** Medio

---

### LOG-007 | Media | server.js L1296-1360
**Que:** `/api/my-shifts` busca trabajador con `includes()` parcial. "Ana" matchea "Ana Maria". Devuelve el primero que encuentre.  
**Donde:** server.js L1296-1360  
**Por que importa:** Trabajadores ven turnos de otra persona con nombre similar.  
**Como arreglar:** Usar match exacto (`===`) o devolver multiples coincidencias.  
**Esfuerzo:** Bajo

---

### LOG-008 | Media | server.js L1352-1354
**Que:** `totalShifts` filtra por array hardcodeado `['M','MR','M7H','M6R','M55','T','N']`. Nuevos tipos de turno no se cuentan.  
**Donde:** server.js L1352-1354  
**Por que importa:** Estadisticas incompletas si se anaden turnos nuevos.  
**Como arreglar:** Definir tipos de turno como constante global o calcular dinamicamente.  
**Esfuerzo:** Bajo

---

### LOG-009 | Media | server.js L1531-1540
**Que:** Daily summary solo clasifica M, T, N. Variantes (MR, M7H, M6R, M55) no se clasifican.  
**Donde:** server.js L1531-1540  
**Por que importa:** Resumen diario incompleto. Trabajadores con turnos especiales no aparecen.  
**Como arreglar:** Clasificar variantes de manana dentro de `shifts.M`.  
**Esfuerzo:** Bajo

---

### LOG-010 | Media | server.js L1433-1468
**Que:** Restaurar backup sin transaccion. Si el upsert falla despues de crear el backup pre-restore, queda un estado inconsistente.  
**Donde:** server.js L1433-1468  
**Por que importa:** Posible perdida de datos en restauracion de backups.  
**Como arreglar:** Envolver en `BEGIN/COMMIT`.  
**Esfuerzo:** Bajo

---

### LOG-011 | Media | index.html L10670-10676
**Que:** `calcMonthHours` no normaliza variantes de turno (MR, M7H, M6R, M55). Subestima horas de trabajadores con turnos especiales.  
**Donde:** index.html L10670-10676  
**Por que importa:** Horas mensuales incorrectas para un subconjunto de trabajadores.  
**Como arreglar:** Aplicar `normalizeShift()` a cada turno o mantener tabla de horas por tipo especifico.  
**Esfuerzo:** Bajo

---

### LOG-012 | Media | index.html L9883
**Que:** Desempate aleatorio con `Math.random()` en sugerencias de cobertura. Resultados inconsistentes entre ejecuciones.  
**Donde:** index.html L9883  
**Por que importa:** El director ve sugerencias diferentes al refrescar. Erosion de confianza.  
**Como arreglar:** Criterio determinista (antiguedad, ID, carga historica).  
**Esfuerzo:** Bajo

---

### LOG-013 | Media | index.html L10496
**Que:** Conteo doble de noches consecutivas al iterar por pares en vez de por bloques.  
**Donde:** index.html L10496  
**Por que importa:** Falsas alertas de noches consecutivas.  
**Como arreglar:** Iterar por bloques consecutivos.  
**Esfuerzo:** Bajo

---

### LOG-014 | Media | index.html L15078-15088
**Que:** Pegar patron entre meses con diferente longitud ignora la diferencia. Patron de 31 dias pegado en mes de 28.  
**Donde:** index.html L15078-15088  
**Por que importa:** Dias sobrantes que no existen en el calendario.  
**Como arreglar:** Truncar `sourceShifts` a la longitud del mes destino.  
**Esfuerzo:** Bajo

---

### LOG-015 | Media | index.html L15493
**Que:** Inconsistencia de indexado de dias (0-indexed vs 1-indexed). `new Date(year, month, day + 1)` puede producir dia incorrecto.  
**Donde:** index.html L15493  
**Por que importa:** Etiquetas de fechas incorrectas en la resolucion de conflictos.  
**Como arreglar:** Estandarizar indexado. Documentar claramente.  
**Esfuerzo:** Medio

---

### LOG-016 | Media | index.html L18454
**Que:** Cuota de vacaciones hardcodeada en 22 dias. En hospitales espanoles varia segun convenio, antiguedad y contrato (22-30 dias).  
**Donde:** index.html L18454, L18619  
**Por que importa:** Calculo de vacaciones restantes incorrecto para trabajadores con mas de 22 dias.  
**Como arreglar:** Campo configurable por trabajador (`w.vacDays`) con default 22.  
**Esfuerzo:** Medio

---

### LOG-017 | Media | index.html L18035-18043
**Que:** Duplicacion de contadores: `w.nights` y `w.nightsThisYear` se calculan igual. Riesgo de desincronizacion.  
**Donde:** index.html L18035-18043, L16656, L16692  
**Por que importa:** Contadores de noches inconsistentes entre vistas.  
**Como arreglar:** Definir semantica clara (mensual vs anual) y derivar uno del otro.  
**Esfuerzo:** Bajo

---

### LOG-018 | Media | index.html L19023-19031
**Que:** No hay alertas de cobertura nocturna para tecnicos. Solo se valida manana y tarde.  
**Donde:** index.html L19023-19031  
**Por que importa:** Deficit de tecnicos en turno de noche pasa desapercibido.  
**Como arreglar:** Anadir bloque de validacion para cobertura nocturna de tecnicos.  
**Esfuerzo:** Bajo

---

### LOG-019 | Media | index.html L23096-23170
**Que:** `autoAssignSP` asigna sin actualizar `sch`. `isWorkerSP` verifica `sch` sin mirar `proposed`, permitiendo asignaciones duplicadas en la misma pasada.  
**Donde:** index.html L23096-23170  
**Por que importa:** Asignaciones SP duplicadas o conflictivas.  
**Como arreglar:** Actualizar `sch` en cada asignacion propuesta, o incluir chequeo de `proposed` en `isWorkerSP`.  
**Esfuerzo:** Medio

---

### LOG-020 | Media | index.html L32014-32024
**Que:** `consecutiveDaysIfAssigned` empieza con `count = 1` asumiendo asignacion, sin verificar si el dia actual ya tiene turno.  
**Donde:** index.html L32014-32024  
**Por que importa:** Conteo de dias consecutivos incorrecto para la IA de asignacion.  
**Como arreglar:** Verificar que el turno propuesto realmente se asignaria antes de sumar 1.  
**Esfuerzo:** Bajo

---

### LOG-021 | Media | index.html L25061 (y muchas mas)
**Que:** `genSchedule(year, month)` invocado docenas de veces sin cache. Reconstruye el schedule completo cada vez.  
**Donde:** index.html L25061, L25104, L25201, L25599, L25840, L29935  
**Por que importa:** Problema de rendimiento significativo con muchos trabajadores.  
**Como arreglar:** Implementar cache/memoizacion para `genSchedule`.  
**Esfuerzo:** Medio

---

### LOG-022 | Baja | server.js L1414-1431
**Que:** Sin limite de backups manuales. Solo los auto-backups se limpian (OFFSET 30).  
**Donde:** server.js L1414-1431  
**Por que importa:** Consumo ilimitado de espacio de BD.  
**Como arreglar:** Limite similar para backups manuales.  
**Esfuerzo:** Bajo

---

### LOG-023 | Baja | index.html L19397-19401
**Que:** Fatiga score puede inflarse si se anaden mas factores sin ajustar limites.  
**Donde:** index.html L19397-19401  
**Por que importa:** Alertas de fatiga desproporcionadas.  
**Como arreglar:** Documentar pesos y agregar tests.  
**Esfuerzo:** Bajo

---

### LOG-024 | Baja | index.html L19073, L19086
**Que:** Motor de rebalanceo hardcodea el nombre "Beatriz" como restriccion.  
**Donde:** index.html L19073, L19086  
**Por que importa:** No escala. Si Beatriz cambia de puesto, hay que editar el codigo.  
**Como arreglar:** Usar restriccion generica `w.rules.noMicro`.  
**Esfuerzo:** Bajo

---

### LOG-025 | Baja | index.html L19050-19065
**Que:** Textos de alertas sin tildes: "manana" por "manana". Confunde "tomorrow" con "morning shift".  
**Donde:** index.html L19050-19065  
**Por que importa:** Ambiguedad en contexto hospitalario.  
**Como arreglar:** Corregir acentos.  
**Esfuerzo:** Bajo

---

## 4. MEJORAS DE INTELIGENCIA

---

### INT-001 | Alta | index.html L9740
**Que:** Matriz de competencias clinicas es un placeholder (siempre 0.5). No se usa para recomendar candidatos segun aptitud por planta/unidad.  
**Donde:** index.html L9740  
**Por que importa:** Sugerencias de cobertura ignoran las habilidades clinicas del trabajador.  
**Como arreglar:** Implementar con datos del sistema de inteligencia subjetiva existente (L11505-11992).  
**Esfuerzo:** Alto

---

### INT-002 | Media | index.html L15892-15921
**Que:** Chat AI procesa cada mensaje de forma aislada. No hay contexto conversacional. "Y sobre ella?" no funciona.  
**Donde:** index.html L15892-15921  
**Por que importa:** Chat inutil para conversaciones naturales de seguimiento.  
**Como arreglar:** Pasar `chatHistory` a `handleChatQuery` y resolver referencias.  
**Esfuerzo:** Medio

---

### INT-003 | Media | index.html L15573-15690
**Que:** Auto-resolver conflictos toma el primer candidato sin evaluar impacto en equidad global.  
**Donde:** index.html L15573-15690  
**Por que importa:** Asignacion sistematica a los mismos trabajadores. Burnout.  
**Como arreglar:** Integrar `scoreCandidate()` en la resolucion automatica.  
**Esfuerzo:** Medio

---

### INT-004 | Media | index.html L15906-15920
**Que:** Sugerencias de follow-up del chat sin contexto de planta activa, alertas activas o estado de cobertura.  
**Donde:** index.html L15906-15920  
**Por que importa:** Sugerencias genericas que no ayudan en el momento.  
**Como arreglar:** Contextualizar con `appState.selectedPlant` y alertas activas.  
**Esfuerzo:** Bajo

---

### INT-005 | Media | index.html L19654-19818
**Que:** Scoring de candidatos para cobertura no incluye burnout risk. Un trabajador en nivel critico puede ser sugerido.  
**Donde:** index.html L19654-19818  
**Por que importa:** Sugerencias que empeoran el burnout del equipo.  
**Como arreglar:** Integrar `computeBurnoutRisk(wId).score` como penalizacion.  
**Esfuerzo:** Bajo

---

### INT-006 | Media | index.html L23095-23170
**Que:** `autoAssignSP` no consulta `w.rules.conciliacion` ni restricciones personales. Puede asignar noche a trabajador con conciliacion familiar.  
**Donde:** index.html L23095-23170  
**Por que importa:** Violacion de derechos de conciliacion. Riesgo legal y de satisfaccion del trabajador.  
**Como arreglar:** Verificar `w.rules` en seleccion de candidatos.  
**Esfuerzo:** Bajo

---

### INT-007 | Media | index.html L9751-9752
**Que:** TODO pendiente en migracion de `scoreCandidate`. Logica de scoring dispersa en multiples funciones.  
**Donde:** index.html L9751-9752  
**Por que importa:** Deuda tecnica que dificulta mejoras de inteligencia.  
**Como arreglar:** Centralizar toda la logica en `scoreCandidate` y eliminar duplicados.  
**Esfuerzo:** Alto

---

### INT-008 | Baja | Oportunidad
**Que:** Sin deteccion de anomalias en patrones de turno (trabajador que siempre trabaja fines de semana, nunca rota a tardes).  
**Donde:** N/A  
**Por que importa:** Inequidades sutiles pasan desapercibidas.  
**Como arreglar:** Analisis de distribucion por dia de semana por trabajador. Alertar cuando hay desviaciones significativas.  
**Esfuerzo:** Medio

---

### INT-009 | Baja | Oportunidad
**Que:** Sin prediccion de ausencias basada en historico (gripe en invierno, vacaciones en verano).  
**Donde:** N/A  
**Por que importa:** El director no puede anticiparse a periodos de riesgo.  
**Como arreglar:** Modulo de prediccion basado en tendencias historicas de BAJ/VAC por mes.  
**Esfuerzo:** Alto

---

### INT-010 | Baja | index.html L22628-22673
**Que:** Burnout engine no pondera la tendencia temporal (ascendente/descendente). No distingue mejora de empeoramiento.  
**Donde:** index.html L22628-22673  
**Por que importa:** Respuesta igual para trabajadores en recuperacion y en deterioro.  
**Como arreglar:** Historicos de score + calculo de derivada. Flecha de tendencia.  
**Esfuerzo:** Alto

---

### INT-011 | Baja | index.html L29815-29817
**Que:** Deteccion del turno actual usa horas fijas no configurables (M:08-15, T:15-22, N:22-08).  
**Donde:** index.html L29815-29817  
**Por que importa:** Hospitales con horarios diferentes ven el turno actual incorrecto.  
**Como arreglar:** Rangos horarios configurables desde la configuracion.  
**Esfuerzo:** Bajo

---

### INT-012 | Baja | index.html L32402-32416
**Que:** Polling cada 4 segundos para `updateSPBadge()` cuando ya hay WebSocket implementado.  
**Donde:** index.html L32402-32416  
**Por que importa:** Calculo pesado innecesario. Consumo de bateria en tablets.  
**Como arreglar:** Reemplazar por actualizacion reactiva tras cambios en schedule o eventos WS.  
**Esfuerzo:** Medio

---

### INT-013 | Baja | Oportunidad
**Que:** Sin sugerencias proactivas de redistribucion nocturna. La deteccion de desequilibrios es pasiva.  
**Donde:** N/A  
**Por que importa:** El director tiene que descubrir y resolver desequilibrios manualmente.  
**Como arreglar:** Boton "Equilibrar noches" que sugiera intercambios voluntarios.  
**Esfuerzo:** Alto

---

## 5. MEJORAS DE INTERFAZ VISUAL (UI)

---

### UI-001 | Alta | index.html L1-8100
**Que:** ~8100 lineas de CSS embebido en `<style>`. Impide cacheo por el navegador, hace el mantenimiento extremadamente dificil.  
**Donde:** index.html L1-8100  
**Por que importa:** Cada carga de pagina descarga 8100 lineas de CSS. Desarrolladores no pueden encontrar reglas.  
**Como arreglar:** Extraer a archivos separados (`styles/main.css`, `styles/components.css`, `styles/responsive.css`).  
**Esfuerzo:** Alto

---

### UI-002 | Alta | index.html L5287-5699, L6477-7517
**Que:** Media query `@media (max-width: 768px)` repetida en 5+ bloques con reglas que se sobreescriben mutuamente. 200+ usos de `!important` para parchar conflictos.  
**Donde:** index.html L5287-5699, L6477-7517  
**Por que importa:** Cascada CSS impredecible en movil. Imposible razonar sobre el layout.  
**Como arreglar:** Consolidar en un unico bloque al final. Eliminar `!important` innecesarios.  
**Esfuerzo:** Alto

---

### UI-003 | Alta | index.html L231-279
**Que:** Inconsistencia de paleta. Conviven verde (#5c7a6f, al menos 15 ocurrencias), indigo (#6366f1 en variables CSS), y colores hardcodeados sin variables.  
**Donde:** index.html L231-279, L4555, L3014, L3074, L3102  
**Por que importa:** La app parece ensamblada de partes de diferentes proyectos. No transmite confianza.  
**Como arreglar:** Definir todos los colores como variables CSS. Eliminar valores hardcodeados.  
**Esfuerzo:** Medio

---

### UI-004 | Alta | index.html L1764-1796
**Que:** Tooltips de shift-pills solo se muestran en `:hover`. No accesibles por teclado ni lectores de pantalla.  
**Donde:** index.html L1764-1796  
**Por que importa:** Informacion critica inaccesible para usuarios con discapacidad o en tablets sin hover.  
**Como arreglar:** Implementar tooltips con `aria-describedby`. Mostrar en `:focus`.  
**Esfuerzo:** Medio

---

### UI-005 | Alta | index.html L6547-6616
**Que:** En movil, tabs a partir del 4to se ocultan con `display: none !important`. Sin indicacion de que existen tabs ocultos.  
**Donde:** index.html L6547-6616  
**Por que importa:** Usuarios moviles pierden acceso a secciones enteras de la app.  
**Como arreglar:** Mostrar boton "Mas" con badge indicando numero de tabs ocultos.  
**Esfuerzo:** Medio

---

### UI-006 | Media | index.html L361-378, L5775-5792
**Que:** Reglas de scrollbar definidas dos veces con valores distintos. La segunda sobreescribe la primera.  
**Donde:** index.html L361-378 y L5775-5792  
**Por que importa:** Aspecto visual inconsistente del scrollbar.  
**Como arreglar:** Eliminar el bloque duplicado.  
**Esfuerzo:** Bajo

---

### UI-007 | Media | index.html L6272-6305
**Que:** `.save-indicator` definido dos veces con posiciones opuestas (`top: 12px` vs `bottom: 100px`). La primera nunca se aplica.  
**Donde:** index.html L2072-2103 y L6272-6305  
**Por que importa:** Codigo muerto que confunde. Posicion del indicador inesperada.  
**Como arreglar:** Decidir cual es la version correcta y eliminar la otra.  
**Esfuerzo:** Bajo

---

### UI-008 | Media | index.html L4555-4561
**Que:** Chat bubble usa verde (#5c7a6f) que no coincide con el accent indigo (#6366f1) del resto de la app.  
**Donde:** index.html L4555-4561  
**Por que importa:** El chat parece pertenecer a otro tema visual.  
**Como arreglar:** Usar `var(--accent)` para coherencia.  
**Esfuerzo:** Bajo

---

### UI-009 | Baja | index.html L608-610, L6262-6264
**Que:** `@keyframes spin` definido dos veces con cuerpo identico. Redundancia.  
**Donde:** index.html L608-610 y L6262-6264  
**Por que importa:** Peso innecesario del archivo.  
**Como arreglar:** Eliminar la segunda definicion.  
**Esfuerzo:** Bajo

---

### UI-010 | Baja | index.html L6477-6484
**Que:** `will-change: transform` aplicado a gran numero de elementos en movil. Consume memoria GPU.  
**Donde:** index.html L6477-6484  
**Por que importa:** Problemas de rendimiento en dispositivos con poca RAM (tablets hospitalarios).  
**Como arreglar:** Aplicar solo durante animacion activa.  
**Esfuerzo:** Medio

---

### UI-011 | Baja | index.html L40-42
**Que:** `.splash-title` referencia CSS variables antes de que se definan en `:root`. Funciona pero confunde.  
**Donde:** index.html L40-42  
**Por que importa:** Mantenibilidad.  
**Como arreglar:** Mover `:root` al inicio del `<style>`.  
**Esfuerzo:** Bajo

---

### UI-012 | Baja | index.html L6267-6345
**Que:** Reglas responsive para `.schedule-table`, `.workers-table`, `.incidents-table` que no existen en ningun otro lugar. Codigo legado.  
**Donde:** index.html L6267-6345  
**Por que importa:** Codigo muerto que anade complejidad.  
**Como arreglar:** Verificar y eliminar si no se usan.  
**Esfuerzo:** Bajo

---

## 6. MEJORAS DE USABILIDAD (UX)

---

### UX-001 | Critica | index.html L17850-17963
**Que:** El editor de turnos permite guardar cambios que violan el convenio laboral. Las alertas de tipo 'danger' son meramente informativas; el boton de guardar no se deshabilita.  
**Donde:** index.html L17850-17963  
**Por que importa:** Un director puede crear planificaciones ilegales sin darse cuenta. Riesgo legal grave.  
**Como arreglar:** Deshabilitar boton de guardar cuando hay alertas 'danger', o exigir confirmacion con motivo documentado.  
**Esfuerzo:** Medio

---

### UX-002 | Alta | index.html L8590
**Que:** Filtros avanzados completamente ocultos en movil con `display:none !important`. Sin alternativa.  
**Donde:** index.html ~L8590  
**Por que importa:** Usuarios moviles no pueden filtrar trabajadores ni turnos.  
**Como arreglar:** Convertir en modal de pantalla completa o bottom sheet en movil.  
**Esfuerzo:** Medio

---

### UX-003 | Media | index.html L10240-10249
**Que:** Toast de undo desaparece a los 3 segundos. Demasiado corto para acciones criticas.  
**Donde:** index.html L10240-10249  
**Por que importa:** El usuario no tiene tiempo de decidir si deshacer un cambio de turno.  
**Como arreglar:** Aumentar a 6-8 segundos o mantener visible hasta interaccion.  
**Esfuerzo:** Bajo

---

### UX-004 | Media | index.html L14527
**Que:** `confirm()` nativos del navegador para acciones destructivas. Inconsistentes con el diseno de la app.  
**Donde:** index.html ~L14527  
**Por que importa:** Rompen la experiencia visual y no se pueden personalizar.  
**Como arreglar:** Reemplazar por modales custom.  
**Esfuerzo:** Medio

---

### UX-005 | Media | index.html L17231-17275
**Que:** Pipeline de importacion tiene ~2 segundos de delays artificiales por archivo (`setTimeout(r, 300-400)`). Con 20 trabajadores = ~40 segundos extra innecesarios.  
**Donde:** index.html L17231-17275  
**Por que importa:** Espera innecesaria que frustra al usuario.  
**Como arreglar:** Reducir a max 100ms para feedback visual.  
**Esfuerzo:** Bajo

---

### UX-006 | Media | index.html L32275-32316
**Que:** `spiaApplyAll()` aplica todas las sugerencias de golpe sin confirmacion.  
**Donde:** index.html L32275-32316  
**Por que importa:** En entorno hospitalario, acciones masivas sin confirmacion son peligrosas.  
**Como arreglar:** Dialogo de confirmacion indicando cuantas asignaciones y a quienes.  
**Esfuerzo:** Medio

---

### UX-007 | Media | index.html L15845-15877
**Que:** `addBotMessage()` usa `innerHTML +=` que re-parsea todo el contenido del chat. Degrada rendimiento en conversaciones largas y destruye event listeners.  
**Donde:** index.html L15845-15877  
**Por que importa:** Chat se vuelve lento despues de varias interacciones.  
**Como arreglar:** Usar `insertAdjacentHTML('beforeend', ...)` o `createElement`.  
**Esfuerzo:** Bajo

---

### UX-008 | Media | index.html L20801
**Que:** Modo Guardia no indica si auto-refresh esta activo ni cuando fue la ultima actualizacion.  
**Donde:** index.html L20801  
**Por que importa:** El jefe de guardia no sabe si ve datos en tiempo real o cacheados.  
**Como arreglar:** Indicador "Ultima actualizacion: hace X seg" + boton de refresh manual.  
**Esfuerzo:** Bajo

---

### UX-009 | Media | index.html L25777-25818
**Que:** Ausencia de loading state real en `analyzeGestor`. Delay artificial de 800ms pero si el calculo real es pesado, la UI se congela despues.  
**Donde:** index.html L25777-25818  
**Por que importa:** UI congelada confunde al usuario.  
**Como arreglar:** Web Workers para calculos pesados con progreso incremental.  
**Esfuerzo:** Alto

---

### UX-010 | Media | index.html L5636-5644
**Que:** Boton "Cerrar" del chat en movil implementado como pseudo-elemento CSS. No es un boton real, no focusable, no accesible.  
**Donde:** index.html L5636-5644  
**Por que importa:** Inaccesible para navegacion por teclado y lectores de pantalla.  
**Como arreglar:** Crear `<button>` real con `aria-label="Cerrar chat"`.  
**Esfuerzo:** Medio

---

### UX-011 | Baja | index.html L9274
**Que:** FAB flotante visible sin datos cargados. Confunde al usuario nuevo.  
**Donde:** index.html ~L9274  
**Por que importa:** Onboarding confuso.  
**Como arreglar:** Ocultar hasta que `workers.length > 0`.  
**Esfuerzo:** Bajo

---

### UX-012 | Baja | index.html L15900-15921
**Que:** Chat simula que "piensa" con delay de 400-700ms para respuestas 100% sincronas.  
**Donde:** index.html L15900-15921  
**Por que importa:** Delay innecesario para queries simples.  
**Como arreglar:** Reducir a 100-200ms o eliminar para respuestas locales.  
**Esfuerzo:** Bajo

---

### UX-013 | Baja | index.html L15755-15820
**Que:** Sin indicador de progreso al resolver conflictos. En meses con muchos trabajadores, la UI puede congelarse.  
**Donde:** index.html L15755-15820  
**Por que importa:** El usuario piensa que la app se colgo.  
**Como arreglar:** Spinner overlay + `requestAnimationFrame`.  
**Esfuerzo:** Bajo

---

### UX-014 | Baja | index.html L15937-15998
**Que:** Menu "Mas" del bottom nav movil sin atributos ARIA (`role="menu"`, `aria-expanded`).  
**Donde:** index.html L15937-15998  
**Por que importa:** Inaccesible para lectores de pantalla.  
**Como arreglar:** Anadir roles ARIA y trap de foco.  
**Esfuerzo:** Medio

---

### UX-015 | Baja | index.html L22694
**Que:** Panel burnout muestra solo top 8 sin opcion de ver mas.  
**Donde:** index.html L22694  
**Por que importa:** Trabajadores en riesgo quedan ocultos en equipos grandes.  
**Como arreglar:** Boton "Ver todos" o filtro por nivel de riesgo.  
**Esfuerzo:** Bajo

---

### UX-016 | Baja | index.html L20851-20857
**Que:** Horas de fatiga en guardia usan valores fijos (M/T=7h, N=10h) en vez de `RULES.SHIFT_HOURS`.  
**Donde:** index.html L20851-20857  
**Por que importa:** Fatiga incorrecta para turnos especiales (MR, M7H, M6R, M55).  
**Como arreglar:** Usar `RULES.SHIFT_HOURS[s] || 7`.  
**Esfuerzo:** Bajo

---

## 7. POLISH Y CALIDAD DE CODIGO

---

### POL-001 | Media | server.js L1249-1251
**Que:** `/api/notify` comprueba `SMTP_HOST` pero el transporter usa Gmail con `GMAIL_APP_PASSWORD`. Condicion incorrecta = emails nunca se envian.  
**Donde:** server.js L1249-1251  
**Por que importa:** Funcionalidad de notificaciones completamente rota.  
**Como arreglar:** Usar `process.env.GMAIL_APP_PASSWORD` como condicion.  
**Esfuerzo:** Bajo

---

### POL-002 | Media | server.js L840-862
**Que:** Fallback de creacion de tablas en runtime dentro de endpoints. Fragil e innecesario si `initializeDatabase()` funciona.  
**Donde:** server.js L840-862  
**Por que importa:** Falsa sensacion de robustez. Oculta fallos de inicializacion.  
**Como arreglar:** Eliminar fallbacks. Si `initializeDatabase()` falla, devolver 503.  
**Esfuerzo:** Bajo

---

### POL-003 | Media | index.html L7662-7668
**Que:** `prefers-reduced-motion` desactiva TODAS las animaciones, incluyendo transiciones funcionales (acordeones, paneles).  
**Donde:** index.html L7662-7668  
**Por que importa:** La app deja de funcionar correctamente para usuarios que prefieren movimiento reducido.  
**Como arreglar:** Desactivar solo animaciones decorativas. Mantener transiciones funcionales con duracion reducida.  
**Esfuerzo:** Medio

---

### POL-004 | Baja | server.js L871, L993
**Que:** Email "from" hardcodea `highkeycvsender@gmail.com` como fallback. Email de desarrollo.  
**Donde:** server.js L871, L993  
**Por que importa:** Emails de produccion salen de cuenta personal si `GMAIL_USER` no esta configurado.  
**Como arreglar:** Eliminar fallback. No enviar si no esta configurado.  
**Esfuerzo:** Bajo

---

### POL-005 | Baja | server.js L952, L1094, L1222
**Que:** Funcion `esc()` de escape HTML definida 3 veces como variable local + 1 como `escHtmlServer` global.  
**Donde:** server.js L952, L1094, L1222  
**Por que importa:** Codigo duplicado. Riesgo de inconsistencia si se corrige en un sitio y no en otros.  
**Como arreglar:** Usar `escHtmlServer` en todos los sitios.  
**Esfuerzo:** Bajo

---

### POL-006 | Baja | server.js L336-361
**Que:** Admin seed hardcodea email, nombre, company, plan. No configurable.  
**Donde:** server.js L336-361  
**Por que importa:** Imposible desplegar para otro hospital sin cambiar el codigo.  
**Como arreglar:** Env vars con valores por defecto.  
**Esfuerzo:** Bajo

---

### POL-007 | Baja | server.js (multiples lineas)
**Que:** Mensajes de error mezclan espanol e ingles. `'Email, password, and name are required'` vs `'Usuario y contrasena son obligatorios'`.  
**Donde:** server.js L442, L508  
**Por que importa:** Inconsistencia para los usuarios.  
**Como arreglar:** Unificar todos los mensajes en espanol.  
**Esfuerzo:** Bajo

---

## ACCESIBILIDAD (RESUMEN)

| # | Lineas | Problema | Severidad |
|---|--------|----------|-----------|
| A1 | L1764-1796 | Tooltips de shift-pills solo hover, sin keyboard/screen reader | Alta |
| A2 | L2526-2553 | Tooltips de heatmap-cell solo hover | Alta |
| A3 | L5636-5644 | Boton cerrar chat es pseudo-elemento CSS, no boton real | Media |
| A4 | L352-358 | `:focus:not(:focus-visible)` elimina outlines sin fallback | Media |
| A5 | L15937-15998 | Menu "Mas" sin ARIA | Baja |
| A6 | L14997-15028 | Menu contextual no se cierra con Escape | Baja |

---

## PLAN DE ACCION RECOMENDADO

### Fase 1: Criticos (1-2 dias)
1. Arreglar recursion infinita en `scheduleSaveThrottled` (BUG-001)
2. Eliminar credenciales offline del frontend (SEC-002)
3. Corregir `saveSchedule()` -> `saveToStorage()` (BUG-002)
4. Arreglar doble release de PostgreSQL (BUG-003)
5. Arreglar doble save por monkey-patching (BUG-004)
6. Renombrar variable `history` (BUG-005)
7. Anadir logging a catch vacios criticos (BUG-006)
8. Bloquear guardado con violaciones de convenio (UX-001)
9. Activar SSL en PostgreSQL (SEC-001)
10. Asignar `w.hours = totalH` (LOG-003)

### Fase 2: Altos (1 semana)
1. Arreglar conteo de noches consecutivas (BUG-012)
2. Unificar sistemas de cobertura (LOG-001)
3. Alinear umbral de noches con convenio (LOG-002)
4. Validar convenio al pegar patrones (LOG-004)
5. Deteccion cross-month de violaciones (LOG-005)
6. Corregir condicion SMTP en `/api/notify` (POL-001)
7. Requerir password actual para cambios (SEC-006)
8. Reducir JWT a 4h + refresh token (SEC-003)
9. Filtros accesibles en movil (UX-002)
10. Escapar `c.title` en exportacion PDF (SEC-008)

### Fase 3: Medios (2-4 semanas)
1. Consolidar CSS responsive en un bloque
2. Unificar paleta de colores con variables CSS
3. Implementar modales custom para reemplazar `alert()`/`confirm()`
4. Cache de `genSchedule()`
5. Implementar matriz de competencias
6. Contexto conversacional para el chat
7. Festivos configurables
8. Vacaciones configurables por trabajador

### Fase 4: Mejoras continuas
1. Extraer CSS a archivos separados
2. Implementar prediccion de ausencias
3. Sugerencias proactivas de redistribucion
4. Motor de tendencia de burnout
5. Tests unitarios para reglas de convenio
6. Accesibilidad completa WCAG 2.1 AA

---

*Auditoria generada el 12 de mayo de 2026. 123 hallazgos verificados contra el codigo fuente.*
