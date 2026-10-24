# Especificación de Requerimientos No Funcionales (RNF)

> **Sistema de Gestión de Postura de Seguridad (SSPM / EASM / CSPM)**  
> Versión: **2.0.0**  
> Alcance: **RNF-01 a RNF-10**

Este documento detalla los requerimientos no funcionales y lineamientos de calidad técnica que rigen el diseño, implementación y operación en producción de la plataforma SSPM.

---

## Matriz Resumen de Requerimientos No Funcionales

| ID | Requerimiento No Funcional | Categoría | Mecanismo Técnico Principal |
| :--- | :--- | :--- | :--- |
| **RNF-01** | Multi-Tenancy Estricto | Seguridad / Aislamiento | Filtro obligatorio por `organizationId` en queries Prisma ORM |
| **RNF-02** | Autenticación Fuerte y MFA | Seguridad / Identidad | JWT de 15m, Refresh Tokens rotativos y TOTP RFC 6238 |
| **RNF-03** | Control de Acceso RBAC | Seguridad / Autorización | Decoradores NestJS `@Roles()` y Guards a nivel de endpoint |
| **RNF-04** | Escaneo No Intrusivo y Seguro | Operabilidad / Seguridad | Sin payloads destructivos, timeouts estrictos y respeto a robots.txt |
| **RNF-05** | Determinismo del Scoring | Confiabilidad / Calidad | Algoritmo matemático transparente sin variables opacas o azar |
| **RNF-06** | Registro Inmutable de Auditoría | Cumplimiento / Gobernanza | Tabla `audit_logs` append-only con metadata JSON y actor |
| **RNF-07** | Concurrencia y Rendimiento | Rendimiento / Escala | PostgreSQL `FOR UPDATE SKIP LOCKED` y timeouts de red |
| **RNF-08** | Privacidad y Sanitización | Privacidad / DLP | Máscara criptográfica `redactToken` en logs y base de datos |
| **RNF-09** | Estándares Abiertos | Interoperabilidad | RFC 9116, BIMI, RFC 4180 (CSV BOM), PDF-1.4 WinAnsi |
| **RNF-10** | Retención y Purga de Datos | Mantenibilidad / Costo | Servicio programado de purga de scans antiguos y sesiones |

---

### RNF-01: Multi-Tenancy Estricto y Aislamiento de Datos
- **Objetivo:** Garantizar que los datos de una organización (activos, credenciales cloud, hallazgos, reportes) sean completamente inaccesibles para cualquier otra organización bajo cualquier circunstancia.
- **Implementación Técnica:**
  - Todas las tablas de dominio (`assets`, `findings`, `cloud_accounts`, `scans`, `reports`, `alerts`, `audit_logs`) incluyen obligatoriamente una columna `organization_id` con clave foránea e índice compuesto.
  - Ningún endpoint REST confía en identificadores pasados por el cuerpo o la URL sin verificar previamente que la entidad pertenezca al `organizationId` del token JWT verificado en el contexto de la petición (`@CurrentUser()`).
  - Las consultas Prisma ORM aplican siempre cláusulas `where: { id, organizationId }` para prevenir vulnerabilidades de *Insecure Direct Object Reference* (IDOR).

---

### RNF-02: Autenticación Fuerte, Sesiones y MFA
- **Objetivo:** Proteger las cuentas de usuario frente a ataques de fuerza bruta, robo de credenciales y reutilización de contraseñas.
- **Implementación Técnica:**
  - **Tokens de Acceso (JWT):** Tiempo de vida corto de 15 minutos, firmados con algoritmo HMAC-SHA256 utilizando un secreto de alta entropía.
  - **Refresh Tokens:** Almacenados en base de datos con rotación obligatoria en cada uso y revocación en caso de detección de reuso sospechoso.
  - **Hashing de Contraseñas:** Algoritmo Argon2id / Bcrypt con factor de costo configurable (mínimo 10 rondas), previniendo ataques con tablas arcoíris o aceleración por GPU.
  - **Autenticación en Dos Pasos (MFA TOTP):** Conforme al estándar RFC 6238 (Google Authenticator, Microsoft Authenticator) con códigos de recuperación de un solo uso generados al activar.
  - **Protección contra Fuerza Bruta:** Limitación estricta de tasa (*Rate Limiting*) en `/api/v1/auth/login` (máximo 5 intentos fallidos por ventana de 15 minutos por IP).

---

### RNF-03: Control de Acceso Basado en Roles (RBAC)
- **Objetivo:** Segmentar los privilegios dentro de cada organización según las responsabilidades del personal.
- **Implementación Técnica:**
  - Tres roles jerárquicos definidos:
    1. **`ADMIN`:** Control total de la organización, gestión de usuarios, configuración de facturación, alta de cuentas Cloud y eliminación de activos.
    2. **`ANALYST`:** Lanzamiento de escaneos, gestión de hallazgos (triage, cambio de estados, re-test), generación de reportes y configuración de alertas.
    3. **`VIEWER`:** Acceso de solo lectura al dashboard, métricas de riesgo y reportes ejecutivos.
  - Aplicación en backend mediante el guard global [`RolesGuard`](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/backend/src/common/guards/roles.guard.ts) y decorador `@Roles(Role.ADMIN)`.
  - Aplicación en frontend mediante componentes de protección de ruta `<ProtectedRoute>` y renderizado condicional de botones de acción.

---

### RNF-04: Escaneo No Intrusivo, Seguro y Ético
- **Objetivo:** Evitar cualquier impacto adverso en la disponibilidad o integridad de los servicios de los clientes durante las auditorías.
- **Implementación Técnica:**
  - Las sondas web y de red son estrictamente pasivas o de diagnóstico ligero: no se ejecutan inyecciones SQL destructivas, ataques DoS, fuzzing masivo de parámetros ni payloads de explotación.
  - El escáner de puertos Nmap utiliza la técnica de conexión TCP segura (`-sT`), velocidad moderada (`-T3`) y límites de versión no agresivos.
  - El mini-crawler web limita la profundidad máxima a 2 niveles, un tope estricto de 20 páginas por activo, y respeta las exclusiones definidas en `robots.txt`.
  - Las peticiones HTTP salientes utilizan timeouts perentorios de 10 segundos para prevenir bloqueos por servidores lentos (*tarpits*).

---

### RNF-05: Determinismo, Transparencia y Auditabilidad del Scoring
- **Objetivo:** Proporcionar una métrica de riesgo comprensible y predecible que inspire confianza tanto en directores como en auditores externos.
- **Implementación Técnica:**
  - El algoritmo de cálculo no utiliza variables aleatorias, factores de tiempo variables o modelos de inteligencia artificial opacos para la nota base.
  - El Security Score se computa con base en deducciones matemáticas fijas por severidad con topes explícitos definidos en código abierto:
    - Crítico: 25 pts (Tope: 60)
    - Alto: 15 pts (Tope: 45)
    - Medio: 6 pts (Tope: 30)
    - Bajo: 2 pts (Tope: 15)
  - Toda deducción es rastreable a uno o más hallazgos visibles en la plataforma.

---

### RNF-06: Trazabilidad, Integridad y Auditoría de Operaciones
- **Objetivo:** Mantener un registro forense inmutable de todas las acciones sensibles realizadas dentro de la plataforma.
- **Implementación Técnica:**
  - La tabla `audit_logs` opera en modalidad de solo inserción (*append-only*); no existen operaciones `UPDATE` ni `DELETE` expuestas en la API para esta entidad.
  - Cada registro captura: `timestamp` ISO 8601, `organizationId`, `userId`, `action` (ej. `USER_INVITED`, `FINDING_STATUS_CHANGED`, `REPORT_GENERATED`), `ipAddress`, `userAgent` y un objeto `details` en formato JSON con el estado previo y posterior.

---

### RNF-07: Rendimiento, Escalabilidad y Concurrencia Adaptativa
- **Objetivo:** Asegurar una respuesta ágil de la interfaz y un procesamiento eficiente de tareas pesadas de escaneo sin degradación del sistema.
- **Implementación Técnica:**
  - Desacoplamiento de operaciones de escaneo mediante el patrón Productor-Consumidor apoyado en la tabla `scans` con lectura no bloqueante `FOR UPDATE SKIP LOCKED`.
  - Concurrencia máxima acotada por instancia de backend (configurable vía variable de entorno `MAX_CONCURRENT_SCANS`, predeterminado en 3 trabajadores paralelos) para preservar la CPU y memoria del host.
  - Respuestas de endpoints de lectura del Dashboard optimizadas por debajo de 200 ms mediante consultas agregadas eficientes y proyecciones reducidas en Prisma.

---

### RNF-08: Privacidad, Sanitización y Ofuscación de Secretos
- **Objetivo:** Cumplir con normativas de protección de datos personales (GDPR, Ley 1581) y estándares bancarios (PCI-DSS) impidiendo que secretos reales se almacenen en texto claro.
- **Implementación Técnica:**
  - La función centralizada [`redactToken()`](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/backend/src/scans/analyzers/js-secrets-sourcemap.analyzer.ts) ofusca cualquier credencial detectada por el Secret Hunter (ej. convirtiendo `sk_live_51AbC...99zX` en `sk_live_...9zX`).
  - Las credenciales de acceso a cuentas Cloud (AWS Access Key Secret y Azure Client Secret) se cifran antes de persistirse utilizando el algoritmo **AES-256-GCM** en `CryptoVaultService`, con un vector de inicialización (IV) de 12 bytes y un tag de autenticación de 16 bytes almacenados de forma independiente.

---

### RNF-09: Interoperabilidad y Cumplimiento de Estándares Abiertos
- **Objetivo:** Facilitar la integración con herramientas corporativas existentes y respetar especificaciones globales de Internet.
- **Implementación Técnica:**
  - **RFC 9116:** Soporte formal para la especificación `security.txt` en ubicaciones normalizadas.
  - **BIMI (Brand Indicators for Message Identification):** Validación de certificados SVG e indicadores de marca en servidores de correo.
  - **RFC 4180:** Exportaciones en formato CSV con Byte Order Mark (BOM) UTF-8 para garantizar apertura nativa sin errores de tildes o caracteres especiales en Microsoft Excel y Google Sheets.
  - **PDF-1.4:** Generación de reportes PDF compatibles con cualquier lector universal, sanitizando entradas tipográficas al estándar WinAnsi (Latin-1).
  - **OpenAPI v3.0 / Swagger:** Contrato de API completamente documentado e interactivo disponible en `/api/docs`.

---

### RNF-10: Resiliencia, Retención de Datos y Purga Automática
- **Objetivo:** Evitar el crecimiento descontrolado del volumen de la base de datos y optimizar los costos de almacenamiento.
- **Implementación Técnica:**
  - Servicio programado [`RetentionService`](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/backend/src/monitoring/retention.service.ts) que ejecuta limpiezas nocturnas de:
    - Escaneos completados o fallidos con antigüedad superior a 90 días (preservando los hallazgos y el score histórico).
    - Tokens de sesión y refresh tokens revocados o expirados.
    - Archivos temporales generados durante la compilación de reportes PDF.
  - Manejo graceful de apagado de contenedores (`SIGTERM`) esperando a que los escaneos en curso guarden su estado antes de terminar el proceso.
