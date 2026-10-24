# Especificación de Requerimientos Funcionales (RF)

> **Sistema de Gestión de Postura de Seguridad (SSPM / EASM / CSPM)**  
> Versión: **2.0.0**  
> Alcance: **RF-01 a RF-18**

Este documento detalla los 18 requerimientos funcionales implementados en la plataforma, especificando el módulo responsable, los criterios de aceptación formales, los endpoints REST involucrados y las validaciones de seguridad aplicadas.

---

## Índice de Requerimientos

| ID | Requerimiento | Módulo Responsable | Criticidad Negocio |
| :--- | :--- | :--- | :---: |
| [RF-01](#rf-01-gestión-de-inventario-de-activos) | Gestión de Inventario de Activos | `AssetsModule` | Alta |
| [RF-02](#rf-02-verificación-criptográfica-de-propiedad) | Verificación de Propiedad de Activos | `AssetsModule` | Crítica |
| [RF-03](#rf-03-descubrimiento-pasivo-de-superficie-easm) | Descubrimiento de Superficie Expuesta | `DiscoveryModule` | Alta |
| [RF-04](#rf-04-auditoría-de-red-puertos-y-servicios) | Auditoría de Red, Puertos y Servicios | `ScansModule` (Nmap) | Alta |
| [RF-05](#rf-05-auditoría-de-cabeceras-http-y-tls) | Auditoría de Cabeceras HTTP y TLS | `ScansModule` (TLS/Headers) | Alta |
| [RF-06](#rf-06-seguridad-del-correo-electrónico-y-marca) | Seguridad del Correo Electrónico y Marca | `ScansModule` (EmailSecurity) | Alta |
| [RF-07](#rf-07-auditoría-web-profunda-e-commerce-y-secret-hunter) | Auditoría Web E-Commerce y Secret Hunter | `ScansModule` (WebScanners) | Crítica |
| [RF-08](#rf-08-madurez-de-divulgación-responsable-rfc-9116) | Madurez de Divulgación Responsable (RFC 9116) | `ScansModule` (SecurityTxt) | Media |
| [RF-09](#rf-09-auditoría-de-postura-cloud-multicloud-cspm) | Auditoría de Postura Cloud Multicloud (CSPM) | `CloudModule` (AWS/Azure) | Crítica |
| [RF-10](#rf-10-orquestador-de-diagnóstico-360-encadenado) | Orquestador de Diagnóstico 360° Encadenado | `DiagnosticOrchestrator` | Crítica |
| [RF-11](#rf-11-motor-de-diff-temporal-de-postura) | Motor de Diff Temporal de Postura | `DiagnosticOrchestrator` | Alta |
| [RF-12](#rf-12-correlación-de-rutas-de-ataque-attack-paths) | Correlación de Rutas de Ataque (Attack Paths) | `FindingsModule` (AttackPaths) | Crítica |
| [RF-13](#rf-13-matriz-quick-wins-24h-vs-mejoras-estructurales) | Matriz Quick Wins 24h vs. Mejoras Estructurales | `FindingsModule` (Catalog) | Alta |
| [RF-14](#rf-14-gestión-de-hallazgos-slas-y-triage-inteligente) | Gestión de Hallazgos, SLAs y Triage | `FindingsModule` | Alta |
| [RF-15](#rf-15-motor-de-riesgo-y-security-score-determinista) | Motor de Riesgo y Security Score Determinista | `RiskModule` | Crítica |
| [RF-16](#rf-16-generador-de-reportes-ejecutivos-y-técnicos-en-pdf) | Generador de Reportes PDF | `ReportsModule` | Alta |
| [RF-17](#rf-17-sistema-de-alertas-tempranas-y-webhooks) | Sistema de Alertas Tempranas y Webhooks | `AlertsModule` | Alta |
| [RF-18](#rf-18-monitoreo-continuo-programado) | Monitoreo Continuo Programado | `MonitoringModule` | Media |

---

### RF-01: Gestión de Inventario de Activos
- **Módulo Responsable:** [`AssetsModule`](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/backend/src/assets/assets.service.ts)
- **Descripción:** Permite a los usuarios registrar, visualizar, actualizar y desactivar activos pertenecientes al perímetro de su organización (Dominios raíz, Subdominios e IPs públicas IPv4).
- **Criterios de Aceptación:**
  1. Validación estricta de formato FQDN (Fully Qualified Domain Name) o IPv4 pública; se rechazan rangos privados (RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) y loopback (`127.0.0.1`).
  2. Asignación obligatoria de nivel de criticidad del activo (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
  3. Soporte para etiquetado flexible (*tags*) para segmentar por entornos (`producción`, `pagos`, `marketing`).
  4. La desactivación de un activo suspende de inmediato sus escaneos programados sin borrar el historial.
- **Endpoints:** `POST /api/v1/assets`, `GET /api/v1/assets`, `PATCH /api/v1/assets/:id`, `DELETE /api/v1/assets/:id`.

---

### RF-02: Verificación Criptográfica de Propiedad
- **Módulo Responsable:** [`AssetVerificationService`](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/backend/src/assets/asset-verification.service.ts)
- **Descripción:** Garantiza que una organización solo pueda escanear activos sobre los cuales tiene control legítimo, evitando el uso indebido de la plataforma contra terceros no autorizados.
- **Criterios de Aceptación:**
  1. Generación de un token criptográfico pseudoaleatorio de 32 bytes en formato hexadecimal.
  2. Verificación por DNS: Búsqueda del registro TXT en el dominio con el prefijo `sspm-verification=<token>`.
  3. Verificación por HTTP: Petición HTTPS GET al archivo público `/.well-known/sspm-verification.txt` esperando el token en texto plano.
  4. Los subdominios de un dominio padre verificado heredan automáticamente el estado `VERIFIED`.
  5. Ningún escaneo profundo o de puertos puede ejecutarse si el activo se encuentra en estado `UNVERIFIED`.
- **Endpoints:** `POST /api/v1/assets/:id/verification/generate`, `POST /api/v1/assets/:id/verification/verify`.

---

### RF-03: Descubrimiento Pasivo de Superficie (EASM)
- **Módulo Responsable:** [`SubdomainDiscoveryService`](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/backend/src/scans/scanners/subdomain-discovery.scanner.ts)
- **Descripción:** Identifica subdominios públicos pertenecientes a la organización mediante consultas no invasivas a registros de transparencia de certificados (Certificate Transparency logs).
- **Criterios de Aceptación:**
  1. Consulta a crt.sh extrayendo certificados SSL/TLS emitidos históricamente para el dominio base.
  2. Filtrado de subdominios únicos y sanitización de caracteres comodín (`*.`).
  3. Resolución DNS activa para verificar si el subdominio está vivo (registros A o CNAME).
  4. Detección de posibles subdominios colgados (*Subdomain Takeover*) si el CNAME apunta a servicios en la nube no configurados.
  5. Opción en un clic para incorporar los subdominios descubiertos al inventario oficial de activos.
- **Endpoints:** `POST /api/v1/assets/:id/discovery/subdomains`.

---

### RF-04: Auditoría de Red, Puertos y Servicios
- **Módulo Responsable:** [`PortScanner`](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/backend/src/scans/scanners/port-scanner.ts) y [`NmapService`](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/backend/src/scans/nmap/nmap.service.ts)
- **Descripción:** Evalúa los puertos TCP expuestos en el activo mediante Nmap en modo seguro, identificando versiones de software y correlacionándolas con bases de datos de vulnerabilidades.
- **Criterios de Aceptación:**
  1. Ejecución mediante `child_process.spawn` sin invocación de shell para prevenir inyección de comandos.
  2. Banderas predeterminadas no agresivas: `-sT -Pn -sV --version-intensity 3 -T3 --open`.
  3. Extracción de CPE (*Common Platform Enumeration*) de cada servicio detectado.
  4. Cruce con el catálogo CISA KEV (*Known Exploited Vulnerabilities*) y cálculo de probabilidad de explotación FIRST EPSS.
  5. Generación de hallazgos automáticos cuando se detectan puertos administrativos expuestos (SSH: 22, RDP: 3389, Bases de Datos: 3306, 5432, 27017, etc.).
- **Endpoints:** `POST /api/v1/assets/:id/scans` (tipo: `PORT_SCAN`).

---

### RF-05: Auditoría de Cabeceras HTTP y TLS
- **Módulo Responsable:** [`WebHeadersScanner`](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/backend/src/scans/scanners/web-headers.scanner.ts) y [`SslCertScanner`](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/backend/src/scans/scanners/ssl-cert.scanner.ts)
- **Descripción:** Inspecciona la configuración criptográfica de transporte y las directivas de seguridad web del servidor HTTP.
- **Criterios de Aceptación:**
  1. Validación de cabeceras de endurecimiento: HSTS (`Strict-Transport-Security`), CSP (`Content-Security-Policy`), `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`.
  2. Detección de versiones obsoletas o inseguras de TLS (TLS 1.0 y TLS 1.1) mediante sonda con `node:tls`.
  3. Verificación de vigencia del certificado X.509, alertando si expira en menos de 30, 15 o 7 días.
  4. Verificación de nombres alternativos del sujeto (SAN) y correspondencia de la cadena de confianza.
- **Endpoints:** `POST /api/v1/assets/:id/scans` (tipos: `WEB_HEADERS`, `SSL_CERT`).

---

### RF-06: Seguridad del Correo Electrónico y Marca
- **Módulo Responsable:** [`EmailSecurityScanner`](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/backend/src/scans/scanners/email-security.scanner.ts) y [`BimiVerifier`](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/backend/src/scans/scanners/bimi.ts)
- **Descripción:** Analiza la postura de seguridad contra suplantación de identidad (Phishing / BEC) y validación de autenticidad de marca en correos electrónicos.
- **Criterios de Aceptación:**
  1. Evaluación de registros SPF: Existencia, sintaxis, número de lookups DNS (máx. 10) y política de cierre (`~all` vs `-all`).
  2. Evaluación de directiva DMARC: Cumplimiento de política (`none`, `quarantine`, `reject`), porcentaje (`pct=100`) y reporte forense (`rua`/`ruf`).
  3. Comprobación de selectores DKIM comunes (`default`, `google`, `k1`, `mail`).
  4. Sonda DNS para MTA-STS y TLS-RPT (reporte de fallos de cifrado en tránsito SMTP).
  5. Consulta de registros BIMI en `default._bimi.<domain>` para verificar logotipos SVG validados y certificados VMC.
  6. Comprobación de reputación en listas negras DNSBL (Spamhaus ZEN, SpamCop).
- **Endpoints:** `POST /api/v1/assets/:id/scans` (tipo: `EMAIL_SECURITY`).

---

### RF-07: Auditoría Web Profunda, E-Commerce y Secret Hunter
- **Módulo Responsable:** [`EcommerceCrawler`](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/backend/src/scans/web/ecommerce-crawler.ts), [`MagecartSecurityAnalyzer`](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/backend/src/scans/analyzers/magecart-security.analyzer.ts), [`JsSecretsSourcemapAnalyzer`](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/backend/src/scans/analyzers/js-secrets-sourcemap.analyzer.ts) y [`CmsEcommerceAnalyzer`](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/backend/src/scans/analyzers/cms-ecommerce.analyzer.ts)
- **Descripción:** Ejecuta una inspección especializada sobre tiendas online para prevenir fraude de tarjetas de crédito (PCI-DSS v4.0), exfiltración de llaves de API y ataques a CMS.
- **Criterios de Aceptación:**
  1. **Mini-Crawler seguro:** Descubre páginas clave respetando `robots.txt` (pasarela `/checkout`, formularios `/cart`, panel `/admin`).
  2. **Anti-Magecart (PCI-DSS 6.4.3 & 11.6.1):** Identifica scripts externos cargados sin hash `integrity="sha..."` y detecta formularios que envían datos por HTTP plano o sin autorización.
  3. **Secret Hunter:** Analiza bundles JavaScript minificados buscando patrones regex de llaves activas de Stripe (`sk_live_`), MercadoPago (`APP_USR-`), AWS Access Keys (`AKIA...`), Google API Keys y tokens JWT.
  4. **Detección de Source Maps:** Verifica si los archivos `.js.map` son accesibles públicamente, exponiendo el código fuente original.
  5. **Auditoría CMS:** Detecta instalaciones y vulnerabilidades en WordPress, WooCommerce, PrestaShop, Magento y Shopify, probando `/wp-json/wp/v2/users` (enumeración de usuarios), `/xmlrpc.php` (amplificación/fuerza bruta) y archivos `debug.log`.
  6. **Sondeo CORS Activo:** Prueba reflejo de encabezado `Origin` no confiable con `Access-Control-Allow-Credentials: true`.
- **Endpoints:** `POST /api/v1/assets/:id/scans` (tipos: `WEB_HEADERS`, `SENSITIVE_PATHS`).

---

### RF-08: Madurez de Divulgación Responsable (RFC 9116)
- **Módulo Responsable:** [`SecurityTxtAnalyzer`](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/backend/src/scans/analyzers/security-txt.analyzer.ts)
- **Descripción:** Comprueba si la organización implementa el estándar RFC 9116 para la recepción de reportes de vulnerabilidades por parte de investigadores externos.
- **Criterios de Aceptación:**
  1. Sondeo HTTP GET en `/.well-known/security.txt` y `/security.txt`.
  2. Validación de la directiva obligatoria `Contact:` (correo electrónico o enlace a portal de divulgación).
  3. Validación de la directiva obligatoria `Expires:` y confirmación de que la fecha sea futura.
  4. Reconocimiento de directivas opcionales: `Encryption:`, `Acknowledgments:`, `Preferred-Languages:` y `Policy:`.
- **Endpoints:** Integrado en escaneo `SENSITIVE_PATHS`.

---

### RF-09: Auditoría de Postura Cloud Multicloud (CSPM)
- **Módulo Responsable:** [`CloudScanService`](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/backend/src/cloud/cloud-scan.service.ts), [`AwsConnectorService`](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/backend/src/cloud/connectors/aws-connector.service.ts) y [`AzureConnectorService`](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/backend/src/cloud/connectors/azure-connector.service.ts)
- **Descripción:** Audita sin agentes la configuración de seguridad en nubes públicas (AWS y Azure), contrastando recursos contra CIS Benchmarks.
- **Criterios de Aceptación:**
  1. Conexión segura con AWS mediante llamadas REST firmadas con AWS SigV4 y cifrado en reposo de Access Keys (`CryptoVaultService` AES-256-GCM).
  2. Conexión con Microsoft Azure mediante autenticación OAuth2 Service Principal (Client ID y Client Secret cifrado).
  3. Evaluación de reglas de almacenamiento: S3 Buckets sin bloqueo de acceso público y Azure Blob Storage públicos.
  4. Evaluación de reglas de red: Security Groups y NSGs con puertos SSH (22) o RDP (3389) abiertos a `0.0.0.0/0`.
  5. Evaluación de IAM: Uso de credenciales root sin MFA y llaves de acceso con más de 90 días de antigüedad.
  6. Evaluación de bases de datos: Instancias RDS y Azure SQL sin cifrado de almacenamiento o con firewall permisivo.
  7. Evaluación de auditoría: CloudTrail o Azure Activity Logs deshabilitados o sin validación de integridad.
- **Endpoints:** `POST /api/v1/cloud/accounts`, `POST /api/v1/cloud/accounts/:id/scan`, `GET /api/v1/cloud/accounts/:id/resources`.

---

### RF-10: Orquestador de Diagnóstico 360° Encadenado
- **Módulo Responsable:** [`DiagnosticOrchestratorService`](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/backend/src/scans/diagnostic-orchestrator.service.ts)
- **Descripción:** Permite ejecutar una auditoría integral multi-etapa con un solo clic, encadenando descubrimiento, escaneo de red y análisis web profundo de forma ordenada.
- **Criterios de Aceptación:**
  1. Creación de un registro maestro `DiagnosticBatch` con estado `RUNNING` y seguimiento de etapa (`stage: 1..3`).
  2. **Etapa 1:** Ejecución y finalización de `SUBDOMAIN_DISCOVERY`.
  3. **Etapa 2:** Ejecución concurrente controlada de `PORT_SCAN`, `SSL_CERT` y `EMAIL_SECURITY`.
  4. **Etapa 3:** Ejecución de `WEB_HEADERS` y `SENSITIVE_PATHS` (auditoría e-commerce y secretos).
  5. Interfaz de usuario con Stepper visual reactivo mostrando porcentaje de avance, estado por etapa y tiempo transcurrido.
  6. Capacidad de cancelación manual en cualquier momento, abortando los escaneos pendientes en la cola.
- **Endpoints:** `POST /api/v1/assets/:id/diagnostic-360`, `GET /api/v1/diagnostic-batches/:id`, `POST /api/v1/diagnostic-batches/:id/cancel`.

---

### RF-11: Motor de Diff Temporal de Postura
- **Módulo Responsable:** [`PostureDiffService`](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/backend/src/scans/posture-diff.service.ts)
- **Descripción:** Compara el resultado del lote de diagnóstico actual contra el lote previo del activo para mostrar de forma transparente la evolución de la postura de seguridad.
- **Criterios de Aceptación:**
  1. Identificación del lote inmediato anterior completado para el mismo activo.
  2. Cálculo del diferencial de Security Score (`scoreDelta`: positivo, negativo o cero).
  3. Clasificación de hallazgos remediados (`resolvedFindingsCount`: presentes en el anterior pero resueltos en el actual).
  4. Clasificación de regresiones (`newFindingsCount`: no presentes en el anterior y recién introducidos).
  5. Cálculo del balance de variación de puertos abiertos y tecnologías detectadas.
  6. Persistencia del diff en formato JSON en el registro `DiagnosticBatch`.
- **Endpoints:** `GET /api/v1/assets/:id/posture-diff/latest`.

---

### RF-12: Correlación de Rutas de Ataque (Attack Paths)
- **Módulo Responsable:** [`AttackPathsService`](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/backend/src/findings/attack-paths.service.ts)
- **Descripción:** Motor heurístico que analiza el conjunto de hallazgos abiertos de la organización y los correlaciona en cadenas de explotación (Kill Chains) con impacto de negocio.
- **Criterios de Aceptación:**
  1. Detección automática de los 6 escenarios críticos:
     - `AP-PAYMENT-FRAUD`: Fraude en Pasarela & E-Skimming (Magecart).
     - `AP-STORE-TAKEOVER`: Toma de Control de Tienda Online.
     - `AP-BRAND-IMPERSONATION`: Suplantación de Marca y Fraude Facturero (BEC).
     - `AP-DATA-EXFILTRATION`: Exfiltración de Código y Datos de Clientes.
     - `AP-INFRASTRUCTURE-COMPROMISE`: Compromiso Perimetral y Ransomware.
     - `AP-SUBDOMAIN-TAKEOVER`: Secuestro de Subdominio de Comercio.
  2. Generación de Kill Chain de 3 pasos para cada ruta activa: Vector de Acceso → Explotación/Evasión → Impacto en Negocio.
  3. Exposición de narrativa ejecutiva del impacto comercial y consecuencias legales/financieras (ej. multas PCI-DSS).
  4. Identificación inmediata de cuántos Quick Wins disponibles existen para desarticular la ruta.
- **Endpoints:** `GET /api/v1/findings/attack-paths`.

---

### RF-13: Matriz Quick Wins 24h vs. Mejoras Estructurales
- **Módulo Responsable:** [`FindingsService`](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/backend/src/findings/findings.service.ts) y [`RulesCatalog`](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/backend/src/findings/rules-catalog.ts)
- **Descripción:** Categoriza los hallazgos según el esfuerzo humano y técnico requerido para su mitigación, permitiendo remediación ágil en menos de 24 horas.
- **Criterios de Aceptación:**
  1. Asignación de nivel de esfuerzo a cada regla del catálogo:
     - `QUICK_WIN`: Remediación en menos de 30 minutos (ej. agregar registro TXT SPF o cabecera X-Content-Type-Options).
     - `MODERATE`: Remediación entre 30 minutos y 2 horas (ej. configurar CSP o renovación de certificados).
     - `STRUCTURAL`: Remediación superior a 4 horas (ej. actualización mayor de versión de CMS o migración de arquitectura de base de datos).
  2. Filtro interactivo en un clic en la interfaz de usuario: "⚡ Quick Wins (< 30 min)".
  3. Desglose en reportes PDF del volumen y puntos de mejora alcanzables aplicando solo Quick Wins.
- **Endpoints:** `GET /api/v1/findings?effortLevel=QUICK_WIN`.

---

### RF-14: Gestión de Hallazgos, SLAs y Triage Inteligente
- **Módulo Responsable:** [`FindingsService`](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/backend/src/findings/findings.service.ts)
- **Descripción:** Administra el ciclo de vida de los hallazgos de seguridad detectados, asignación de responsables, control de vencimiento de SLAs y verificación de re-test.
- **Criterios de Aceptación:**
  1. Estados formales de hallazgo: `OPEN`, `IN_PROGRESS`, `VERIFYING`, `RESOLVED`, `ACCEPTED`, `FALSE_POSITIVE`.
  2. Control de SLAs por severidad con cálculo automático de fecha de vencimiento (`dueDate`):
     - `CRITICAL`: 7 días de calendario.
     - `HIGH`: 15 días de calendario.
     - `MEDIUM`: 30 días de calendario.
     - `LOW`: 60 días de calendario.
  3. Estados de cumplimiento de SLA: `ON_TRACK`, `APPROACHING` (< 48 horas para vencer), `OVERDUE` (vencido).
  4. Capacidad de asignación a un usuario miembro del tenant (`assignedToId`).
  5. Registro obligatorio de justificación de negocio al marcar un hallazgo como `ACCEPTED` o `FALSE_POSITIVE`.
  6. Re-test puntual: Permite lanzar una comprobación aislada de la regla para mover el estado a `RESOLVED` sin re-escanear todo el activo.
- **Endpoints:** `GET /api/v1/findings`, `PATCH /api/v1/findings/:id`, `POST /api/v1/findings/:id/retest`.

---

### RF-15: Motor de Riesgo y Security Score Determinista
- **Módulo Responsable:** [`RiskService`](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/backend/src/risk/risk.service.ts) y [`scoring.ts`](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/backend/src/risk/scoring.ts)
- **Descripción:** Calcula la postura global de seguridad de la organización en una escala normalizada de 0 a 100 puntos y su correspondiente calificación en grado escolar (A, B, C, D, F).
- **Criterios de Aceptación:**
  1. Algoritmo 100% determinista basado exclusivamente en los hallazgos abiertos no aceptados.
  2. Penalizaciones base por severidad:
     - `CRITICAL`: 25 puntos (Tope máximo de deducción por categoría: 60 puntos).
     - `HIGH`: 15 puntos (Tope máximo: 45 puntos).
     - `MEDIUM`: 6 puntos (Tope máximo: 30 puntos).
     - `LOW`: 2 puntos (Tope máximo: 15 puntos).
  3. Cálculo de pérdida total y puntaje:
     $$\text{Pérdida Total} = \min(100, P_{\text{crit}} + P_{\text{high}} + P_{\text{med}} + P_{\text{low}})$$
     $$\text{Security Score} = \max(0, 100 - \text{Pérdida Total})$$
  4. Escala de grados:
     - **Grado A:** 90 – 100 puntos (Postura Excelente).
     - **Grado B:** 80 – 89 puntos (Postura Buena).
     - **Grado C:** 70 – 79 puntos (Postura Aceptable).
     - **Grado D:** 60 – 69 puntos (Postura Deficiente).
     - **Grado F:** 0 – 59 puntos (Postura Crítica).
  5. Registro histórico continuo para graficar la tendencia en el tiempo.
- **Endpoints:** `GET /api/v1/risk/score`, `GET /api/v1/risk/history`.

---

### RF-16: Generador de Reportes Ejecutivos y Técnicos en PDF
- **Módulo Responsable:** [`ReportsService`](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/backend/src/reports/reports.service.ts) y [`PdfRendererService`](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/backend/src/reports/pdf-renderer.ts)
- **Descripción:** Produce documentos PDF de alta fidelidad estética listos para presentar a juntas directivas, aseguradoras de ciberriesgo o equipos de ingeniería.
- **Criterios de Aceptación:**
  1. Renderizado en streaming con PDFKit sin requerir Chromium headless, manteniendo el contenedor liviano.
  2. Sanitización estricta de cadenas a WinAnsi (Latin-1) para evitar caracteres corruptos o errores en tiempo de ejecución.
  3. Dos modalidades de reporte:
     - **Reporte Ejecutivo:** Dirigido a directivos; incluye resumen de Security Score, impacto financiero proyectado, desglose de Rutas de Ataque (Attack Paths) activas y plan de acción Quick Wins 24h.
     - **Reporte Técnico:** Dirigido a ingenieros; incluye evidencias completas, puertos abiertos, directivas HTTP ausentes, comandos Nmap y guías de remediación paso a paso.
  4. Descarga directa en navegador o envío automatizado por correo a los administradores.
- **Endpoints:** `POST /api/v1/reports/generate`, `GET /api/v1/reports/:id/download`.

---

### RF-17: Sistema de Alertas Tempranas y Webhooks
- **Módulo Responsable:** [`AlertsService`](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/backend/src/alerts/alerts.service.ts)
- **Descripción:** Monitorea y despacha notificaciones inmediatas ante eventos que degraden la postura de seguridad del perímetro.
- **Criterios de Aceptación:**
  1. Disparadores de alerta en tiempo real:
     - Detección de nuevos puertos abiertos en activo productivo.
     - Descubrimiento de nuevos hallazgos de severidad `CRITICAL` o `HIGH`.
     - Caída del Security Score por debajo del umbral configurado por la organización.
     - Certificado TLS próximo a expirar en menos de 7 días.
  2. Canales de despacho soportados: Correo electrónico SMTP y Webhooks HTTP POST salientes.
  3. Formato de payload de webhook enriquecido con compatibilidad nativa para Slack y Discord (bloques enriquecidos).
  4. Cola de reintentos exponencial con timeout estricto de 5 segundos para no bloquear la ejecución principal.
- **Endpoints:** `POST /api/v1/alerts/channels`, `GET /api/v1/alerts/channels`, `POST /api/v1/alerts/channels/:id/test`.

---

### RF-18: Monitoreo Continuo Programado
- **Módulo Responsable:** [`MonitoringService`](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/backend/src/monitoring/monitoring.service.ts)
- **Descripción:** Ejecuta periódicamente auditorías automáticas sobre todos los activos activos de la organización sin requerir acción manual del usuario.
- **Criterios de Aceptación:**
  1. Frecuencias configurables a nivel de organización: `DAILY` (Diario), `WEEKLY` (Semanal) o `DISABLED` (Desactivado).
  2. Tarea cron nocturna que evalúa los activos verificados cuyo último escaneo supere el intervalo configurado.
  3. Encolado progresivo con dispersión temporal (*jitter*) para evitar picos de carga en la base de datos o en la red.
  4. Disparo automático de alertas si el monitoreo detecta regresiones o nuevas vulnerabilidades.
- **Endpoints:** `PATCH /api/v1/organizations/settings/monitoring`.
