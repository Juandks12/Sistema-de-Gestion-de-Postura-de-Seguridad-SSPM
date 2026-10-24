# Centro de Documentación Técnica – Plataforma SSPM

> **Sistema de Gestión de Postura de Seguridad (SSPM / EASM / CSPM – SaaS Lite)**  
> Versión: **2.0.0 (Sprint 13 / Épica Macro #110)**  
> Repositorio Principal: [Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM)

Bienvenido a la documentación técnica estructurada del **Sistema de Gestión de Postura de Seguridad (SSPM)**. Esta documentación ha sido organizada temáticamente para brindar trazabilidad completa a desarrolladores, auditores de seguridad, arquitectos DevSecOps y directores de tecnología (C-Levels).

---

## Mapa de Navegación de la Documentación

La documentación se divide en cuatro áreas fundamentales, complementadas por los registros de decisiones arquitectónicas (ADRs) y los manuales de despliegue:

```
docs/
├── README.md                                # Portal central de documentación (este archivo)
│
├── requirements/                            # Especificación Formal de Requerimientos
│   ├── functional-requirements.md           # RF-01 a RF-18 detallados con criterios de aceptación
│   └── non-functional-requirements.md       # RNF-01 a RNF-10 (seguridad, aislamiento, SLAs)
│
├── architecture/                            # Arquitectura del Sistema y Diseño Técnico
│   ├── overview.md                          # Visión C4, límites de seguridad y multi-tenancy
│   ├── workflows-and-diagrams.md            # Diagramas de secuencia y flujos Mermaid
│   └── data-model.md                        # Modelo de datos relacional, esquemas Prisma y ERD
│
├── modules/                                 # Documentación Detallada de Módulos Core
│   ├── ecommerce-crawler-and-secrets.md     # Mini-crawler, SRI Magecart, Secret Hunter y CMS
│   ├── diagnostic-360-orchestrator.md       # Orquestador 3-etapas y Diff Temporal de Postura
│   ├── attack-paths-and-quick-wins.md       # Motor de 6 Rutas de Ataque y Matriz Quick Wins 24h
│   ├── cspm-multicloud.md                   # Conectores sin agente AWS SigV4 y Azure REST API
│   ├── risk-scoring-and-slas.md             # Motor determinista de Security Score y SLAs
│   └── reports-and-alerts.md                # Generador PDFKit, canales de alerta y webhooks
│
├── roadmap/                                 # Estrategia de Evolución y Mejora Continua
│   ├── future-integrations.md               # GCP CSPM, Jira/ServiceNow, SIEM, WAF 1-clic, PCI-DSS
│   └── technical-debt.md                    # BullMQ + Redis, workers efímeros, observabilidad
│
├── adr/                                     # Architecture Decision Records (ADR-0001 a ADR-0007)
│   ├── 0001-monorepo-vs-multirepo.md
│   ├── 0002-nmap-subprocess-postgres-queue.md
│   ├── 0003-scoring-propio-no-certificado.md
│   ├── 0004-alertas-entrega-asincrona-en-proceso.md
│   ├── 0005-verificacion-propiedad-y-proteccion-login.md
│   ├── 0006-cve-correo-y-subdominios.md
│   └── 0007-auditoria-recuperacion-invitaciones-mfa.md
│
├── architecture.md                          # Arquitectura base histórica del sistema
├── deployment.md                            # Guía de despliegue en entornos Azure y Docker
├── sistema-completo-arquitectura-requerimientos-flujos.md # Compendio integral del sistema
└── pendientes-backlog-futuras-integraciones.md            # Compendio macro de backlog e integraciones
```

---

## 1. Requerimientos del Sistema (`requirements/`)

- [**Requerimientos Funcionales (RF-01 a RF-18)**](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/docs/requirements/functional-requirements.md):
  Inventario de activos, verificación criptográfica de propiedad, descubrimiento pasivo Certificate Transparency, escaneo no intrusivo Nmap, cabeceras HTTP/TLS, seguridad de correo (SPF/DMARC/DKIM/BIMI), auditoría e-commerce PCI-DSS v4.0, RFC 9116 security.txt, CSPM multicloud AWS/Azure, diagnóstico 360° en 3 etapas, diff temporal, correlación de rutas de ataque, matriz de remediación Quick Wins 24h, scoring determinista 0-100 y reportes ejecutivos en PDF.
- [**Requerimientos No Funcionales (RNF-01 a RNF-10)**](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/docs/requirements/non-functional-requirements.md):
  Aislamiento multi-tenancy a nivel de query, autenticación JWT con MFA TOTP (RFC 6238), control de acceso basado en roles (RBAC), escaneo no destructivo, determinismo matemático del scoring, auditoría inmutable de eventos, concurrencia adaptativa PostgreSQL, ofuscación estricta de credenciales detectadas (`redactToken`), cumplimiento RFC 4180 / WinAnsi Latin-1 y retención automatizada de datos.

---

## 2. Arquitectura y Diseño Técnico (`architecture/`)

- [**Visión General de Arquitectura**](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/docs/architecture/overview.md):
  Modelo C4 (Contexto y Contenedores), topología de microservicios lógicos en monorrepo NestJS, límites de confianza, modelo de aislamiento de datos y esquema de despliegue en Azure Container Apps + Static Web Apps.
- [**Flujos y Diagramas de Secuencia**](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/docs/architecture/workflows-and-diagrams.md):
  Diagramas Mermaid de los 5 flujos vitales del sistema: Orquestador 360°, Correlación de Rutas de Ataque, Conectores CSPM AWS/Azure, Ciclo de Vida y Estados de SLAs de Hallazgos, y Algoritmo de Security Score.
- [**Modelo de Datos y Esquema Relacional**](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/docs/architecture/data-model.md):
  Esquema de entidades relacionales (Prisma ORM), llaves foráneas, índices de rendimiento, restricciones multi-tenant y diagrama ERD integral.

---

## 3. Módulos Especializados (`modules/`)

- [**Auditoría E-Commerce, Mini-Crawler y Secret Hunter**](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/docs/modules/ecommerce-crawler-and-secrets.md):
  Inspección de pasarelas de pago, análisis de Subresource Integrity (Magecart), búsqueda de credenciales expuestas en frontend con regex, introspección CMS (WordPress, WooCommerce, PrestaShop, Magento, Shopify), divulgación RFC 9116 y verificación de marca BIMI.
- [**Orquestador de Diagnóstico 360° y Diff Temporal**](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/docs/modules/diagnostic-360-orchestrator.md):
  Pipeline secuencial en 3 etapas encoladas, barra de progreso reactiva, cancelación en cascada y cálculo del delta temporal de postura frente al lote anterior.
- [**Correlación de Rutas de Ataque (Attack Paths) y Quick Wins 24h**](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/docs/modules/attack-paths-and-quick-wins.md):
  Los 6 escenarios de impacto de negocio (Fraude en Pagos, Toma de Control, Suplantación BEC, Exfiltración de Datos, Compromiso de Servidor, Subdomain Takeover) y catálogo de remediación (< 30 min, < 2 h, > 4 h).
- [**Postura de Seguridad Cloud Multicloud (CSPM)**](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/docs/modules/cspm-multicloud.md):
  Conexión agentless para AWS y Azure, bóveda de cifrado AES-256-GCM para llaves de acceso, catálogo de reglas CIS Benchmark y remediaciones paso a paso.
- [**Motor de Riesgo, Security Score y SLAs**](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/docs/modules/risk-scoring-and-slas.md):
  Fórmula matemática transparente (0-100), penalizaciones ponderadas, topes máximos por severidad, grados A-F y reloj de SLAs por severidad.
- [**Reportes Ejecutivos en PDF y Alertas Tempranas**](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/docs/modules/reports-and-alerts.md):
  Motor PDFKit sin navegador headless, estructura del Reporte Ejecutivo C-Level vs. Reporte Técnico, notificaciones por correo y webhooks con reintentos exponenciales.

---

## 4. Hoja de Ruta y Evolución (`roadmap/`)

- [**Futuras Integraciones Estratégicas**](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/docs/roadmap/future-integrations.md):
  Conector CSPM para Google Cloud Platform (GCP), sincronización bidireccional Jira/ServiceNow, integración SIEM (Splunk HEC, Microsoft Sentinel, AWS Security Hub), playbooks WAF de auto-remediación en 1-clic, atestación PCI-DSS v4.0 SAQ-A y CLI Shift-Left para CI/CD.
- [**Gestión de Deuda Técnica y Escala**](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/docs/roadmap/technical-debt.md):
  Migración de colas PostgreSQL a Redis + BullMQ, desacoplamiento en workers efímeros (Fargate/K8s), instrumentación OpenTelemetry y rate limiting jerárquico por organización.

---

## 5. Decisiones Arquitectónicas (ADRs)

| ADR | Título | Estado |
| :--- | :--- | :---: |
| [ADR-0001](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/docs/adr/0001-monorepo-vs-multirepo.md) | Monorrepo vs. Multirrepo | Aceptado |
| [ADR-0002](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/docs/adr/0002-nmap-subprocess-postgres-queue.md) | Ejecución de Nmap como subproceso con cola en PostgreSQL | Aceptado |
| [ADR-0003](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/docs/adr/0003-scoring-propio-no-certificado.md) | Algoritmo determinista propio para cálculo de Security Score | Aceptado |
| [ADR-0004](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/docs/adr/0004-alertas-entrega-asincrona-en-proceso.md) | Notificaciones de alerta asíncronas en proceso | Aceptado |
| [ADR-0005](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/docs/adr/0005-verificacion-propiedad-y-proteccion-login.md) | Verificación criptográfica de propiedad y protección de login | Aceptado |
| [ADR-0006](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/docs/adr/0006-cve-correo-y-subdominios.md) | Correlación CVE/KEV, seguridad de correo y Certificate Transparency | Aceptado |
| [ADR-0007](file:///home/miguel/Proyectos/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/docs/adr/0007-auditoria-recuperacion-invitaciones-mfa.md) | Auditoría inmutable, recuperación de contraseñas, invitaciones y MFA TOTP | Aceptado |

---

## Glosario de Conceptos Clave

- **EASM (External Attack Surface Management)**: Descubrimiento y monitoreo continuo de activos expuestos a Internet sin requerir instalación de agentes en el servidor objetivo.
- **CSPM (Cloud Security Posture Management)**: Identificación de malas configuraciones de seguridad, exceso de privilegios e incumplimiento normativo en plataformas de nube pública (AWS, Azure, GCP).
- **Magecart / E-Skimming**: Modalidad de ciberataque donde código malicioso inyectado en scripts de terceros intercepta números de tarjetas de crédito y datos personales directamente en el navegador del cliente.
- **SRI (Subresource Integrity)**: Mecanismo W3C que permite al navegador verificar que los recursos cargados desde CDNs externas no hayan sido manipulados maliciosamente mediante comparación de hashes criptográficos (`sha256`, `sha384`).
- **Attack Path (Ruta de Ataque)**: Cadena de vulnerabilidades o debilidades correlacionadas que un atacante puede explotar en secuencia para alcanzar un objetivo crítico de negocio (ej. exfiltración de base de datos o toma de control de pagos).
- **Quick Win**: Vulnerabilidad de alta efectividad defensiva cuya remediación toma menos de 30 minutos y no requiere cambios estructurales en el código base o arquitectura.
