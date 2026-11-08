# Roadmap: de MVP académico a SaaS vendible

Este documento traduce la evaluación de alcance y valor real del proyecto
en pasos concretos, priorizados por lo que más rápido convierte el sistema
en algo vendible a PyMEs (y eventualmente a empresas más grandes), no por
lo más interesante técnicamente.

## Ya completado (Sprints 0-4)

Inventario de activos, escaneo de puertos/servicios (Nmap), auditoría de
headers HTTP y SSL/TLS, detección de rutas sensibles, clasificación de
hallazgos, Security Score con histórico, dashboard, y en el Sprint 4:

- **Reportes PDF** (RF-09) ejecutivo y técnico, de la organización o de un activo.
- **Alertas** (RF-10) por puerto nuevo, certificado por vencer y hallazgo crítico,
  notificadas por correo o webhook (Slack, Discord, JSON) con severidad mínima por canal.
- **Monitoreo continuo** (sección 10.4) diario o semanal por organización: es lo que
  convierte el producto en una suscripción de vigilancia, no en un análisis puntual.
- **CI** en cada PR: lint, pruebas unitarias y e2e con PostgreSQL, build de imágenes.

Después del MVP, dos bloques pensados para la venta como SaaS:

- **Bloque 1 — confianza:** verificación de propiedad de los activos antes de
  escanearlos (DNS TXT o archivo) y protección del login y el registro
  ([ADR-0005](adr/0005-verificacion-propiedad-y-proteccion-login.md)).
- **Bloque 2 — inteligencia de amenazas:** CVE de las versiones detectadas (NVD, con
  prioridad a los explotados activamente según CISA KEV), seguridad del correo
  (SPF, DMARC, DKIM) y descubrimiento de subdominios en Certificate Transparency con
  alerta de los nuevos ([ADR-0006](adr/0006-cve-correo-y-subdominios.md)). Es lo que
  lleva el producto de "puertos abiertos" a "riesgos concretos que un gerente entiende".
- **Bloque 3 — confianza operativa y ciclo de vida de cuentas:** registro de auditoría
  (RNF-06), recuperación de contraseña por correo, invitaciones de usuarios y
  verificación en dos pasos (TOTP)
  ([ADR-0007](adr/0007-auditoria-recuperacion-invitaciones-mfa.md)). Cierra lo que un
  cliente con varias personas en su equipo da por sentado en cualquier SaaS.

Ver README para el detalle funcional completo.

## Siguiente en el sistema

1. Verificación del correo del propio usuario al registrarse o cambiarlo (hoy solo se
   valida el formato).
2. **Criticidad de activos** en el Security Score, **seguimiento de la remediación**
   (responsable y fecha objetivo), **exportación CSV** y reporte ejecutivo programado.
3. **Retención de datos** y **reintentos** en la entrega de alertas.
4. Selectores DKIM declarados por el cliente y MTA-STS/TLS-RPT en la seguridad del correo.
5. SSO (SAML/OIDC) como alternativa al login con contraseña para empresas medianas
   (relacionado con la fase 4).

## Fase 2 — DevOps (para poder vender con confianza)

1. ~~CI en cada PR: lint + test + build~~ (hecho, `.github/workflows/ci.yml`).
2. Build y publicación de imágenes Docker versionadas (GHCR) en cada
   merge a `main`.
3. Observabilidad mínima: logs estructurados (JSON) y un dashboard de
   salud operacional (no solo `/health`), para poder responder con datos
   cuando un cliente pregunte "¿está funcionando mi monitoreo?".
4. Backups automatizados y verificados de PostgreSQL.

## Fase 3 — Diferenciación con IA (donde de verdad aporta, no como adorno)

Priorizar usos de IA que reduzcan trabajo humano real, no "features de IA"
decorativas:

1. ~~**Resumen ejecutivo generado por LLM**~~ (completado): a partir de los hallazgos
   abiertos y el histórico de score, generar el texto del reporte
   ejecutivo (no el técnico, que debe ser preciso y verificable) en
   lenguaje de negocio. Alto valor, bajo riesgo (es prosa, no una decisión
   de seguridad).
2. ~~**Triage asistido de hallazgos**~~ (completado): sugerir si un hallazgo es
   probablemente un falso positivo dado el contexto del activo (con catálogo
   de reglas heurísticas expertas y síntesis LLM con fallback, confirmando
   siempre el analista la decisión).
3. ~~**Detección de anomalías en el histórico de score**~~ (completado): alertar si el
   score de un activo cae de forma atípica respecto a su propia
   tendencia (reglas estadísticas de z-score y caídas abruptas contextualizadas con
   los hallazgos detonantes). Encaja como quinto tipo en `backend/src/alerts/alert-rules.ts`,
   reutilizando canales, entrega y visualización temporal en gráficos.

Explícitamente **no** priorizar: "chatbot de seguridad" genérico o
generación automática de remediación de código — no hay evidencia de que
un cliente PyME lo pida, y el riesgo de una recomendación incorrecta en
seguridad es alto.

## Fase 4 — Crecer hacia "empresas", no solo PyMEs

Esto es lo que de verdad amplía el mercado más allá del nicho actual:

1. ~~**Integraciones de postura en la nube (AWS/Azure config checks — CSPM)**~~ (completado en Sprints 14–19):
   conectores sin agente para AWS (SigV4) y Microsoft Azure (ARM OAuth2), bóveda AES-256-GCM y re-auditoría automática integrada en el planificador de monitoreo continuo.
2. ~~**Centro Unificado de Hallazgos y Gobierno Normativo Multi-Marco (GRC Hub)**~~ (completado en Sprints 15 y 20):
   mapeo taxonómico CWE, OWASP Top 10 y MITRE ATT&CK, triaje/SLA en lote, auditoría manual y evaluación continua en 5 marcos (`ISO_27001`, `PCI_DSS`, `SOC_2`, `NIST_CSF`, `CIS_CONTROLS`).
3. ~~**Laboratorio Forense de Malware, Phishing y Amenazas (Threat & Malware Lab)**~~ (completado en Sprints 21 y 22):
   estación interactiva de análisis estático y heurístico para correos `.eml`/BEC, archivos/hashes y URLs sospechosas con promoción en 1 clic a hallazgo GRC y navegación unificada en **5 Dominios de Seguridad**.
4. ~~**Exportación de datos y API pública (API Keys e integración SIEM/SOAR)**~~ (completado en Sprints 9 y 23):
   autenticación con secretos prefijados y hashes SHA-256 en base de datos, scopes granulares,
   endpoints de sincronización incremental (`since`) y formatos JSON/NDJSON para postura, activos, hallazgos, alertas, rutas de ataque (`/attack-paths`), cumplimiento GRC (`/compliance`) y laboratorio forense (`/threat-lab`).
5. **Siguientes integraciones en hoja de ruta (`docs/roadmap/future-integrations.md`):**
   conector CSPM para Google Cloud Platform (GCP), sincronización bidireccional ITSM (Jira/ServiceNow), atestación automatizada PCI-DSS v4.0 SAQ-A, playbooks de mitigación WAF en 1 clic y migración de colas de alto volumen a BullMQ + Redis.
