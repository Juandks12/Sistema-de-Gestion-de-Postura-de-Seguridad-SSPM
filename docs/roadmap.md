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

Ver README para el detalle funcional completo.

## Siguiente en el sistema

1. **Registro de auditoría** (RNF-06): quién hizo qué (altas de activos, revisiones de
   hallazgos, cambios de usuarios) con consulta para el administrador.
2. **Ciclo de vida de cuentas:** recuperar contraseña por correo, verificación del
   correo, invitaciones y MFA (TOTP).
3. **Criticidad de activos** en el Security Score, **seguimiento de la remediación**
   (responsable y fecha objetivo), **exportación CSV** y reporte ejecutivo programado.
4. **Retención de datos** y **reintentos** en la entrega de alertas.
5. Selectores DKIM declarados por el cliente y MTA-STS/TLS-RPT en la seguridad del correo.

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

1. **Resumen ejecutivo generado por LLM**: a partir de los hallazgos
   abiertos y el histórico de score, generar el texto del reporte
   ejecutivo (no el técnico, que debe ser preciso y verificable) en
   lenguaje de negocio. Alto valor, bajo riesgo (es prosa, no una decisión
   de seguridad).
2. **Triage asistido de hallazgos**: sugerir si un hallazgo es
   probablemente un falso positivo dado el contexto del activo (ya
   existe el catálogo de reglas; un LLM puede argumentar el porqué,
   con el analista humano confirmando siempre la decisión final).
3. **Detección de anomalías en el histórico de score**: alertar si el
   score de un activo cae de forma atípica respecto a su propia
   tendencia (esto puede empezar como una regla estadística simple antes
   de justificar un modelo). Encaja como un cuarto tipo en
   `backend/src/alerts/alert-rules.ts`, reutilizando canales y entrega.

Explícitamente **no** priorizar: "chatbot de seguridad" genérico o
generación automática de remediación de código — no hay evidencia de que
un cliente PyME lo pida, y el riesgo de una recomendación incorrecta en
seguridad es alto.

## Fase 4 — Crecer hacia "empresas", no solo PyMEs

Esto es lo que de verdad amplía el mercado más allá del nicho actual:

1. Integraciones de postura en la nube (AWS/Azure/GCP config checks) —
   esto es lo que el mercado llama "SSPM" hoy; el producto actual es más
   bien EASM (superficie externa). Evaluar si conviene ampliar el alcance
   o mantener el posicionamiento actual y ser explícitos en el nombre.
2. SSO (SAML/OIDC) — requisito de compra típico en empresas medianas.
3. Exportación de datos (API pública documentada, no solo Swagger interno)
   para integrarse con el SIEM/herramientas que la empresa ya tenga —
   coherente con el límite explícito de "no reemplazar un SIEM completo".
4. Certificaciones/cumplimiento (SOC 2 tipo I como mínimo) — solo cuando
   haya clientes reales que lo exijan contractualmente; es costoso y no
   debe anticiparse sin demanda confirmada.
