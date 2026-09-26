# Roadmap: de MVP académico a SaaS vendible

Este documento traduce la evaluación de alcance y valor real del proyecto
en pasos concretos, priorizados por lo que más rápido convierte el sistema
en algo vendible a PyMEs (y eventualmente a empresas más grandes), no por
lo más interesante técnicamente.

## Ya completado (Sprints 0-3)

Inventario de activos, escaneo de puertos/servicios (Nmap), auditoría de
headers HTTP y SSL/TLS, detección de rutas sensibles, clasificación de
hallazgos, Security Score con histórico, dashboard. Ver README para el
detalle funcional completo.

## Fase 1 — Cerrar el MVP funcional (Sprint 4 del plan original)

1. **Reportes PDF** (RF-09): ejecutivo (para gerencia, sin jerga técnica) y
   técnico (para el administrador de TI, con evidencia y recomendaciones).
   Es el entregable que un cliente PyME espera poder mostrar a su junta o
   a un auditor.
2. **Alertas** (RF-10): tabla `alerts` + notificación por email o webhook
   ante: nuevo puerto expuesto, certificado por vencer, hallazgo crítico
   nuevo. Sin esto, el sistema es una foto puntual, no "gestión continua de
   postura" — que es la promesa del nombre SSPM.
3. **Escaneos programados** (sección 10.4): un cron (o job periódico del
   propio worker) que reencole auditorías por activo cada N días según
   configuración por organización. Esto es lo que justifica cobrar una
   suscripción recurrente en vez de un análisis puntual.

## Fase 2 — DevOps (para poder vender con confianza)

1. CI en cada PR: lint + test + build (ver `.github/workflows/ci.yml`).
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
   de justificar un modelo).

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
