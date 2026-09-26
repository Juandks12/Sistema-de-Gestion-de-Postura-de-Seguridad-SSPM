# Arquitectura del sistema

Este documento complementa el README (que cubre "cómo levantar y usar" el
sistema) con la vista de **por qué está construido así** y hacia dónde escala.

## 1. Vista de contenedores (C4 nivel 2)

```
┌──────────────────────────────────────────────────────────────────────┐
│                              Usuario (PyME)                          │
│                    Admin / Analista / Gerente (VIEWER)               │
└───────────────────────────────┬────────────────────────────────────┘
                                 │ HTTPS
                                 ▼
                    ┌─────────────────────────┐
                    │   Frontend (React SPA)  │
                    │   Nginx en producción    │
                    └────────────┬────────────┘
                                 │ /api (proxy)
                                 ▼
                    ┌─────────────────────────┐
                    │   Backend (NestJS API)  │
                    │  - Auth/RBAC (JWT)       │
                    │  - Assets / Findings     │
                    │  - Risk Engine           │
                    │  - Scan Worker (cola)    │
                    └───┬───────────────┬─────┘
                        │               │
             ┌──────────▼───┐   ┌───────▼────────────────┐
             │ PostgreSQL    │   │ Herramientas externas   │
             │ (Prisma)      │   │ - Nmap (child_process)  │
             │ - multi-tenant│   │ - HTTP/TLS probes       │
             └───────────────┘   │   (undici, node:tls)    │
                                  └─────────────────────────┘
```

Todo corre hoy como **dos servicios** (`api`, `web`) más `db`, orquestados con
Docker Compose. No hay colas externas (Redis/RabbitMQ): la cola de escaneos
vive en la propia tabla `scans` de PostgreSQL (`FOR UPDATE SKIP LOCKED`), lo
que es correcto para el volumen actual y evita infraestructura adicional
(ver ADR-0002).

## 2. Multi-tenancy

Aislamiento **lógico** (fila por `organization_id`), no físico. Cada
request obtiene `org`/`role` del JWT; nunca de la URL o el body. Es el
patrón correcto para SaaS Lite: barato de operar, suficiente para PyMEs, y
migrable a aislamiento físico (esquema o base por tenant) si en el futuro
un cliente enterprise lo exige contractualmente — no antes.

## 3. Motor de escaneo y motor de riesgo

Ver README (`Módulo de escaneo`, `Motor de riesgo y Security Score`) para
el detalle funcional. Desde el ángulo de arquitectura, lo relevante es que
ambos son **puros y aislables**: los analizadores (`scans/analyzers/`)
son funciones que convierten resultados crudos en hallazgos, y el scoring
(`risk/scoring.ts`) es una función determinista sobre conteos de severidad.
Esto permite, sin reescribir nada:

- Añadir nuevos tipos de escaneo (ej. escaneo de cabeceras de API, exposición
  en buckets S3 públicos) como un nuevo `scanner` + `analyzer` sin tocar el
  worker ni el motor de riesgo.
- Sustituir o versionar la fórmula de scoring sin tocar los escáneres.

## 4. Ruta de escalado (SaaS real)

El sistema actual es un buen "SaaS Lite" para PyMEs con pocos activos. Los
puntos de escalado, en orden de necesidad real (no especulativa):

| Cuello de botella | Cuándo aparece | Solución |
|---|---|---|
| Un solo worker de escaneos por instancia | Al superar decenas de organizaciones activas simultáneamente | Escalar instancias de `api` (la cola en Postgres ya soporta múltiples workers, ver `SCAN_WORKER_ENABLED`) |
| Escaneos bajo demanda únicamente | Cuando se venda "monitoreo continuo" (RF real de SSPM) | Job programado (cron / GitHub Actions runner / worker dedicado) que encole auditorías periódicas por activo |
| Aislamiento lógico multi-tenant | Si un cliente enterprise exige aislamiento físico contractual | Esquema por tenant en Postgres, o base separada, sin cambiar el modelo de datos |
| Sin observabilidad (logs planos) | Al operar para terceros, no solo para el equipo | OpenTelemetry + logs estructurados + dashboard de salud (ver roadmap DevOps) |

**No** se recomienda anticipar microservicios, colas externas o Kubernetes
antes de tener el primer cliente real pagando: la arquitectura actual
(monolito modular + Postgres) soporta con holgura decenas de organizaciones
y cientos de activos.

## 5. Por qué un solo repositorio de código

Backend y frontend comparten contrato de API y ciclo de release; con un
equipo de 2 personas, separarlos en repos distintos solo añade fricción
(versionado cruzado, PRs sincronizados, CI duplicado) sin beneficio real de
aislamiento de equipos o permisos. Ver ADR-0001.
