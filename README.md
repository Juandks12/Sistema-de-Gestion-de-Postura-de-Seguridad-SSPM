# Sistema de Gestión de Postura de Seguridad (SSPM – SaaS Lite)

Plataforma SaaS multi-tenant orientada a PyMEs para registrar activos externos
(dominios e IPs públicas), escanearlos con herramientas automatizadas (Nmap, análisis
de cabeceras HTTP, certificados SSL/TLS), clasificar hallazgos por criticidad y
calcular un *Security Score* comprensible para la toma de decisiones.

Este repositorio contiene el **backend** (API REST). El frontend se añadirá en un
directorio hermano (`frontend/`) en sprints posteriores.

## Estado del proyecto

| Sprint | Alcance | Estado |
|--------|---------|--------|
| Sprint 0 | Diseño, modelo de datos, arquitectura | ✅ Documentado |
| Sprint 1 | Registro de activos (RF-01), integración Nmap, detección de puertos/servicios (RF-02, RF-03) | ✅ Implementado |
| Sprint 2 | Cabeceras HTTP, SSL/TLS, rutas sensibles, clasificación | ⏳ |
| Sprint 3 | Security Score y dashboard | ⏳ |
| Sprint 4 | Reportes PDF y alertas | ⏳ |

## Stack tecnológico

- **Runtime:** Node.js 22 + TypeScript
- **Framework:** [NestJS 11](https://nestjs.com/) (Express)
- **ORM / migraciones:** [Prisma 6](https://www.prisma.io/)
- **Base de datos:** PostgreSQL 16
- **Autenticación:** JWT (Bearer) con Passport
- **Autorización:** RBAC por organización (roles `ADMIN`, `ANALYST`, `VIEWER`)
- **Documentación de la API:** Swagger / OpenAPI en `/api/docs`
- **Escaneo:** Nmap ejecutado de forma asíncrona con `child_process.spawn` (sin shell) y cola de trabajos en PostgreSQL
- **Parser XML:** `fast-xml-parser` para la salida `-oX` de Nmap

## Estructura de carpetas

```
.
├── docker-compose.yml          # PostgreSQL (+ API opcional) para desarrollo
└── backend/
    ├── prisma/
    │   ├── schema.prisma       # Modelo de datos (users, organizations, assets, scans)
    │   ├── migrations/         # Migraciones SQL versionadas
    │   └── seed.ts             # Datos de demostración
    ├── src/
    │   ├── main.ts             # Bootstrap: helmet, validación global, Swagger
    │   ├── app.module.ts       # Módulo raíz y guards globales (JWT + roles)
    │   ├── config/             # Validación de variables de entorno
    │   ├── prisma/             # PrismaService (conexión a PostgreSQL)
    │   ├── common/
    │   │   ├── decorators/     # @Public, @Roles, @CurrentUser
    │   │   ├── guards/         # JwtAuthGuard, RolesGuard (RBAC)
    │   │   ├── filters/        # Traducción de errores Prisma a HTTP
    │   │   └── utils/          # Validación/normalización de dominios e IPs
    │   ├── auth/               # Registro de organización, login, estrategia JWT
    │   ├── organizations/      # Datos de la organización del usuario
    │   ├── users/              # Gestión de usuarios del tenant (solo ADMIN)
    │   ├── assets/             # RF-01: inventario de activos
    │   ├── scans/              # RF-02/RF-03: escaneos con Nmap
    │   │   ├── nmap/           # Ejecutor, argumentos, parser XML y tipos
    │   │   ├── scan-worker.service.ts  # Cola y worker asíncrono
    │   │   └── target-resolver.ts      # Resolución DNS segura del objetivo
    │   └── health/             # Endpoint de salud
    └── test/                   # Pruebas end-to-end (supertest)
```

## Requisitos previos

- Node.js ≥ 20 y npm
- PostgreSQL 16 (local o mediante Docker)
- Docker y Docker Compose (opcional, recomendado para la base de datos)
- Nmap ≥ 7.80 instalado y accesible en el `PATH` (`sudo apt install nmap`, `brew install nmap` o el instalador oficial en Windows)

## Puesta en marcha (desarrollo)

### 1. Clonar e instalar dependencias

```bash
git clone <url-del-repositorio>
cd Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/backend
npm install
```

### 2. Levantar PostgreSQL

Con Docker (desde la raíz del repositorio):

```bash
docker compose up -d db
```

O bien usa una instancia local y crea la base de datos:

```sql
CREATE DATABASE sspm_db;
```

### 3. Configurar variables de entorno

```bash
cp .env.example .env
```

Ajusta `DATABASE_URL` y `JWT_SECRET` si es necesario. Valores por defecto:

```
DATABASE_URL="postgresql://postgres:admin@localhost:5432/sspm_db?schema=public"
JWT_SECRET=cambia-este-secreto-por-uno-largo-y-aleatorio
```

### 4. Aplicar migraciones y generar el cliente Prisma

```bash
npx prisma migrate dev      # aplica migraciones y regenera el cliente
npx prisma db seed          # (opcional) carga una organización de demostración
```

### 5. Arrancar la API

```bash
npm run start:dev           # recarga automática
# o
npm run build && npm start  # modo producción
```

- API: <http://localhost:3000/api/v1>
- Swagger UI: <http://localhost:3000/api/docs>
- Salud: <http://localhost:3000/api/v1/health>

### Todo con Docker (base de datos + API)

```bash
docker compose up -d --build
```

## Usuarios de demostración (tras `prisma db seed`)

| Correo | Rol | Contraseña |
|--------|-----|------------|
| `admin@demo.local` | ADMIN | `Password123!` |
| `analista@demo.local` | ANALYST | `Password123!` |
| `gerente@demo.local` | VIEWER | `Password123!` |

## Endpoints disponibles

Todos los endpoints (salvo `health`, `register` y `login`) requieren la cabecera
`Authorization: Bearer <token>`.

| Método | Ruta | Roles | Descripción |
|--------|------|-------|-------------|
| GET | `/api/v1/health` | público | Estado de la API y la base de datos |
| POST | `/api/v1/auth/register` | público | Crea una organización y su primer usuario ADMIN |
| POST | `/api/v1/auth/login` | público | Devuelve un JWT |
| GET | `/api/v1/auth/me` | todos | Usuario autenticado |
| GET | `/api/v1/organizations/me` | todos | Organización del usuario |
| PATCH | `/api/v1/organizations/me` | ADMIN | Renombrar la organización |
| GET | `/api/v1/users` | ADMIN | Usuarios de la organización |
| POST | `/api/v1/users` | ADMIN | Crear usuario en la organización |
| PATCH | `/api/v1/users/:id` | ADMIN | Cambiar rol / activar / desactivar |
| **POST** | **`/api/v1/assets`** | ADMIN, ANALYST | **RF-01: registrar un dominio o IP** |
| GET | `/api/v1/assets` | todos | Listado paginado (`type`, `isActive`, `search`, `page`, `pageSize`) |
| GET | `/api/v1/assets/:id` | todos | Detalle de un activo |
| PATCH | `/api/v1/assets/:id` | ADMIN, ANALYST | Editar nombre, descripción o estado |
| DELETE | `/api/v1/assets/:id` | ADMIN | Eliminar activo y sus escaneos |
| **POST** | **`/api/v1/assets/:id/scans`** | ADMIN, ANALYST | **RF-02/RF-03: encolar un escaneo Nmap (responde 202)** |
| GET | `/api/v1/assets/:id/exposure` | todos | Puertos abiertos según el último escaneo completado |
| GET | `/api/v1/scans` | todos | Listado paginado (`assetId`, `status`, `type`, `page`, `pageSize`) |
| GET | `/api/v1/scans/:id` | todos | Estado, resumen y puertos detectados (`?includeRaw=true` añade la salida completa) |
| POST | `/api/v1/scans/:id/cancel` | ADMIN, ANALYST | Cancelar un escaneo pendiente o en ejecución |

### Ejemplo: registrar un activo (RF-01)

```bash
# 1. Obtener token
TOKEN=$(curl -s -X POST http://localhost:3000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@demo.local","password":"Password123!"}' | jq -r .accessToken)

# 2. Registrar el activo
curl -X POST http://localhost:3000/api/v1/assets \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "value": "https://www.mi-empresa.com/",
    "name": "Sitio web corporativo",
    "authorizationConfirmed": true
  }'
```

Reglas aplicadas al registrar:

- El valor se **normaliza** (minúsculas, sin esquema, ruta ni puerto) y el tipo
  (`DOMAIN` / `IP`) se detecta automáticamente; `type` es opcional.
- Solo se aceptan **activos públicos**: se rechazan IPs privadas/reservadas
  (RFC 1918, loopback, link-local, etc.) y hosts como `localhost` o `*.local`.
- `authorizationConfirmed` debe ser `true`: el usuario declara que tiene
  autorización para analizar el activo (sección 1.6.3 de la documentación).
- La unicidad es **por organización** (`organization_id` + `value`); un duplicado
  responde `409 Conflict`.

### Ejemplo: escanear un activo (RF-02 / RF-03)

```bash
# 1. Encolar el escaneo (responde 202 con estado PENDING)
SCAN_ID=$(curl -s -X POST http://localhost:3000/api/v1/assets/<ASSET_ID>/scans \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{}' | jq -r .id)

# 2. Consultar el estado hasta que sea COMPLETED o FAILED
curl -s http://localhost:3000/api/v1/scans/$SCAN_ID -H "Authorization: Bearer $TOKEN" | jq '{status, summary, ports}'

# 3. Superficie expuesta actual del activo
curl -s http://localhost:3000/api/v1/assets/<ASSET_ID>/exposure -H "Authorization: Bearer $TOKEN"
```

## Módulo de escaneo (Nmap)

### Flujo

1. `POST /assets/:id/scans` valida permisos, estado del activo y límites, y crea el
   registro en `scans` con estado `PENDING`.
2. El worker reclama el trabajo (`PENDING` → `RUNNING`) con `FOR UPDATE SKIP LOCKED`.
3. El dominio se resuelve por DNS. Si alguna IP resultante es privada o reservada, el
   escaneo se bloquea. A Nmap se le entrega la IP ya validada, nunca el texto del usuario.
4. Nmap se ejecuta con `spawn` sin shell:
   `nmap -sT -sV -Pn -n -T4 --max-retries 2 --host-timeout <s> --top-ports 1000 -oX - <IP>`.
5. La salida XML se normaliza y se guarda: resumen en `scans.summary`, salida completa en
   `scans.raw_result` y cada puerto en la tabla `scan_ports` (servicio, producto, versión, CPE).
6. El estado final es `COMPLETED`, `FAILED` (con `error_message`) o `CANCELLED`.

### Garantías y protección contra abuso (sección 11.3)

- **Asíncrono:** la API responde al instante; Nmap corre en segundo plano sin bloquear el servidor.
- **Cola persistente:** los escaneos pendientes sobreviven a reinicios. Al apagar el
  servidor, los escaneos en curso se detienen y vuelven a `PENDING`.
- **Escalable:** varias instancias pueden compartir la cola sin tomar el mismo escaneo.
  Con `SCAN_WORKER_ENABLED=false` una instancia solo atiende la API.
- **Límites:** concurrencia global y por organización, escaneos por hora por organización,
  un solo escaneo en curso por activo y tiempo máximo por escaneo.
- **Huérfanos:** un escaneo `RUNNING` que supera el tiempo máximo con margen pasa a `FAILED`.

### Configuración

| Variable | Por defecto | Descripción |
|----------|-------------|-------------|
| `NMAP_PATH` | `nmap` | Binario de Nmap |
| `SCAN_WORKER_ENABLED` | `true` | Procesar la cola en este proceso |
| `SCAN_MAX_CONCURRENCY` | `2` | Escaneos simultáneos por instancia |
| `SCAN_MAX_CONCURRENCY_PER_ORG` | `1` | Escaneos simultáneos por organización |
| `SCAN_MAX_PER_HOUR_PER_ORG` | `30` | Escaneos que una organización puede pedir por hora |
| `SCAN_TIMEOUT_SECONDS` | `600` | Tiempo máximo por escaneo |
| `SCAN_POLL_INTERVAL_MS` | `5000` | Frecuencia de revisión de la cola |
| `SCAN_TOP_PORTS` | `1000` | Puertos más comunes a escanear |
| `SCAN_PORTS` | vacío | Lista explícita (`22,80,443,8000-8100`); tiene prioridad sobre `SCAN_TOP_PORTS` |
| `SCAN_TIMING_TEMPLATE` | `4` | Temporización de Nmap, de `0` (lento) a `5` (agresivo) |
| `ALLOW_PRIVATE_TARGETS` | `false` | Modo laboratorio, ver abajo |

### Modo laboratorio

Para el caso de estudio con activos controlados (sección 13.5) se puede activar
`ALLOW_PRIVATE_TARGETS=true`. Permite registrar y escanear IPs privadas, `localhost`
o máquinas virtuales de una red local. La aplicación se niega a arrancar si se activa
con `NODE_ENV=production`.

```bash
ALLOW_PRIVATE_TARGETS=true SCAN_PORTS=22,80,443,5432 npm run start:dev
```

## Modelo multi-tenant y RBAC

- Cada usuario pertenece a **una** organización; el JWT incluye `org` y `role`.
- El identificador de organización **nunca** se acepta desde la URL ni el cuerpo:
  se toma siempre del token, y todas las consultas filtran por `organization_id`.
- Acceder a un recurso de otra organización responde `404` (no se revela su existencia).
- `JwtAuthGuard` y `RolesGuard` son globales: todo endpoint exige token salvo los
  marcados con `@Public()`, y `@Roles(...)` restringe por rol.
- La estrategia JWT recarga el usuario en cada petición, por lo que desactivar una
  cuenta u organización tiene efecto inmediato aunque el token siga vigente.

| Rol | Perfil (documento) | Permisos |
|-----|--------------------|----------|
| `ADMIN` | Administrador de TI | Gestiona usuarios, activos, escaneos y la organización |
| `ANALYST` | Desarrollador | Registra/edita activos y lanza escaneos |
| `VIEWER` | Gerente | Solo lectura (listados, dashboard, reportes) |

## Modelo de datos (Sprint 1)

Tablas creadas por las migraciones (sección 6.2 del documento, más `scan_ports`):

- **organizations**: tenant (`name`, `slug`, `is_active`).
- **users**: `email` único, `password_hash` (bcrypt), `role`, `organization_id`.
- **assets**: `type`, `value` (único por organización), `authorization_confirmed`,
  `created_by_id`, `last_scanned_at`.
- **scans**: `asset_id`, `type` (`PORT_SCAN`, `WEB_HEADERS`, `SSL_CERT`,
  `SENSITIVE_PATHS`), `status` (`PENDING` → `RUNNING` → `COMPLETED`/`FAILED`/`CANCELLED`),
  `target_address` (IP escaneada), `parameters`, `raw_result` y `summary` en JSONB.
- **scan_ports**: un registro por puerto detectado en cada escaneo: `port`, `protocol`,
  `state`, `service_name`, `product`, `version`, `extra_info`, `tunnel`, `cpe`. Permite
  consultar la superficie expuesta y comparar escaneos (base de las alertas de nuevos puertos).

Las tablas `findings`, `risk_scores`, `reports` y `alerts` se añadirán en los sprints 2–4.

## Scripts útiles

```bash
npm run start:dev     # servidor con recarga
npm run build         # compila a dist/
npm run lint          # ESLint
npm test              # pruebas unitarias
npm run test:e2e      # pruebas end-to-end (requiere base de datos)
npx prisma studio     # explorador visual de la base de datos
npx prisma migrate dev --name <nombre>   # nueva migración tras cambiar schema.prisma
```

## Seguridad del propio sistema

- Contraseñas con bcrypt; login con comparación de tiempo constante.
- `helmet` para cabeceras HTTP seguras y CORS restringido por `CORS_ORIGINS`.
- Validación estricta de entrada (`whitelist` + `forbidNonWhitelisted`).
- Los valores de activos se validan como FQDN/IP antes de persistirse y de nuevo antes
  de cada escaneo.
- Nmap recibe siempre una IP literal validada y se ejecuta con `spawn` sin shell, con
  un entorno mínimo y sin privilegios (escaneo `-sT`), lo que evita la inyección de
  comandos (sección 11.2).
- La imagen Docker ejecuta la API como usuario sin privilegios.

## Próximos pasos (Sprint 2)

1. Análisis de cabeceras HTTP de seguridad (RF-04) sobre los puertos HTTP/HTTPS detectados.
2. Validación de certificados SSL/TLS (RF-05).
3. Detección de rutas y archivos sensibles (RF-06).
4. Tabla `findings` y clasificación por severidad (RF-08).
