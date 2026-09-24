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
| Sprint 1 | Registro de activos (RF-01), integración Nmap, detección de puertos/servicios | 🔄 RF-01 listo; Nmap pendiente |
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
- **Escaneo (próximo paso):** Nmap ejecutado de forma asíncrona con `child_process.spawn`

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
    │   └── health/             # Endpoint de salud
    └── test/                   # Pruebas end-to-end (supertest)
```

## Requisitos previos

- Node.js ≥ 20 y npm
- PostgreSQL 16 (local o mediante Docker)
- Docker y Docker Compose (opcional, recomendado para la base de datos)
- Nmap (solo necesario cuando se active el módulo de escaneo)

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

Tablas creadas por la migración inicial (sección 6.2 del documento):

- **organizations**: tenant (`name`, `slug`, `is_active`).
- **users**: `email` único, `password_hash` (bcrypt), `role`, `organization_id`.
- **assets**: `type`, `value` (único por organización), `authorization_confirmed`,
  `created_by_id`, `last_scanned_at`.
- **scans**: `asset_id`, `type` (`PORT_SCAN`, `WEB_HEADERS`, `SSL_CERT`,
  `SENSITIVE_PATHS`), `status` (`PENDING` → `RUNNING` → `COMPLETED`/`FAILED`),
  `raw_result` y `summary` en JSONB.

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
- Los valores de activos se validan como FQDN/IP antes de persistirse, base para
  evitar inyección de comandos cuando se invoque Nmap (sección 11.2).

## Próximos pasos (Sprint 1)

1. Módulo `scans`: endpoint `POST /assets/:id/scans` que encola un escaneo.
2. Worker asíncrono que ejecuta `nmap -sV -oX -` con `spawn` (sin shell) y guarda
   el resultado en `scans.raw_result` / `scans.summary`.
3. Límites de concurrencia y tiempo máximo por escaneo (protección contra abuso).
