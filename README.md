# Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM

Sistema de Gestión de Postura de Seguridad (SSPM – SaaS Lite) orientado a PyMEs: inventario de
activos externos, escaneo de puertos y servicios con Nmap, auditoría de configuración web,
Security Score, dashboard, reportes y alertas. Este repositorio contiene el **backend** (API REST).

Estado actual: **Sprint 1 – Módulo de Identificación** (registro de activos, autenticación JWT y
control de acceso multi-tenant). La integración con Nmap es el siguiente paso del sprint.

## Stack

| Componente      | Tecnología                                     |
| --------------- | ---------------------------------------------- |
| Runtime         | Node.js 24 LTS (TypeScript 6)                  |
| Framework       | NestJS 12 (Express)                            |
| Base de datos   | PostgreSQL 16 + Prisma ORM 7 (migraciones)     |
| Autenticación   | JWT (Passport) + bcrypt                        |
| Documentación   | Swagger / OpenAPI en `/docs`                   |
| Pruebas         | Jest (unitarias) + Supertest (end-to-end)      |
| Escáner         | Nmap (incluido en la imagen Docker del backend) |

Se eligió NestJS por su arquitectura modular (módulos, guards, pipes), su soporte de primera clase
para colas de trabajo (BullMQ) que usaremos para ejecutar Nmap de forma asíncrona, y el tipado
end-to-end que aporta Prisma sobre el modelo de datos.

## Estructura del repositorio

```
.
├── docker-compose.yml          # PostgreSQL (+ API opcional) para desarrollo
└── backend/
    ├── prisma/
    │   ├── schema.prisma       # Modelo de datos (users, organizations, assets, scans)
    │   ├── migrations/         # Migraciones SQL versionadas
    │   └── seed.ts             # Datos de demostración
    ├── prisma.config.ts
    ├── src/
    │   ├── main.ts             # Bootstrap: helmet, CORS, validación global, Swagger
    │   ├── app.module.ts       # Módulo raíz; registra los guards globales (JWT + roles)
    │   ├── config/             # Validación tipada de variables de entorno
    │   ├── prisma/             # PrismaService (conexión compartida)
    │   ├── common/
    │   │   ├── decorators/     # @Public(), @Roles(), @CurrentUser()
    │   │   ├── guards/         # JwtAuthGuard, RolesGuard (RBAC)
    │   │   └── filters/        # Traducción de errores de Prisma a HTTP
    │   ├── auth/               # Registro de organización, login, estrategia JWT
    │   ├── organizations/      # Organización actual y gestión de miembros
    │   ├── assets/             # RF-01: inventario de activos (dominios / IPs)
    │   └── health/             # GET /health
    └── test/                   # Pruebas end-to-end
```

## Requisitos

- Node.js **24.9 o superior** (NestJS 12 es ESM puro y Jest necesita `require(esm)` nativo).
- npm 10+.
- PostgreSQL 16 (local o vía Docker).
- Docker y Docker Compose (opcional, recomendado para la base de datos).
- Nmap (solo necesario cuando se habilite el módulo de escaneo).

## Puesta en marcha (desarrollo)

1. Clonar el repositorio e instalar dependencias del backend:

   ```bash
   cd backend
   npm install
   ```

2. Levantar PostgreSQL. La opción más simple es Docker Compose desde la raíz del repo:

   ```bash
   docker compose up -d db
   ```

   Si prefieres una instancia local, crea la base `sspm_db` con usuario `postgres` y contraseña
   `admin`, o ajusta `DATABASE_URL` en el siguiente paso.

3. Configurar variables de entorno:

   ```bash
   cp .env.example .env
   # Edita .env: DATABASE_URL, JWT_SECRET (mínimo 16 caracteres), etc.
   ```

4. Generar el cliente Prisma y aplicar las migraciones:

   ```bash
   npm run prisma:generate
   npm run prisma:migrate      # crea/aplica migraciones en desarrollo
   # En producción usa: npm run prisma:deploy
   ```

5. (Opcional) Cargar datos de demostración:

   ```bash
   npm run db:seed
   ```

   Crea la organización **Demo PyME** con tres usuarios (contraseña `Demo1234`):
   `admin@demo.local` (ADMIN), `analyst@demo.local` (ANALYST) y `viewer@demo.local` (VIEWER).

6. Arrancar la API:

   ```bash
   npm run start:dev
   ```

   - API: `http://localhost:3000/api/v1`
   - Swagger: `http://localhost:3000/docs`
   - Salud: `http://localhost:3000/health`

### Todo con Docker

```bash
docker compose up --build
```

Levanta PostgreSQL y la API (aplica las migraciones al arrancar). La imagen del backend ya incluye
Nmap.

## Variables de entorno

| Variable                | Descripción                                                          | Por defecto            |
| ----------------------- | -------------------------------------------------------------------- | ---------------------- |
| `NODE_ENV`              | `development` / `test` / `production`                                | `development`          |
| `PORT`                  | Puerto HTTP                                                          | `3000`                 |
| `DATABASE_URL`          | Cadena de conexión PostgreSQL                                        | —                      |
| `JWT_SECRET`            | Secreto para firmar tokens (≥ 16 caracteres)                         | —                      |
| `JWT_EXPIRES_IN`        | Vigencia del token (`15m`, `1h`, `7d`)                               | `1h`                   |
| `BCRYPT_ROUNDS`         | Costo del hash de contraseñas                                        | `12`                   |
| `CORS_ORIGINS`          | Orígenes permitidos, separados por coma                              | vacío (CORS apagado)   |
| `ALLOW_PRIVATE_TARGETS` | Permitir IPs privadas como activos (solo pruebas locales)            | `false`                |

La aplicación valida estas variables al arrancar y falla de inmediato si alguna es inválida.

## Modelo de datos (sección 6.2, Sprint 1)

| Tabla           | Propósito                                                                                  |
| --------------- | ------------------------------------------------------------------------------------------ |
| `organizations` | Tenant. Toda entidad de negocio cuelga de una organización.                                |
| `users`         | Usuarios con `role` (`ADMIN`, `ANALYST`, `VIEWER`) y pertenencia a una organización.       |
| `assets`        | Activos externos (`DOMAIN` o `IP`), únicos por organización, con confirmación de autorización. |
| `scans`         | Escaneos asíncronos (`PENDING` → `RUNNING` → `COMPLETED`/`FAILED`), salida cruda y resumen. |

`findings`, `risk_scores`, `reports` y `alerts` se incorporarán en los sprints 2 a 4.

## Seguridad y multi-tenant

- **Autenticación**: todos los endpoints exigen `Authorization: Bearer <JWT>` salvo `/health`,
  `/auth/register` y `/auth/login`. El token contiene el usuario, su organización y su rol, pero
  el rol y el estado del usuario se releen de la base de datos en cada petición.
- **RBAC**: el decorador `@Roles()` y el `RolesGuard` restringen operaciones por rol.
  - `ADMIN`: gestiona usuarios, activos y escaneos.
  - `ANALYST`: gestiona activos y escaneos.
  - `VIEWER`: solo lectura.
- **Aislamiento de datos**: el cliente nunca envía `organizationId`; se toma del JWT y todas las
  consultas filtran por él. Un `id` válido de otra organización devuelve `404`.
- **Alcance ético (sección 1.6.3)**: al registrar un activo se exige `authorizationConfirmed: true`
  y, por defecto, se rechazan IPs privadas o reservadas.
- Cabeceras de seguridad con `helmet`, validación estricta de entrada (propiedades desconocidas
  rechazadas) y hashes bcrypt para contraseñas.

## Endpoints disponibles

| Método | Ruta                                 | Roles           | Descripción                                   |
| ------ | ------------------------------------ | --------------- | --------------------------------------------- |
| GET    | `/health`                            | público         | Estado de la API y de la base de datos        |
| POST   | `/api/v1/auth/register`              | público         | Crea una organización y su usuario ADMIN      |
| POST   | `/api/v1/auth/login`                 | público         | Devuelve un JWT                               |
| GET    | `/api/v1/auth/me`                    | cualquiera      | Usuario autenticado                           |
| GET    | `/api/v1/organizations/me`           | cualquiera      | Organización actual con contadores            |
| GET    | `/api/v1/organizations/me/members`   | ADMIN           | Lista usuarios de la organización             |
| POST   | `/api/v1/organizations/me/members`   | ADMIN           | Crea un usuario con rol en la organización    |
| POST   | `/api/v1/assets`                     | ADMIN, ANALYST  | **RF-01** Registra un activo (dominio o IP)   |
| GET    | `/api/v1/assets`                     | cualquiera      | Lista activos (paginación, filtro, búsqueda)  |
| GET    | `/api/v1/assets/:id`                 | cualquiera      | Detalle de un activo                          |

### Probar RF-01 con curl

```bash
# 1. Registrar organización y administrador
curl -s -X POST http://localhost:3000/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"organizationName":"Acme S.A.S.","fullName":"Ana Pérez","email":"ana@acme.com","password":"Sup3rSecreta"}'

# 2. Iniciar sesión y guardar el token
TOKEN=$(curl -s -X POST http://localhost:3000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"ana@acme.com","password":"Sup3rSecreta"}' | jq -r .accessToken)

# 3. Registrar un activo (el tipo se detecta automáticamente)
curl -s -X POST http://localhost:3000/api/v1/assets \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"value":"www.acme.com","label":"Sitio corporativo","authorizationConfirmed":true}'

# 4. Listar activos de la organización
curl -s http://localhost:3000/api/v1/assets -H "Authorization: Bearer $TOKEN"
```

Respuestas de error esperadas al registrar activos: `400` (URL con esquema/ruta, IP privada,
dominio inválido, tipo inconsistente, autorización no confirmada), `403` (rol VIEWER),
`409` (activo duplicado en la organización).

## Scripts útiles

| Script                    | Descripción                                  |
| ------------------------- | -------------------------------------------- |
| `npm run start:dev`       | API en modo desarrollo con recarga           |
| `npm run build`           | Compila a `dist/`                            |
| `npm start`               | Ejecuta la build de producción               |
| `npm run typecheck`       | Verificación de tipos sin emitir             |
| `npm test`                | Pruebas unitarias                            |
| `npm run test:e2e`        | Pruebas end-to-end (requiere base de datos)  |
| `npm run prisma:migrate`  | Crea y aplica migraciones (desarrollo)       |
| `npm run prisma:deploy`   | Aplica migraciones pendientes (producción)   |
| `npm run prisma:studio`   | Explorador visual de la base de datos        |
| `npm run db:seed`         | Carga datos de demostración                  |
| `npm run format`          | Formatea el código con Prettier              |

## Decisiones y supuestos del Sprint 1

La documentación (sección 6.2) enumera las tablas pero no define sus columnas ni relaciones, y no
detalla el modelo de roles. Se tomaron las siguientes decisiones, abiertas a revisión:

- **Un usuario pertenece a una sola organización.** Simplifica el aislamiento; si en el futuro un
  consultor debe atender varias PyMEs, se introducirá una tabla `memberships`.
- **Roles `ADMIN`, `ANALYST` y `VIEWER`**, derivados de los stakeholders de la sección 3.4
  (Administrador de TI, Desarrollador, Gerente).
- **Registro de tenant autoservicio** (`POST /auth/register`) y alta de miembros por el ADMIN. No
  hay invitaciones por correo ni verificación de email todavía.
- **Activos**: unicidad por `(organization_id, value)`, tipo detectado automáticamente y
  confirmación explícita de autorización. Los subdominios se registran como dominios individuales.
- **Escaneos**: la tabla `scans` ya contempla tipo, estado, parámetros, salida cruda y resumen JSON
  para almacenar los resultados de Nmap de forma asíncrona.

## Próximos pasos (resto del Sprint 1)

1. Cola de trabajos (BullMQ + Redis) y worker que ejecute Nmap con `spawn` (sin shell) sobre un
   activo, con lista blanca de perfiles de escaneo y límites de concurrencia.
2. Parseo de la salida XML de Nmap y persistencia en `scans.summary`
   (puertos, servicios, versiones) — RF-02 y RF-03.
3. Endpoints `POST /assets/:id/scans`, `GET /scans/:id` y `GET /assets/:id/scans`.
4. Tabla `audit_logs` para RNF-06 y limitación de tasa en `/auth/login`.
