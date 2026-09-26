# Sistema de Gestión de Postura de Seguridad (SSPM – SaaS Lite)

Plataforma SaaS multi-tenant orientada a PyMEs para registrar activos externos
(dominios e IPs públicas), escanearlos con herramientas automatizadas (Nmap, análisis
de cabeceras HTTP, certificados SSL/TLS), clasificar hallazgos por criticidad,
calcular un *Security Score* comprensible para la toma de decisiones, vigilar los
activos de forma continua con alertas tempranas y generar reportes PDF.

La documentación técnica ampliada (arquitectura, decisiones, despliegue y roadmap)
está en [`docs/`](docs/); la memoria académica y el material de negocio viven en el
repositorio `sspm-docs`.

Este repositorio contiene el **backend** (API REST, en `backend/`) y el **frontend**
(dashboard web, en `frontend/`).

## Estado del proyecto

| Sprint | Alcance | Estado |
|--------|---------|--------|
| Sprint 0 | Diseño, modelo de datos, arquitectura | ✅ Documentado |
| Sprint 1 | Registro de activos (RF-01), integración Nmap, detección de puertos/servicios (RF-02, RF-03) | ✅ Implementado |
| Sprint 2 | Cabeceras HTTP (RF-04), SSL/TLS (RF-05), rutas sensibles (RF-06), clasificación por severidad (RF-08) | ✅ Implementado |
| Sprint 3 | Security Score (RF-07), histórico de postura (RF-11), endpoints del dashboard y base del frontend | ✅ Implementado |
| Sprint 4 | Reportes PDF (RF-09), alertas por correo y webhook (RF-10), monitoreo continuo programado (10.4) | ✅ Implementado |
| Bloque 1 (SaaS) | Verificación de propiedad de activos, protección del inicio de sesión y del registro | ✅ Implementado |
| Bloque 2 (SaaS) | CVE de las versiones detectadas (NVD + KEV), seguridad del correo (SPF/DMARC/DKIM), descubrimiento de subdominios (Certificate Transparency) | ✅ Implementado |

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
- **Auditoría web:** `undici` (HTTP con conexión a IP validada) y `node:tls` (certificados)
- **Contenedores:** Docker multi-etapa (Ubuntu 24.04 LTS, Node 22, Nmap 7.94) y Docker Compose
- **Reportes PDF:** [PDFKit](https://pdfkit.org/) (sin navegador headless: la imagen no crece)
- **Notificaciones:** [Nodemailer](https://nodemailer.com/) (SMTP) y webhooks con `undici`
- **Frontend:** React 19 + Vite + TypeScript, React Router, TanStack Query, Tailwind CSS 4 y Recharts, servido por Nginx en Docker
- **CI:** GitHub Actions (lint, pruebas unitarias y e2e con PostgreSQL, build de las imágenes Docker)

## Estructura de carpetas

```
.
├── docker-compose.yml          # Base de datos + API (imagen de producción)
├── docker-compose.dev.yml      # Modo desarrollo: código montado y recarga en caliente
├── docker-compose.db-access.yml # Opcional: publica PostgreSQL en tu equipo
├── .env.example                # Variables opcionales de docker compose
├── frontend/                   # Dashboard web (React + Vite)
│   ├── Dockerfile              # development (Vite) y production (Nginx + proxy /api)
│   ├── nginx.conf              # Sirve la SPA y reenvía /api al backend
│   └── src/
│       ├── auth/               # Sesión JWT, contexto y rutas protegidas
│       ├── components/         # Layout, componentes de interfaz y gráficas
│       ├── hooks/queries.ts    # Acceso a la API con TanStack Query
│       ├── lib/                # Cliente HTTP, tipos de la API y formato
│       └── pages/              # Vista general, activos, detalle, hallazgos y escaneos
└── backend/
    ├── Dockerfile              # Imagen multi-etapa: development y production
    ├── docker-entrypoint.sh    # Migraciones y datos de demostración al arrancar
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
    │   ├── scans/              # Escaneos asíncronos
    │   │   ├── scanners/       # Un escáner por tipo: puertos, cabeceras, TLS, rutas
    │   │   ├── analyzers/      # Funciones puras que convierten resultados en hallazgos
    │   │   ├── web/            # Cliente HTTP seguro, sonda TLS y catálogo de rutas
    │   │   ├── nmap/           # Ejecutor, argumentos, parser XML y tipos
    │   │   ├── scan-worker.service.ts  # Cola y worker asíncrono
    │   │   └── target-resolver.ts      # Resolución DNS segura del objetivo
    │   ├── findings/           # RF-08: hallazgos, catálogo de reglas y severidad
    │   ├── risk/               # RF-07/RF-11: motor de riesgo, Security Score e histórico
    │   ├── dashboard/          # Datos agregados para el dashboard (sección 8)
    │   ├── alerts/             # RF-10: reglas de alerta, canales, correo y webhooks
    │   ├── monitoring/         # Sección 10.4: planificador del monitoreo continuo
    │   ├── reports/            # RF-09: datos y renderizado de los reportes PDF
    │   └── health/             # Endpoint de salud
    └── test/                   # Pruebas end-to-end (supertest)
```

## Puesta en marcha con Docker (recomendado)

Solo necesitas **Git** y **Docker**. No hace falta instalar Node.js, PostgreSQL
ni Nmap: la base de datos, la API y la aplicación web se ejecutan en contenedores.

- Windows y macOS: [Docker Desktop](https://www.docker.com/products/docker-desktop/).
  En Windows, activa el motor WSL 2 durante la instalación.
- Linux: Docker Engine con el plugin `docker compose`.

### 1. Clonar y arrancar

```bash
git clone <url-del-repositorio>
cd Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM
docker compose up -d --build
```

La primera vez tarda unos minutos porque construye la imagen. Después, al
arrancar el contenedor de la API se hace automáticamente lo siguiente:

1. Espera a que PostgreSQL esté listo.
2. Aplica las migraciones pendientes.
3. Carga la organización y los usuarios de demostración (ver tabla más abajo).
4. Arranca la API con el worker de escaneos y Nmap.
5. Arranca la aplicación web.

Cuando `docker compose ps` muestre `api` y `web` como `healthy`, ya está disponible:

- **Aplicación web: <http://localhost:8080>** (entra con `admin@demo.local` / `Password123!`)
- API: <http://localhost:3000/api/v1>
- Swagger UI: <http://localhost:3000/api/docs>
- Salud: <http://localhost:3000/api/v1/health>

### Comandos habituales

| Acción | Comando |
|--------|---------|
| Ver el estado | `docker compose ps` |
| Ver los logs de la API | `docker compose logs -f api` |
| Ver los logs de la web | `docker compose logs -f web` |
| Detener (conserva los datos) | `docker compose down` |
| Detener y borrar la base de datos | `docker compose down -v` |
| Reconstruir tras un `git pull` | `docker compose up -d --build` |
| Abrir una consola SQL | `docker compose exec db psql -U postgres -d sspm_db` |

### Modo desarrollo (recarga en caliente)

Para programar sin instalar nada en tu equipo, usa el archivo
`docker-compose.dev.yml`. Monta las carpetas `backend/` y `frontend/` en los
contenedores: Nest reinicia la API y Vite recarga la web cada vez que guardas un archivo.

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
```

En este modo la aplicación web está en <http://localhost:5173> y los correos de
alerta no salen a Internet: los captura [Mailpit](https://mailpit.axllent.org/),
visible en <http://localhost:8025>.

Con la API de desarrollo levantada, puedes ejecutar comandos dentro del contenedor:

```bash
# Alias opcional para no repetir los dos archivos (Git Bash, Linux o macOS)
alias dc='docker compose -f docker-compose.yml -f docker-compose.dev.yml'

dc exec api npm test                                   # pruebas unitarias
dc exec api npm run test:e2e                           # pruebas end-to-end
dc exec api npm run lint                               # linter
dc exec api npx prisma migrate dev --name <nombre>     # nueva migración tras editar schema.prisma
dc exec web npm run lint                               # linter del frontend
dc exec web npm run typecheck                          # tipos del frontend
```

Notas del modo desarrollo:

- `node_modules` vive en un volumen propio de cada contenedor, con dependencias
  compiladas para Linux. El `node_modules` de tu equipo, si existe, no se usa.
- Si `package-lock.json` cambia, por ejemplo tras un `git pull`, el contenedor
  sincroniza las dependencias automáticamente al arrancar.
- Los cambios se detectan por sondeo para que funcione en Windows y macOS.

### Conectarse a la base de datos desde tu equipo

Por defecto PostgreSQL no publica ningún puerto: la API llega a la base por la
red interna de Docker, y así no choca con un PostgreSQL instalado en tu equipo.
Para usar una consola SQL no necesitas nada más:

```bash
docker compose exec db psql -U postgres -d sspm_db
```

Para conectarte con una herramienta gráfica (pgAdmin, DBeaver, DataGrip), añade
`docker-compose.db-access.yml`, que publica el puerto solo en `127.0.0.1`:

```bash
docker compose -f docker-compose.yml -f docker-compose.db-access.yml up -d
```

Después conéctate a `localhost:5432`, usuario `postgres`, contraseña `admin`,
base `sspm_db`. Si el 5432 está ocupado, pon otro puerto en `DB_PORT` dentro del
`.env` de la raíz, por ejemplo `DB_PORT=15432`.

### Configuración opcional

`docker compose` funciona sin configuración. Para cambiar puertos, secretos u
otras opciones, copia `.env.example` como `.env` en la raíz del repositorio y
edítalo. Las variables principales son:

| Variable | Por defecto | Uso |
|----------|-------------|-----|
| `API_PORT` | `3000` | Puerto de la API en tu equipo |
| `WEB_PORT` | `8080` | Puerto de la aplicación web (`5173` en modo desarrollo) |
| `DB_PORT` | `5432` | Puerto de PostgreSQL en tu equipo, solo con `docker-compose.db-access.yml` |
| `JWT_SECRET` | valor de desarrollo | Secreto para firmar los tokens |
| `SEED_DEMO_DATA` | `true` | Crear los usuarios de demostración al arrancar |
| `ALLOW_PRIVATE_TARGETS` | `false` | Modo laboratorio, solo en modo desarrollo |
| `SCHEDULER_ENABLED` | `true` | Planificador del monitoreo continuo |
| `ASSET_VERIFICATION_REQUIRED` | `true` | Exigir la verificación de propiedad antes de escanear (no desactivable en producción) |
| `TRUST_PROXY` | `1` en Compose | Saltos de proxy de confianza para conocer la IP real del cliente |
| `AUTH_MAX_FAILED_LOGINS`, `AUTH_LOCKOUT_MINUTES` | `5`, `15` | Bloqueo temporal de una cuenta por intentos fallidos |
| `AUTH_LOGIN_RATE_PER_MINUTE`, `AUTH_REGISTER_RATE_PER_HOUR` | `20`, `5` | Límites por IP en login y registro |
| `CVE_LOOKUP_ENABLED`, `NVD_API_KEY`, `CVE_CACHE_HOURS` | `true`, vacío, `24` | Correlación de versiones con CVE de NVD; la clave gratuita de NVD sube el límite de peticiones |
| `SUBDOMAIN_DISCOVERY_ENABLED`, `SUBDOMAIN_DISCOVERY_MAX_HOSTS` | `true`, `500` | Descubrimiento de subdominios en Certificate Transparency |
| `APP_URL` | `http://localhost:8080` | URL de la web usada en los enlaces de las alertas |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM` | vacío | Servidor de correo para las alertas; sin `SMTP_HOST` los canales de correo se omiten |

La API y la web se publican solo en `127.0.0.1`, así que no son accesibles desde
otros equipos de tu red. La base de datos no se publica salvo que lo pidas.

### Escanear servicios de tu propio equipo

Dentro del contenedor, `localhost` es el propio contenedor, no tu equipo. Para
el caso de estudio con activos controlados:

1. Pon `ALLOW_PRIVATE_TARGETS=true` en el `.env` de la raíz.
2. Arranca en modo desarrollo; el modo laboratorio no se permite en producción.
3. Registra el activo `host.docker.internal`, que apunta a tu equipo.
4. Verifícalo: sirve el archivo `/.well-known/sspm-verification.txt` que indica la
   plataforma desde tu servidor local (en un puerto de `WEB_HTTP_PORTS`), o bien pon
   `ASSET_VERIFICATION_REQUIRED=false` en el `.env` (solo fuera de producción).

### Solución de problemas

- **"port is already allocated" o "Intento de acceso a un socket no permitido"**:
  otro programa usa ese puerto o Windows lo tiene reservado. Si es el 3000 o el 8080,
  cambia `API_PORT` o `WEB_PORT` en el `.env` de la raíz. Si es el 5432 al usar
  `docker-compose.db-access.yml`, cambia `DB_PORT`.
- **Swagger muestra una versión antigua**: quedan contenedores de una versión
  anterior ocupando el puerto. Revisa `docker ps`; si aparecen `sspm-api` o
  `sspm-db` sin el sufijo `-1`, elimínalos con `docker rm -f sspm-api sspm-db`.
- **La API no pasa a `healthy`**: revisa `docker compose logs api`. Si cambiaste
  `POSTGRES_PASSWORD` después de crear la base, borra el volumen con
  `docker compose down -v`; la contraseña solo se aplica la primera vez.
- **`docker-entrypoint.sh: not found` o `$'\r': command not found`**: el script
  tiene finales de línea de Windows. El repositorio lo evita con `.gitattributes`
  y la imagen los corrige al construir; reconstruye con `docker compose build --no-cache api`.

## Puesta en marcha sin Docker

Solo si prefieres ejecutar la API directamente en tu equipo.

### Requisitos previos

- Node.js ≥ 20.18 y npm
- PostgreSQL 16, instalado localmente o solo la base en Docker con
  `docker compose -f docker-compose.yml -f docker-compose.db-access.yml up -d db`
- Nmap ≥ 7.80 accesible en el `PATH` (`sudo apt install nmap`, `brew install nmap` o el instalador oficial en Windows)

### 1. Instalar dependencias

```bash
cd Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM/backend
npm install
```

### 2. Configurar variables de entorno

```bash
cp .env.example .env
```

Ajusta `DATABASE_URL` y `JWT_SECRET` si es necesario. Valores por defecto:

```
DATABASE_URL="postgresql://postgres:admin@localhost:5432/sspm_db?schema=public"
JWT_SECRET=cambia-este-secreto-por-uno-largo-y-aleatorio
```

### 3. Aplicar migraciones y cargar datos de demostración

```bash
npx prisma migrate dev      # aplica migraciones y regenera el cliente
npx prisma db seed          # (opcional) carga una organización de demostración
```

### 4. Arrancar la API

```bash
npm run start:dev           # recarga automática
# o
npm run build && npm start  # modo producción
```

### 5. Arrancar la aplicación web

```bash
cd ../frontend
npm install
npm run dev                 # http://localhost:5173, reenvía /api a http://localhost:3000
```

Para servirla compilada, `npm run build` genera `frontend/dist/`; cualquier servidor
estático vale si reenvía `/api` al backend (ver `frontend/nginx.conf`).

## Usuarios de demostración

Se crean automáticamente con Docker, o con `npx prisma db seed` sin Docker.

| Correo | Rol | Contraseña |
|--------|-----|------------|
| `admin@demo.local` | ADMIN | `Password123!` |
| `analista@demo.local` | ANALYST | `Password123!` |
| `gerente@demo.local` | VIEWER | `Password123!` |

## Aplicación web (frontend)

Dashboard de la sección 8 del documento, construido sobre los endpoints de la API.
Se adapta a móvil y escritorio y respeta el modo claro u oscuro del sistema.

| Pantalla | Qué muestra |
|----------|-------------|
| Inicio de sesión | Acceso con la cuenta de la organización; la sesión se guarda en el navegador |
| Vista general | Security Score con calificación y tendencia, hallazgos por severidad, activos monitoreados, escaneos en curso, evolución de la postura, activos con peor postura, hallazgos prioritarios y escaneos recientes |
| Activos | Tabla ordenada por peor postura con score, hallazgos abiertos y último escaneo; alta de activos con declaración de autorización; auditoría completa con un clic |
| Detalle de activo | Verificación de propiedad con las instrucciones (DNS o archivo) y su comprobación; score con el desglose de la fórmula, último escaneo de cada tipo, evolución, puertos abiertos y hallazgos; activar o desactivar el activo y lanzar escaneos por tipo |
| Hallazgos | Filtros por estado, severidad y categoría; cada fila se expande con descripción, recomendación, evidencia y acciones para aceptar el riesgo, marcar falso positivo o reabrir |
| Escaneos | Historial con estado, resultado y duración, actualizado automáticamente mientras hay escaneos en curso; cancelación. Los del monitoreo continuo llevan la marca "Programado" |
| Alertas | Avisos de puertos nuevos, certificados por vencer y hallazgos críticos, con el resultado de entrega por canal; revisión individual o masiva. El menú muestra cuántas hay pendientes |
| Reportes | Descarga del reporte ejecutivo o técnico en PDF, de la organización o de un activo, e historial de reportes generados. También desde la vista general y el detalle de cada activo |
| Configuración (solo ADMIN) | Frecuencia del monitoreo continuo con la próxima auditoría de cada activo, y canales de notificación (correo o webhook de Slack, Discord o JSON) con envío de prueba |
| Usuarios (solo ADMIN) | Alta de usuarios con contraseña inicial y generador, cambio de rol, restablecimiento de contraseña y activación o desactivación del acceso |
| Mi cuenta | Datos del perfil y la organización, y cambio de la propia contraseña con los requisitos a la vista |

Las acciones de escritura (registrar, auditar, revisar) solo aparecen para los roles
`ADMIN` y `ANALYST`. El rol `VIEWER` ve todo en modo lectura.

Convenciones del código:

- Las páginas obtienen datos con los hooks de `src/hooks/queries.ts`; cada mutación
  invalida las consultas afectadas para que la interfaz se refresque sola.
- Los colores se definen como roles (`bg-surface`, `text-ink`, `text-critical`...) en
  `src/index.css`, con valores distintos para modo claro y oscuro.
- La severidad nunca se comunica solo con color: siempre lleva icono y etiqueta.

## Endpoints disponibles

Todos los endpoints (salvo `health`, `register` y `login`) requieren la cabecera
`Authorization: Bearer <token>`.

| Método | Ruta | Roles | Descripción |
|--------|------|-------|-------------|
| GET | `/api/v1/health` | público | Estado de la API y la base de datos |
| POST | `/api/v1/auth/register` | público | Crea una organización y su primer usuario ADMIN |
| POST | `/api/v1/auth/login` | público | Devuelve un JWT |
| GET | `/api/v1/auth/me` | todos | Usuario autenticado |
| PATCH | `/api/v1/auth/me/password` | todos | Cambiar mi contraseña (exige la actual); cierra mis otras sesiones y devuelve un token nuevo |
| GET | `/api/v1/organizations/me` | todos | Organización del usuario |
| PATCH | `/api/v1/organizations/me` | ADMIN | Renombrar la organización |
| GET | `/api/v1/users` | ADMIN | Usuarios de la organización |
| POST | `/api/v1/users` | ADMIN | Crear usuario en la organización |
| PATCH | `/api/v1/users/:id` | ADMIN | Cambiar rol / activar / desactivar |
| POST | `/api/v1/users/:id/reset-password` | ADMIN | Asignar una contraseña nueva a otro usuario; cierra sus sesiones |
| **POST** | **`/api/v1/assets`** | ADMIN, ANALYST | **RF-01: registrar un dominio o IP** |
| GET | `/api/v1/assets` | todos | Listado paginado (`type`, `isActive`, `search`, `page`, `pageSize`) |
| GET | `/api/v1/assets/:id` | todos | Detalle de un activo |
| GET | `/api/v1/assets/:id/verification` | todos | Estado de la verificación de propiedad e instrucciones (registro DNS o archivo) |
| POST | `/api/v1/assets/:id/verify` | ADMIN, ANALYST | Comprobar la prueba publicada (`method` opcional: `DNS_TXT` o `HTTP_FILE`) |
| PATCH | `/api/v1/assets/:id` | ADMIN, ANALYST | Editar nombre, descripción o estado |
| DELETE | `/api/v1/assets/:id` | ADMIN | Eliminar activo y sus escaneos |
| **POST** | **`/api/v1/assets/:id/scans`** | ADMIN, ANALYST | **Encolar un escaneo: `PORT_SCAN`, `WEB_HEADERS`, `SSL_CERT`, `SENSITIVE_PATHS`, `EMAIL_SECURITY` o `SUBDOMAIN_DISCOVERY` (responde 202)** |
| POST | `/api/v1/assets/:id/scans/all` | ADMIN, ANALYST | Auditoría completa: encola todos los tipos que aplican al activo (seis en dominios, cuatro en IPs) |
| GET | `/api/v1/assets/:id/discovered-hosts` | todos | Subdominios descubiertos del dominio, con su estado (sin inventariar, en inventario, descartado) |
| PATCH | `/api/v1/discovered-hosts/:id` | ADMIN, ANALYST | Descartar o restaurar un subdominio (`ignored`) |
| POST | `/api/v1/discovered-hosts/import` | ADMIN, ANALYST | Registrar subdominios como activos (`ids`, `authorizationConfirmed: true`) |
| GET | `/api/v1/assets/:id/exposure` | todos | Puertos abiertos según el último escaneo completado |
| GET | `/api/v1/scans` | todos | Listado paginado (`assetId`, `status`, `type`, `page`, `pageSize`) |
| GET | `/api/v1/scans/:id` | todos | Estado, resumen y puertos detectados (`?includeRaw=true` añade la salida completa) |
| POST | `/api/v1/scans/:id/cancel` | ADMIN, ANALYST | Cancelar un escaneo pendiente o en ejecución |
| GET | `/api/v1/findings` | todos | RF-08: hallazgos paginados (`assetId`, `severity`, `status`, `category`) |
| GET | `/api/v1/findings/summary` | todos | Conteo de hallazgos abiertos por severidad y categoría (`assetId` opcional) |
| GET | `/api/v1/findings/rules` | todos | Catálogo de reglas con severidad y CVSS de referencia |
| GET | `/api/v1/findings/:id` | todos | Detalle de un hallazgo con evidencia y recomendación |
| PATCH | `/api/v1/findings/:id` | ADMIN, ANALYST | Aceptar el riesgo, marcar falso positivo o reabrir |
| **GET** | **`/api/v1/risk-scores/current`** | todos | **RF-07: Security Score actual de la organización o de un activo (`assetId`), con el desglose de la fórmula** |
| GET | `/api/v1/risk-scores/history` | todos | RF-11: histórico de postura (`assetId`, `from`, `to`, `granularity=day\|raw`) |
| GET | `/api/v1/risk-scores/model` | todos | Fórmula, pesos, topes y calificaciones del modelo |
| POST | `/api/v1/risk-scores/recalculate` | ADMIN, ANALYST | Recalcular y registrar una instantánea de todos los activos |
| GET | `/api/v1/dashboard/overview` | todos | Vista general: score, tendencia, hallazgos, activos y escaneos recientes |
| GET | `/api/v1/dashboard/assets` | todos | Tabla de activos con score y hallazgos, peor postura primero |
| GET | `/api/v1/dashboard/assets/:id` | todos | Vista detallada de un activo: score, histórico, hallazgos y puertos abiertos |
| GET | `/api/v1/dashboard/history` | todos | Serie diaria del score de la organización (`days`, por defecto 30) |
| GET | `/api/v1/alerts` | todos | RF-10: alertas paginadas (`acknowledged`, `severity`, `type`, `assetId`) |
| GET | `/api/v1/alerts/summary` | todos | Alertas pendientes por severidad |
| POST | `/api/v1/alerts/:id/acknowledge` | ADMIN, ANALYST | Marcar una alerta como revisada |
| POST | `/api/v1/alerts/acknowledge-all` | ADMIN, ANALYST | Marcar todas las pendientes como revisadas |
| GET/POST | `/api/v1/alerts/channels` | ADMIN | Listar o crear canales de correo o webhook (las URL se devuelven enmascaradas) |
| PATCH/DELETE | `/api/v1/alerts/channels/:id` | ADMIN | Editar o eliminar un canal |
| POST | `/api/v1/alerts/channels/:id/test` | ADMIN | Enviar una notificación de prueba |
| GET | `/api/v1/monitoring` | todos | Sección 10.4: frecuencia y próxima auditoría de cada activo |
| PATCH | `/api/v1/monitoring` | ADMIN | Cambiar la frecuencia (`OFF`, `DAILY`, `WEEKLY`) |
| GET | `/api/v1/reports/executive` | todos | RF-09: reporte ejecutivo en PDF (`assetId` opcional) |
| GET | `/api/v1/reports/technical` | todos | RF-09: reporte técnico en PDF (`assetId` opcional) |
| GET | `/api/v1/reports` | todos | Historial de reportes generados |

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
- La declaración no basta para escanear: hay que **verificar la propiedad** del activo
  (ver [Verificación de propiedad](#verificación-de-propiedad-de-activos)). Un
  subdominio de un dominio ya verificado por DNS queda verificado al registrarse.
- La unicidad es **por organización** (`organization_id` + `value`); un duplicado
  responde `409 Conflict`.

### Ejemplo: escanear un activo

```bash
# 1. Encolar un escaneo (responde 202 con estado PENDING). Sin `type` se hace PORT_SCAN.
SCAN_ID=$(curl -s -X POST http://localhost:3000/api/v1/assets/<ASSET_ID>/scans \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"type":"WEB_HEADERS"}' | jq -r .id)

# O encolar la auditoría completa (todos los tipos que aplican al activo)
curl -s -X POST http://localhost:3000/api/v1/assets/<ASSET_ID>/scans/all -H "Authorization: Bearer $TOKEN"

# 2. Consultar el estado hasta que sea COMPLETED o FAILED
curl -s http://localhost:3000/api/v1/scans/$SCAN_ID -H "Authorization: Bearer $TOKEN" | jq '{status, summary, ports}'

# 3. Superficie expuesta actual del activo
curl -s http://localhost:3000/api/v1/assets/<ASSET_ID>/exposure -H "Authorization: Bearer $TOKEN"

# 4. Hallazgos abiertos ordenados por severidad, y resumen para el dashboard
curl -s "http://localhost:3000/api/v1/findings?assetId=<ASSET_ID>&status=OPEN" -H "Authorization: Bearer $TOKEN"
curl -s "http://localhost:3000/api/v1/findings/summary" -H "Authorization: Bearer $TOKEN"
```

## Módulo de escaneo

### Flujo común

1. `POST /assets/:id/scans` valida permisos, estado del activo y límites, y crea el
   registro en `scans` con estado `PENDING`.
2. El worker reclama el trabajo (`PENDING` → `RUNNING`) con `FOR UPDATE SKIP LOCKED`.
3. El dominio se resuelve por DNS. Si alguna IP resultante es privada o reservada, el
   escaneo se bloquea. A los escáneres se les entrega la IP ya validada, nunca el texto del usuario.
   Los escáneres pasivos (`EMAIL_SECURITY` y `SUBDOMAIN_DISCOVERY`) no se conectan al
   activo: solo consultan DNS y fuentes públicas, así que omiten este paso.
4. Se ejecuta el escáner del tipo solicitado (tabla siguiente) y sus resultados se
   convierten en hallazgos mediante el catálogo de reglas.
5. Se guardan resumen (`scans.summary`), salida completa (`scans.raw_result`), puertos
   (`scan_ports`) y hallazgos (`findings`), y se actualiza `assets.last_scanned_at`.
6. El estado final es `COMPLETED`, `FAILED` (con `error_message`) o `CANCELLED`.

### Tipos de escaneo

| Tipo | Requisito | Qué hace |
|------|-----------|----------|
| `PORT_SCAN` | RF-02, RF-03 | Nmap con `spawn` sin shell: `nmap -sT -sV -Pn -n -T4 --max-retries 2 --host-timeout <s> --top-ports 1000 -oX - <IP>`. Cada puerto abierto genera un hallazgo clasificado por el servicio (base de datos, escritorio remoto, Telnet, Docker...). Las versiones detectadas se cruzan con los CVE publicados (ver más abajo). |
| `WEB_HEADERS` | RF-04 | Pide `/` por HTTPS y HTTP (puertos configurables más los detectados por Nmap), sigue redirecciones y evalúa HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, divulgación de versiones, atributos de cookies y redirección HTTP→HTTPS. |
| `SSL_CERT` | RF-05 | Conecta por TLS y comprueba caducidad (vencido, < 7 días, < 30 días), validez futura, coincidencia del nombre, cadena de confianza, TLS 1.0/1.1, tamaño de clave, algoritmo de firma y ausencia de HTTPS. |
| `SENSITIVE_PATHS` | RF-06 | Solicita unas 60 rutas conocidas (`.env`, `.git/`, volcados SQL, `phpinfo.php`, paneles, listados) y solo reporta las que cumplen una firma de contenido, lo que descarta los sitios que responden 200 a todo. Nunca almacena el contenido del archivo. |
| `EMAIL_SECURITY` | Solo dominios | SPF, DMARC y DKIM a partir de los registros DNS públicos (ver más abajo). |
| `SUBDOMAIN_DISCOVERY` | Solo dominios | Subdominios en los registros de Certificate Transparency, resueltos en DNS, para detectar activos fuera del inventario. |

### Vulnerabilidades conocidas (CVE)

Nmap identifica el software y su versión con un CPE (`cpe:/a:openbsd:openssh:7.4p1`).
Tras el escaneo de puertos, la plataforma consulta en la
[API 2.0 de NVD](https://nvd.nist.gov/developers/vulnerabilities) todos los CVE del
producto y decide **localmente** qué versiones están afectadas con los rangos de cada CVE
(`versionStartIncluding`, `versionEndExcluding`...). Así una sola descarga sirve para
todas las versiones y se guarda en `cve_product_cache` (`CVE_CACHE_HOURS`, 24 h por
defecto) para respetar el límite de NVD (5 peticiones cada 30 s sin clave, 50 con
`NVD_API_KEY`).

- Un hallazgo `VULN-KNOWN-CVE` por servicio vulnerable, con el total de CVE, los 20 más
  relevantes en la evidencia (enlace a NVD, CVSS, descripción) y la severidad y CVSS del
  más grave.
- Los CVE del catálogo **KEV de CISA** (explotados activamente, dato que publica NVD) van
  primero y elevan la severidad: a crítica si ya era alta y a alta en otro caso.
- **Backports:** si el banner indica un paquete de distribución (Ubuntu, Debian, RHEL...),
  la severidad baja un nivel y el hallazgo lo explica, porque estas distribuciones corrigen
  vulnerabilidades sin cambiar el número de versión. Se puede marcar como falso positivo.
- No se usan versiones imprecisas de Nmap (`9.6.0 or later`, `2.4.X`) ni los CPE de sistema
  operativo.
- Si NVD no responde se usa la caché caducada; si no la hay, los hallazgos de CVE abiertos
  **se conservan** en lugar de darse por resueltos, y el resumen del escaneo lo indica.

### Seguridad del correo (SPF, DMARC, DKIM)

Solo consultas DNS: el escáner no envía correo ni se conecta a los servidores.

| Regla | Severidad | Qué detecta |
|-------|-----------|-------------|
| `MAIL-SPF-MISSING` | Media (baja si el dominio no recibe correo) | Sin registro SPF; en dominios sin correo se recomienda `v=spf1 -all`. No se reporta si el dominio no recibe correo y un DMARC que rechaza ya lo protege |
| `MAIL-SPF-INVALID` | Media | Varios registros, mecanismos no válidos, `include` sin SPF, bucles o más de 10 consultas DNS |
| `MAIL-SPF-PASS-ALL` | Alta | `+all`: autoriza a cualquier servidor |
| `MAIL-SPF-NEUTRAL` | Media | `?all` o sin `all` |
| `MAIL-SPF-SOFTFAIL` | Baja | `~all` sin un DMARC que rechace o ponga en cuarentena |
| `MAIL-DMARC-MISSING` | Media | Ni el dominio ni sus dominios superiores publican DMARC |
| `MAIL-DMARC-INVALID` | Media | Varios registros o sin política `p=` válida |
| `MAIL-DMARC-MONITOR-ONLY` | Media | Política efectiva `none` (propia o `sp` heredada) |
| `MAIL-DMARC-PARTIAL` | Baja | `pct` < 100 |
| `MAIL-DMARC-SUBDOMAINS-UNPROTECTED` | Baja | `sp=none` con la política principal activa |
| `MAIL-DMARC-NO-REPORTS` | Informativa | Sin `rua`, no se reciben informes |
| `MAIL-DKIM-NOT-FOUND` | Baja | Dominio con correo sin clave en los ~37 selectores habituales (Google, Microsoft 365, Zoho, SendGrid...) |
| `MAIL-DKIM-WEAK-KEY` | Media (< 1024 bits) o baja (1024) | Clave RSA de menos de 2048 bits |

Un subdominio sin DMARC propio hereda el del dominio organizativo (se aplica `sp`). Un
fallo del DNS (timeout, SERVFAIL) hace fallar el escaneo en lugar de reportar
registros ausentes.

### Descubrimiento de subdominios (shadow IT)

Todo certificado TLS emitido por una CA pública queda en los registros de
Certificate Transparency con sus nombres. El escáner los consulta en
[crt.sh](https://crt.sh) (y en [Cert Spotter](https://sslmate.com/certspotter/) si
crt.sh falla), se queda con los subdominios del dominio (`*.x` cuenta como `x`,
marcado como comodín), los resuelve en DNS y los guarda en `discovered_hosts`.

- En la ficha del dominio se ven los subdominios **sin inventariar**, en inventario y
  descartados, con las IP a las que resuelven y una marca si alguna es **interna** (el
  certificado revela infraestructura privada).
- Se pueden **incorporar al inventario** en bloque (confirmando la autorización): los que
  cuelgan de un dominio verificado por DNS heredan la verificación y se pueden auditar
  enseguida. También se pueden descartar.
- El primer descubrimiento es la línea base; en los siguientes, los subdominios nuevos
  fuera del inventario generan la alerta `NEW_SUBDOMAIN`.
- La consulta envía el nombre del dominio a esos servicios públicos; se puede desactivar
  con `SUBDOMAIN_DISCOVERY_ENABLED=false`.

### Hallazgos (RF-08)

- Cada hallazgo referencia una regla del catálogo (`GET /findings/rules`) con severidad y
  puntuación CVSS v3.1 de referencia: `CRITICAL` ≥ 9.0, `HIGH` ≥ 7.0, `MEDIUM` ≥ 4.0, `LOW` > 0, `INFO` = 0.
- Se deduplican por activo mediante `fingerprint` = sha256(regla + ubicación). Un mismo
  problema detectado en escaneos sucesivos es un único hallazgo con `first_seen_at` y `last_seen_at`.
- Ciclo de vida: `OPEN` mientras se detecta; pasa a `RESOLVED` cuando un escaneo posterior
  del mismo tipo ya no lo encuentra, y se reabre si reaparece. `ACCEPTED` y `FALSE_POSITIVE`
  los fija el usuario y se conservan entre escaneos.
- `GET /findings/summary` devuelve los conteos que alimentan el Security Score.

## Motor de riesgo y Security Score (RF-07)

Implementa la sección 6.3 del documento. El código está en `backend/src/risk/scoring.ts`
y `GET /risk-scores/model` devuelve el modelo vigente.

### Fórmula

```
Score = 100 − Σ min(Tope_s, Peso_s × Abiertos_s)      acotado a [0, 100]
```

Solo cuentan los hallazgos en estado `OPEN`. Los `ACCEPTED` (riesgo aceptado), los
`FALSE_POSITIVE` y los `RESOLVED` no penalizan, así que revisar un hallazgo cambia el score.

| Severidad | Rango CVSS v3.1 | Peso por hallazgo | Tope de penalización |
|-----------|-----------------|-------------------|----------------------|
| CRITICAL | 9.0 – 10.0 | 25 | 100 |
| HIGH | 7.0 – 8.9 | 10 | 60 |
| MEDIUM | 4.0 – 6.9 | 4 | 30 |
| LOW | 0.1 – 3.9 | 1 | 10 |
| INFO | 0.0 | 0 | 0 |

Los topes (reglas de penalización, 6.3.4) evitan que muchos hallazgos menores hundan
la puntuación por sí solos u oculten uno crítico. Un solo hallazgo crítico deja el
score en 75 y cuatro lo llevan a 0.

### Calificación (6.3.5)

| Score | Grado | Nivel |
|-------|-------|-------|
| 90 – 100 | A | Excelente |
| 75 – 89 | B | Buena |
| 60 – 74 | C | Aceptable |
| 40 – 59 | D | Deficiente |
| 0 – 39 | F | Crítica |

### Activo y organización

- Un activo se evalúa cuando tiene al menos un escaneo completado; hasta entonces su
  score es nulo y no cuenta.
- El score de la organización es la media redondeada de los scores de sus activos
  activos y evaluados. Así no depende del número de activos registrados; los conteos
  globales por severidad se reportan aparte para no ocultar la gravedad.
- Desactivar un activo lo excluye del cálculo.

### Histórico de postura (RF-11)

Cada vez que cambia la información que alimenta el score se guarda una instantánea
en `risk_scores`, una del activo y otra de la organización:

| Evento | `trigger` |
|--------|-----------|
| Escaneo completado | `SCAN_COMPLETED` |
| Hallazgo aceptado, descartado o reabierto | `FINDING_REVIEWED` |
| Activo activado, desactivado o eliminado | `ASSET_CHANGED` |
| `POST /risk-scores/recalculate` | `MANUAL` |

`GET /risk-scores/history` devuelve la serie, por defecto con la última instantánea de
cada día. `GET /dashboard/overview` incluye la tendencia frente a la instantánea anterior
y frente a hace siete días.

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
| `WEB_HTTPS_PORTS` | `443` | Puertos HTTPS a auditar, además de los detectados por Nmap |
| `WEB_HTTP_PORTS` | `80` | Puertos HTTP a auditar, además de los detectados por Nmap |
| `WEB_REQUEST_TIMEOUT_MS` | `10000` | Tiempo máximo por petición HTTP o TLS |
| `WEB_PATHS_CONCURRENCY` | `4` | Peticiones simultáneas al comprobar rutas sensibles |
| `ALLOW_PRIVATE_TARGETS` | `false` | Modo laboratorio, ver abajo |

### Modo laboratorio

Para el caso de estudio con activos controlados (sección 13.5) se puede activar
`ALLOW_PRIVATE_TARGETS=true`. Permite registrar y escanear IPs privadas, `localhost`
o máquinas virtuales de una red local. La aplicación se niega a arrancar si se activa
con `NODE_ENV=production`.

```bash
ALLOW_PRIVATE_TARGETS=true SCAN_PORTS=22,80,443,5432 WEB_HTTPS_PORTS=8443 npm run start:dev
```

## Verificación de propiedad de activos

Declarar que se tiene autorización no impide registrar el dominio de otra empresa y
escanearlo desde nuestros servidores. Por eso **no se escanea ningún activo cuya
propiedad no se haya demostrado** (sección 1.6.3): ni por petición manual, ni en la
auditoría completa, ni en el monitoreo continuo. El worker vuelve a comprobarlo antes
de ejecutar.

Cada organización tiene un token secreto y publica el valor
`sspm-verification=<token>` de una de estas formas:

| Método | Dónde | Alcance |
|--------|-------|---------|
| `DNS_TXT` (recomendado) | Registro TXT en `_sspm-verification.<dominio>` | El dominio y **todos sus subdominios**: los que ya estén registrados y los que se registren después quedan verificados (`INHERITED`) |
| `HTTP_FILE` | Archivo `/.well-known/sspm-verification.txt` con ese contenido exacto, servido por el propio host en `WEB_HTTPS_PORTS` o `WEB_HTTP_PORTS` | Solo ese host. Es la única opción para direcciones IP |

- La prueba DNS se busca desde el nombre del activo hacia los dominios superiores
  (`a.tienda.example.com`, `tienda.example.com`, `example.com`).
- El archivo no sigue redirecciones: una redirección abierta del sitio no puede
  usarse para "demostrar" la propiedad con un archivo alojado en otro dominio.
- La verificación es por organización: la de una no sirve para otra.
- Un intento fallido no retira una verificación anterior; queda registrado con el
  detalle de cada comprobación para que el usuario vea qué falta.
- `scanme.nmap.org`, que el proyecto Nmap ofrece públicamente para practicar, viene
  pre-autorizado en los datos de demostración.
- `ASSET_VERIFICATION_REQUIRED=false` desactiva la exigencia en pruebas o
  laboratorio; la aplicación se niega a arrancar así con `NODE_ENV=production`.

## Alertas tempranas (RF-10)

Al completar cada escaneo se evalúan cuatro reglas (`backend/src/alerts/alert-rules.ts`):

| Tipo | Cuándo se genera | Severidad |
|------|------------------|-----------|
| `NEW_OPEN_PORT` | Un puerto abierto que no estaba en el escaneo de puertos anterior del activo. El primer escaneo es la línea base y no alerta. | La del hallazgo del puerto, mínimo media |
| `CERT_EXPIRING` | El hallazgo de certificado caducado, a menos de 7 días o a menos de 30 días aparece o se reabre | La del hallazgo |
| `CRITICAL_FINDING` | Hallazgos críticos nuevos o reabiertos no cubiertos por las anteriores (agrupados en una alerta por escaneo); incluye los CVE explotados activamente | Crítica |
| `NEW_SUBDOMAIN` | Subdominios que aparecen por primera vez en Certificate Transparency y no están en el inventario. El primer descubrimiento es la línea base y no alerta. | Media |

Como solo cuentan los hallazgos que **pasan a abiertos**, un problema que persiste no
genera una alerta en cada escaneo.

Cada alerta se guarda en `alerts` y se notifica, **de forma asíncrona** (sin retrasar
al worker), por los canales activos de la organización cuya severidad mínima cubre la
de la alerta. El resultado de cada envío (`SENT`, `FAILED` o `SKIPPED`) queda en la
alerta y en el canal.

- **Correo:** SMTP con Nodemailer. Sin `SMTP_HOST` el envío se marca `SKIPPED`.
- **Webhook:** cuerpo adaptado a Slack (`hooks.slack.com`), Discord
  (`discord.com/api/webhooks`) o JSON genérico (`event: alert.created`). La URL es
  un secreto: se muestra enmascarada.

Protección contra SSRF en los webhooks (sección 11.3): solo `https://` hacia dominios
o IPs públicas, sin credenciales en la URL; en cada envío se resuelve el DNS, se
rechazan direcciones privadas, se conecta a la IP validada (nombre en Host/SNI, TLS
verificado) y no se siguen redirecciones. En modo laboratorio se admiten HTTP y hosts
locales para las pruebas.

## Monitoreo continuo (sección 10.4)

Cada organización elige en **Configuración** una frecuencia: `OFF` (por defecto),
`DAILY` o `WEEKLY`. El planificador (`backend/src/monitoring/`) revisa cada
`SCHEDULER_INTERVAL_MS` qué activos activos y autorizados están vencidos y encola su
auditoría completa como escaneos con `source = SCHEDULED`.

- **Varias instancias:** cada activo se reclama con un `UPDATE` condicional sobre
  `last_scheduled_scan_at`, así que solo una instancia lo encola por periodo.
- **Sin duplicados:** los tipos con un escaneo ya en curso se omiten.
- **Límites:** los escaneos programados respetan la concurrencia global y por
  organización, pero no consumen el límite por hora pensado para las peticiones manuales.
- Con `SCHEDULER_ENABLED=false` una instancia no planifica (útil si se separa en un
  proceso propio).

## Reportes PDF (RF-09)

`GET /reports/executive` y `GET /reports/technical` generan el PDF bajo demanda con los
datos vigentes, de la organización o de un activo (`assetId`). Cada generación se
registra en `reports` (quién, cuándo, score y tamaño); el PDF no se almacena.

- **Ejecutivo (gerencia):** score con su tendencia semanal, resumen en lenguaje de
  negocio, hallazgos por severidad, evolución de 30 días, principales riesgos,
  recomendaciones agrupadas por acción, activos con peor postura, alertas y anexo
  metodológico del Security Score.
- **Técnico (TI):** por activo, del peor al mejor score: último escaneo de cada tipo,
  puertos abiertos y cada hallazgo abierto con CVSS, ubicación, fechas, descripción,
  recomendación y evidencia.

## Modelo multi-tenant y RBAC

- Cada usuario pertenece a **una** organización; el JWT incluye `org` y `role`.
- El identificador de organización **nunca** se acepta desde la URL ni el cuerpo:
  se toma siempre del token, y todas las consultas filtran por `organization_id`.
- Acceder a un recurso de otra organización responde `404` (no se revela su existencia).
- Cambiar o restablecer una contraseña incrementa `users.token_version`, que viaja en el
  JWT: todas las sesiones anteriores de ese usuario dejan de ser válidas al instante.
- `JwtAuthGuard` y `RolesGuard` son globales: todo endpoint exige token salvo los
  marcados con `@Public()`, y `@Roles(...)` restringe por rol.
- La estrategia JWT recarga el usuario en cada petición, por lo que desactivar una
  cuenta u organización tiene efecto inmediato aunque el token siga vigente.

| Rol | Perfil (documento) | Permisos |
|-----|--------------------|----------|
| `ADMIN` | Administrador de TI | Gestiona usuarios, activos, escaneos y la organización |
| `ANALYST` | Desarrollador | Registra/edita activos y lanza escaneos |
| `VIEWER` | Gerente | Solo lectura (listados, dashboard, reportes) |

## Modelo de datos

Tablas creadas por las migraciones (sección 6.2 del documento, más `scan_ports`):

- **organizations**: tenant (`name`, `slug`, `is_active`).
- **users**: `email` único, `password_hash` (bcrypt), `role`, `organization_id`,
  `token_version` (revocación de sesiones) y `password_changed_at`.
- **assets**: `type`, `value` (único por organización), `authorization_confirmed`,
  `created_by_id`, `last_scanned_at`.
- **scans**: `asset_id`, `type` (`PORT_SCAN`, `WEB_HEADERS`, `SSL_CERT`,
  `SENSITIVE_PATHS`, `EMAIL_SECURITY`, `SUBDOMAIN_DISCOVERY`), `status` (`PENDING` → `RUNNING` → `COMPLETED`/`FAILED`/`CANCELLED`),
  `target_address` (IP escaneada), `parameters`, `raw_result` y `summary` en JSONB.
- **scan_ports**: un registro por puerto detectado en cada escaneo: `port`, `protocol`,
  `state`, `service_name`, `product`, `version`, `extra_info`, `tunnel`, `cpe`. Permite
  consultar la superficie expuesta y comparar escaneos (base de las alertas de nuevos puertos).
- **findings**: hallazgos deduplicados por activo: `rule_id`, `category`, `severity`,
  `cvss_score`, `status`, `title`, `description`, `recommendation`, `location`, `evidence`,
  `fingerprint`, `first_seen_at`, `last_seen_at`, `resolved_at`, `reviewed_by_id`, `review_note`.

- **risk_scores**: instantáneas del Security Score por activo (`scope = ASSET`) y por
  organización (`scope = ORGANIZATION`): `score`, `grade`, conteos por severidad,
  `scored_assets`, `breakdown` con el desglose de la fórmula, `trigger` y `scan_id`.

- **alerts**: alertas tempranas: `type`, `severity`, `title`, `message`, `data` (puertos,
  hallazgos, fechas), `deliveries` (resultado por canal), `acknowledged_at`/`acknowledged_by_id`.
- **alert_channels**: canales de notificación por organización: `type` (`EMAIL` o
  `WEBHOOK`), `target`, `min_severity`, `is_active` y el resultado del último envío.
- **discovered_hosts**: subdominios descubiertos por organización (`hostname` único),
  `asset_id` del dominio que los encontró, `resolves`, `addresses`, `wildcard`,
  `last_certificate_at`, `ignored_at`, `first_seen_at` y `last_seen_at`.
- **cve_product_cache**: caché global de NVD por producto (`vendor:product`) con los CVE
  reducidos a id, CVSS, KEV, descripción y rangos de versiones afectadas.
- **login_attempts**: intentos fallidos de inicio de sesión por cuenta (clave sha256 del
  correo), con `failures` y `locked_until`.
- **reports**: registro de reportes generados: `type`, `asset_id` (nulo = organización),
  `generated_by_id`, `score`, `grade`, `open_findings`, `pages`, `size_bytes`.

Además, `organizations.monitoring_frequency`, `assets.last_scheduled_scan_at` y
`scans.source` (`MANUAL` o `SCHEDULED`) soportan el monitoreo continuo, y
`organizations.verification_token` junto con `assets.verified_at`,
`verification_method`, `verification_scope`, `verification_checked_at` y
`verification_error` soportan la verificación de propiedad.

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
- **Bloqueo por fuerza bruta:** tras `AUTH_MAX_FAILED_LOGINS` fallos seguidos (5) la
  cuenta queda bloqueada `AUTH_LOCKOUT_MINUTES` (15) y responde `429` aunque la
  contraseña sea correcta. El contador vive en PostgreSQL (`login_attempts`, con el
  hash sha256 del correo como clave), sirve con varias instancias y se aplica también a correos
  que no existen, así que no revela qué cuentas hay. Restablecer la contraseña desde
  administración desbloquea la cuenta.
- **Límites por IP:** `AUTH_LOGIN_RATE_PER_MINUTE` (20) intentos de login por minuto y
  `AUTH_REGISTER_RATE_PER_HOUR` (5) registros de organización por hora. Detrás de un
  proxy hay que definir `TRUST_PROXY` (en Docker Compose ya vale `1`, por el Nginx de la
  web); si no, todos los clientes compartirían la IP del proxy.
- **Solo se escanean activos verificados** (ver
  [Verificación de propiedad](#verificación-de-propiedad-de-activos)).
- Política de contraseñas única para todos los formularios: 8 a 72 caracteres, con
  mayúscula, minúscula y número. La aplicación web muestra los requisitos mientras se escribe.
- Cambio de contraseña y restablecimiento por un administrador, que cierran las demás sesiones.
- `helmet` para cabeceras HTTP seguras y CORS restringido por `CORS_ORIGINS`.
- Validación estricta de entrada (`whitelist` + `forbidNonWhitelisted`).
- Los valores de activos se validan como FQDN/IP antes de persistirse y de nuevo antes
  de cada escaneo.
- Nmap recibe siempre una IP literal validada y se ejecuta con `spawn` sin shell, con
  un entorno mínimo y sin privilegios (escaneo `-sT`), lo que evita la inyección de
  comandos (sección 11.2).
- La auditoría web conecta directamente a la IP validada y envía el nombre en `Host` y SNI,
  así una redirección o un cambio de DNS no pueden desviar las peticiones a la red interna.
- Los hallazgos de rutas sensibles guardan solo la ruta y el código de estado, nunca el
  contenido del archivo.
- Las consultas a fuentes externas solo envían datos públicos: el producto (`vendor:product`)
  a NVD y el nombre del dominio a Certificate Transparency. Las respuestas tienen límite de
  tamaño y de tiempo, y se pueden desactivar (`CVE_LOOKUP_ENABLED`, `SUBDOMAIN_DISCOVERY_ENABLED`).
- Los webhooks de alertas se validan igual que los objetivos de escaneo (solo HTTPS a
  hosts públicos, IP validada en cada envío, sin redirecciones) y sus URL, que son
  secretas, se devuelven enmascaradas. Los correos se construyen sin acceso a archivos
  ni URLs (`disableFileAccess`, `disableUrlAccess`) y con el contenido escapado.
- La imagen Docker ejecuta la API y Nmap como usuario sin privilegios y desactiva
  la telemetría de Prisma y de Scarf.
- `docker compose` publica los puertos solo en `127.0.0.1`.

## Próximos pasos

El alcance funcional del MVP (RF-01 a RF-11) está completo. Las siguientes fases
(publicación de imágenes y despliegue continuo, observabilidad, funciones de IA y
expansión a postura en la nube) están en [`docs/roadmap.md`](docs/roadmap.md).
