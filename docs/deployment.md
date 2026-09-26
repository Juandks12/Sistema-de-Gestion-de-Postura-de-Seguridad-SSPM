# Guía de despliegue

Para desarrollo local, ver el README (`Puesta en marcha con Docker`). Esta
guía cubre despliegue en un entorno real (staging/producción) fuera de tu
equipo.

## 1. Requisitos de infraestructura

- Un host (VM o servicio administrado) con Docker Engine, o un clúster
  capaz de correr `docker-compose.yml` tal cual (Docker Swarm, o un
  `docker compose`-compatible en un solo nodo). **No** se necesita
  Kubernetes en esta etapa (ver `docs/architecture.md`, sección 4).
- PostgreSQL 16: puede ser el contenedor `db` del compose (con volumen
  persistente respaldado) o un servicio administrado (RDS, Cloud SQL,
  Azure Database for PostgreSQL) apuntando `DATABASE_URL` a él.
- Un dominio con TLS (Nginx del frontend puede terminar TLS, o ponerlo
  detrás de un balanceador/reverse proxy como Caddy, Traefik o un ALB con
  certificado gestionado).

## 2. Variables de entorno obligatorias en producción

| Variable | Nota |
|---|---|
| `NODE_ENV=production` | Desactiva `ALLOW_PRIVATE_TARGETS` aunque esté en `.env` (falla al arrancar si ambas están activas). |
| `JWT_SECRET` | Debe ser un secreto largo y aleatorio, distinto al de desarrollo. Rotar invalida todas las sesiones activas. |
| `DATABASE_URL` | Apuntando a la base de datos de producción, con `sslmode=require` si el proveedor lo exige. |
| `CORS_ORIGINS` | Dominio(s) reales del frontend, nunca `*`. |
| `SEED_DEMO_DATA=false` | No crear usuarios de demostración en producción. |
| `APP_URL` | URL pública de la web: se usa en los enlaces de las alertas. |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM` | Servidor de correo para las alertas y para la recuperación de contraseña e invitaciones (p. ej. Amazon SES, SendGrid o Postmark por SMTP). Sin `SMTP_HOST` esos correos no se envían: la recuperación de contraseña queda sin vía y las invitaciones hay que crearlas a mano desde Usuarios. |
| `TRUST_PROXY` | Número de proxies delante de la API (1 con el Nginx de la imagen web; 2 si además hay un balanceador). Sin él, los límites por IP del login tratarían a todos los clientes como uno solo. No lo pongas si la API está expuesta sin proxy: el cliente podría falsear su IP. |
| `ASSET_VERIFICATION_REQUIRED` | Siempre `true` (la aplicación no arranca con `false` en producción). |
| `NVD_API_KEY` | Recomendada: con varios clientes, el límite sin clave de NVD (5 peticiones cada 30 s) ralentiza los escaneos de puertos que consultan productos nuevos. Es gratuita. |
| Salida a Internet | La API necesita salir por HTTPS a `services.nvd.nist.gov`, `crt.sh` y `api.certspotter.com`, y hacer consultas DNS (UDP y TCP al puerto 53) para la seguridad del correo. Si la red lo impide, desactiva `CVE_LOOKUP_ENABLED` o `SUBDOMAIN_DISCOVERY_ENABLED`. |
| `SCHEDULER_ENABLED` | Puede quedar en `true` en varias réplicas: cada activo se reclama una sola vez por periodo. Si el planificador se separa en un proceso propio, pon `false` en las instancias de la API. |

## 3. Migraciones en despliegue

`docker-entrypoint.sh` aplica `prisma migrate deploy` automáticamente al
arrancar el contenedor `api`. Para despliegues con múltiples réplicas,
asegúrate de que las migraciones corran una sola vez (ej. un job de
despliegue separado, o aceptar que Prisma serializa migraciones
concurrentes de forma segura vía `advisory lock`, que es su comportamiento
por defecto).

## 4. Checklist antes de exponer el sistema a un cliente real

- [ ] TLS terminado correctamente (no servir HTTP plano).
- [ ] `JWT_SECRET` único y fuera del control de versiones.
- [ ] Backups automáticos de PostgreSQL (el histórico de `risk_scores` y
      `findings` es el activo de valor del producto).
- [ ] Límites de escaneo (`SCAN_MAX_PER_HOUR_PER_ORG`, concurrencia)
      revisados para el volumen de clientes esperado.
- [ ] `TRUST_PROXY` coherente con la cadena de proxies real (ver tabla).
- [ ] `NVD_API_KEY` configurada y salida a NVD, crt.sh y DNS permitida (ver tabla).
- [ ] SMTP configurado y probado con el botón "Probar" de Configuración (o al menos un webhook).
- [ ] Logs centralizados (ver roadmap DevOps en `docs/roadmap.md`).
- [ ] Página de estado / health check (`/api/v1/health`) monitoreada
      externamente (uptime robot, Better Uptime, etc.).

## 5. Ruta recomendada de CI/CD

Ver `.github/workflows/`: en cada PR se corre lint + test de backend y
frontend, y build de las imágenes Docker (sin publicarlas). El siguiente
paso natural (no implementado aún) es publicar las imágenes a un registro
(GHCR) en cada merge a `main` y disparar el despliegue mediante
`docker compose pull && docker compose up -d` en el host de destino, o
migrar a un proveedor con despliegue continuo nativo (Render, Railway,
Fly.io) si se prefiere no operar el host directamente.
