#!/bin/sh
# Punto de entrada de la imagen de la API.
# Prepara la base de datos y después ejecuta el comando del contenedor.
set -e

PRISMA=./node_modules/.bin/prisma

if [ ! -x "$PRISMA" ]; then
  echo "[entrypoint] Prisma no está instalado en /app; se omite la preparación de la base de datos."
  exec "$@"
fi

if [ "$NODE_ENV" != "production" ]; then
  # En desarrollo node_modules vive en un volumen propio. Si package-lock.json
  # cambió desde que se creó ese volumen, se sincronizan las dependencias.
  if [ -f node_modules/.package-lock.sha256 ] \
    && ! sha256sum -c --status node_modules/.package-lock.sha256 2>/dev/null; then
    echo "[entrypoint] package-lock.json cambió: sincronizando dependencias..."
    npm install
    sha256sum package-lock.json > node_modules/.package-lock.sha256
  fi

  # El esquema puede haber cambiado en el código montado desde el host.
  echo "[entrypoint] Generando el cliente de Prisma..."
  $PRISMA generate > /dev/null
fi

if [ "${RUN_MIGRATIONS:-true}" = "true" ]; then
  echo "[entrypoint] Aplicando migraciones pendientes..."
  $PRISMA migrate deploy
fi

if [ "${SEED_DEMO_DATA:-false}" = "true" ]; then
  echo "[entrypoint] Cargando datos de demostración..."
  if [ -f dist-seed/seed.js ]; then
    node dist-seed/seed.js
  else
    ./node_modules/.bin/ts-node prisma/seed.ts
  fi
fi

exec "$@"
