# syntax=docker/dockerfile:1
#
# Imagen de la API del SSPM. Etapas:
#   development -> dependencias completas y recarga en caliente (docker-compose.dev.yml)
#   production  -> solo dependencias de ejecución, código compilado y usuario sin privilegios
#
# Base: Ubuntu 24.04 LTS con Nmap del repositorio oficial y el runtime de Node
# copiado desde la imagen oficial de Node.

ARG NODE_VERSION=22

FROM node:${NODE_VERSION}-bookworm-slim AS node

# ---------------------------------------------------------------------------
# Base común: sistema, Node, Nmap y punto de entrada
# ---------------------------------------------------------------------------
FROM ubuntu:24.04 AS base

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates openssl nmap tini \
 && rm -rf /var/lib/apt/lists/*

COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
 && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx \
 # Usuario sin privilegios "node" (uid 1000), como en la imagen oficial de Node.
 && userdel --remove ubuntu \
 && useradd --create-home --uid 1000 --shell /bin/bash node \
 && node --version && npm --version && nmap --version | head -n 1

# Sin telemetría de Prisma ni de Scarf, y sin avisos de npm durante la instalación.
ENV CHECKPOINT_DISABLE=1 \
    SCARF_ANALYTICS=false \
    NPM_CONFIG_FUND=false \
    NPM_CONFIG_AUDIT=false \
    NPM_CONFIG_UPDATE_NOTIFIER=false

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
# Elimina finales de línea CRLF por si el repositorio se clonó en Windows.
RUN sed -i 's/\r$//' /usr/local/bin/docker-entrypoint.sh \
 && chmod +x /usr/local/bin/docker-entrypoint.sh

WORKDIR /app
ENTRYPOINT ["/usr/bin/tini", "--", "docker-entrypoint.sh"]

# ---------------------------------------------------------------------------
# Dependencias completas (desarrollo y compilación)
# ---------------------------------------------------------------------------
FROM base AS dev-deps
RUN chown node:node /app
USER node
COPY --chown=node:node package.json package-lock.json ./
COPY --chown=node:node prisma ./prisma
RUN npm ci \
 && npx prisma generate \
 && sha256sum package-lock.json > node_modules/.package-lock.sha256

# ---------------------------------------------------------------------------
# Desarrollo: el código se monta desde el host y Nest recompila al guardar
# ---------------------------------------------------------------------------
FROM dev-deps AS development
ENV NODE_ENV=development
COPY --chown=node:node . .
EXPOSE 3000
CMD ["npm", "run", "start:dev"]

# ---------------------------------------------------------------------------
# Compilación de la API y del script de datos de demostración
# ---------------------------------------------------------------------------
FROM dev-deps AS build
COPY --chown=node:node . .
RUN npm run build && npm run build:seed

# ---------------------------------------------------------------------------
# Dependencias de ejecución
# ---------------------------------------------------------------------------
FROM base AS prod-deps
COPY package.json package-lock.json ./
COPY prisma ./prisma
RUN npm ci --omit=dev \
 && npx prisma generate \
 && npm cache clean --force

# ---------------------------------------------------------------------------
# Producción
# ---------------------------------------------------------------------------
FROM base AS production
ENV NODE_ENV=production
COPY --from=prod-deps /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/dist-seed ./dist-seed
COPY package.json ./
COPY prisma ./prisma
# La API y Nmap (escaneo -sT, sin privilegios) se ejecutan como usuario "node".
USER node
EXPOSE 3000
CMD ["node", "dist/main.js"]
