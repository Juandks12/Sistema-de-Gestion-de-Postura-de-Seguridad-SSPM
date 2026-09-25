# syntax=docker/dockerfile:1
#
# Imagen del frontend del SSPM.
#   development -> servidor de Vite con recarga en caliente (docker-compose.dev.yml)
#   production  -> aplicación compilada servida por Nginx, que además reenvía /api al backend

ARG NODE_VERSION=22

# ---------------------------------------------------------------------------
# Dependencias
# ---------------------------------------------------------------------------
FROM node:${NODE_VERSION}-bookworm-slim AS deps
ENV NPM_CONFIG_FUND=false NPM_CONFIG_AUDIT=false NPM_CONFIG_UPDATE_NOTIFIER=false
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci \
 && sha256sum package-lock.json > node_modules/.package-lock.sha256

# ---------------------------------------------------------------------------
# Desarrollo: el código se monta desde el host
# ---------------------------------------------------------------------------
FROM deps AS development
ENV CHOKIDAR_USEPOLLING=true
COPY . .
EXPOSE 5173
CMD ["sh", "-c", "if [ -f node_modules/.package-lock.sha256 ] && ! sha256sum -c --status node_modules/.package-lock.sha256; then echo '[frontend] package-lock.json cambió: sincronizando dependencias...'; npm install; sha256sum package-lock.json > node_modules/.package-lock.sha256; fi; exec npm run dev"]

# ---------------------------------------------------------------------------
# Compilación
# ---------------------------------------------------------------------------
FROM deps AS build
COPY . .
RUN npm run build

# ---------------------------------------------------------------------------
# Producción
# ---------------------------------------------------------------------------
FROM nginx:1.27-alpine AS production
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/ > /dev/null || exit 1
