# ---------- Etapa de build ----------
FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
COPY prisma ./prisma
RUN npm ci
COPY . .
RUN npx prisma generate && npm run build

# ---------- Etapa de ejecución ----------
FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
# Nmap se usará por el módulo de escaneo (Sprint 1, siguiente paso)
RUN apk add --no-cache nmap
COPY package*.json ./
COPY prisma ./prisma
RUN npm ci --omit=dev && npx prisma generate
COPY --from=build /app/dist ./dist
EXPOSE 3000
# Aplica migraciones pendientes y arranca la API
CMD ["sh", "-c", "npx prisma migrate deploy && node dist/main.js"]
