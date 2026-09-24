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
# Nmap para el módulo de escaneo. Se usa -sT (TCP connect), que no requiere root.
RUN apk add --no-cache nmap nmap-scripts
COPY package*.json ./
COPY prisma ./prisma
RUN npm ci --omit=dev && npx prisma generate
COPY --from=build /app/dist ./dist
# La API y Nmap se ejecutan sin privilegios de root.
USER node
EXPOSE 3000
# Aplica migraciones pendientes y arranca la API
CMD ["sh", "-c", "npx prisma migrate deploy && node dist/main.js"]
