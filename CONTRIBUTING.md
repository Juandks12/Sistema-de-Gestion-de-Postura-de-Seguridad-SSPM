# Guía de contribución

## Flujo de trabajo

1. Crear una rama a partir de `main`: `feature/<descripcion-corta>` o
   `fix/<descripcion-corta>`.
2. Desarrollar en modo dev (`docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build`,
   ver README).
3. Antes de abrir el PR, correr localmente:
   ```bash
   dc exec api npm run lint && dc exec api npm test
   dc exec web npm run lint && dc exec web npm run typecheck
   ```
4. Abrir el PR contra `main`. El pipeline de CI (`.github/workflows/ci.yml`)
   corre lint + test + build automáticamente.
5. Si el cambio modifica `prisma/schema.prisma`, incluir la migración
   generada (`npx prisma migrate dev --name <nombre>`) en el mismo PR.

## Decisiones de arquitectura (ADRs)

Cambios que afectan una decisión estructural (nueva dependencia de
infraestructura, cambio de patrón de concurrencia, cambio del modelo de
scoring, etc.) deben documentarse como un ADR nuevo en `docs/adr/`,
siguiendo el formato de los existentes (Contexto → Decisión →
Consecuencias).

## Convenciones de commits

Mensajes en imperativo, describiendo el *por qué* cuando no sea obvio del
diff (ver ejemplos en el historial de commits del repo).

## Seguridad

No commitear secretos (`.env` real, tokens, contraseñas). El repo incluye
`.gitattributes`/`.gitignore` para evitarlo; si detectas un secreto
expuesto en el historial, avisa antes de hacer nada — no se resuelve
solo con un nuevo commit.
