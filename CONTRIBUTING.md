# Guía de contribución

## Flujo de trabajo

El repositorio sigue un Git Flow simplificado:

| Rama | Uso |
|---|---|
| `main` | Versión estable. Solo recibe PRs desde `develop` (o `hotfix/*`). |
| `develop` | Integración. Todas las ramas de trabajo salen de aquí y vuelven aquí. |
| `feature/<desc>` | Funcionalidad nueva (`feature/reportes-pdf`). |
| `fix/<desc>` | Corrección (`fix/mfa-password-reset`). |
| `hotfix/<desc>` | Corrección urgente sobre `main`; se fusiona en `main` y en `develop`. |
| `chore/`, `docs/`, `refactor/`, `test/`, `ci/`, `build/` | Mantenimiento. |

1. Crear la rama a partir de `develop` actualizado:
   ```bash
   git checkout develop && git pull
   git checkout -b feature/<descripcion-corta>
   ```
2. Desarrollar en modo dev (`docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build`,
   ver README).
3. Antes de abrir el PR, correr localmente:
   ```bash
   dc exec api npm run lint && dc exec api npm test
   dc exec web npm run lint && dc exec web npm run typecheck
   ```
4. Abrir el PR contra `develop`. El pipeline de CI (`.github/workflows/ci.yml`)
   corre lint + test + build y revisa el nombre de la rama y los commits.
5. Para publicar una versión, abrir un PR de `develop` a `main`.
6. Si el cambio modifica `prisma/schema.prisma`, incluir la migración
   generada (`npx prisma migrate dev --name <nombre>`) en el mismo PR.

Una rama por tarea: cuando su PR se fusiona, la rama se borra y el siguiente
trabajo empieza en una rama nueva desde `develop` (no se reutiliza la misma
rama para varios PRs).

## Decisiones de arquitectura (ADRs)

Cambios que afectan una decisión estructural (nueva dependencia de
infraestructura, cambio de patrón de concurrencia, cambio del modelo de
scoring, etc.) deben documentarse como un ADR nuevo en `docs/adr/`,
siguiendo el formato de los existentes (Contexto → Decisión →
Consecuencias).

## Convenciones de commits

Mensajes en imperativo, describiendo el *por qué* cuando no sea obvio del
diff (ver ejemplos en el historial de commits del repo). Formato
recomendado: `tipo(ámbito): descripción` (`feat(alerts): ...`,
`fix(auth): ...`, `docs: ...`).

Los commits los firma la persona que los hace, con su cuenta de GitHub. Si
usas un asistente de IA o una herramienta que genera commits o PRs,
desactiva sus firmas automáticas (líneas `Co-authored-by:` de la
herramienta, enlaces de sesión o pies de página "Generated with"): el CI
rechaza los PRs que las incluyan y las ramas con nombres fuera de la
convención.

## Seguridad

No commitear secretos (`.env` real, tokens, contraseñas). El repo incluye
`.gitattributes`/`.gitignore` para evitarlo; si detectas un secreto
expuesto en el historial, avisa antes de hacer nada — no se resuelve
solo con un nuevo commit.
