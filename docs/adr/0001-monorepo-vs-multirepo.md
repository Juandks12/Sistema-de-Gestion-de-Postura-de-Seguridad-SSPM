# ADR-0001: Monorepo de código, repo separado solo para documentación

## Estado

Aceptado.

## Contexto

Al plantear la evolución del proyecto hacia un producto vendible como SaaS,
se evaluó si el repositorio de código debía dividirse (backend, frontend,
infraestructura en repos independientes) y si la documentación debía vivir
dentro o fuera del repo de código.

## Decisión

- **Backend y frontend permanecen en un único repositorio**
  (`sistema-de-gestion-de-postura-de-seguridad-sspm`), organizados por
  carpetas (`backend/`, `frontend/`). Comparten contrato de API, versión de
  despliegue (`docker-compose.yml`) y equipo (2 personas), por lo que
  separarlos en repos distintos multiplicaría el overhead de coordinación
  (PRs cruzados, versionado de contratos, pipelines duplicados) sin ningún
  beneficio real de aislamiento de permisos o de release independiente.
- **La documentación técnica** (arquitectura, ADRs, guía de despliegue,
  contribución) vive **dentro** de este mismo repositorio, en `docs/`,
  porque debe evolucionar versionada junto con el código que describe.
- **La documentación académica y comercial** (memoria de tesis desarrollada,
  diagramas UML completos, plan de negocio, material de venta) vive en un
  repositorio aparte (`sspm-docs`), porque tiene audiencia (asesor
  académico, clientes potenciales) y ciclo de cambio distintos al código, y
  eventualmente puede necesitar visibilidad o formato de publicación
  (sitio estático) que no tiene sentido mezclar con el código fuente.

## Consecuencias

- Un solo pipeline de CI cubre backend + frontend.
- Cambiar un contrato de API y su consumo en el frontend es un solo PR.
- El repo `sspm-docs` puede evolucionar (y eventualmente hacerse público o
  publicarse como sitio) sin exponer el código fuente del producto.
- Si en el futuro el equipo crece y aparecen dueños de servicio distintos
  para backend/frontend, esta decisión debe revisitarse.
