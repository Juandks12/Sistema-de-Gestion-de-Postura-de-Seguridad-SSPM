# ADR-0002: Nmap vía subprocess sin shell + cola en PostgreSQL (sin Redis/RabbitMQ)

## Estado

Aceptado.

## Contexto

El sistema necesita ejecutar escaneos (Nmap, auditoría web) de forma
asíncrona, sin bloquear la API, con reintentos, límites y visibilidad de
estado. Existían dos decisiones a tomar: (1) cómo invocar Nmap de forma
segura, (2) qué mecanismo de cola usar.

## Decisión

1. **Nmap se invoca con `child_process.spawn` sin shell**, recibiendo
   siempre una IP ya resuelta y validada (nunca el texto ingresado por el
   usuario), con un entorno mínimo y sin privilegios (`-sT`). Esto elimina
   la clase de vulnerabilidad de inyección de comandos sin necesitar una
   librería de sandboxing adicional.
2. **La cola de trabajos vive en la tabla `scans` de PostgreSQL**
   (`PENDING` → `RUNNING` → `COMPLETED`/`FAILED`/`CANCELLED`), reclamada con
   `FOR UPDATE SKIP LOCKED`, en vez de introducir Redis, RabbitMQ o SQS.

## Justificación

- El volumen esperado (escaneos bajo demanda o programados por PyME) no
  justifica operar un segundo sistema con su propia disponibilidad y
  backup.
- Postgres ya es una dependencia dura del sistema; no sumar una nueva
  reduce superficie operativa para un equipo de 2 personas.
- `FOR UPDATE SKIP LOCKED` da concurrencia segura entre múltiples instancias
  de la API sin coordinación adicional.

## Cuándo reconsiderar

Si el volumen de escaneos por minuto crece a un punto donde el polling de
la cola (`SCAN_POLL_INTERVAL_MS`) o la contención en la tabla se vuelven el
cuello de botella medible (no especulativo), migrar a una cola dedicada
(ej. BullMQ sobre Redis) es un cambio aislado al `scan-worker.service.ts`
sin impacto en el resto del sistema.
