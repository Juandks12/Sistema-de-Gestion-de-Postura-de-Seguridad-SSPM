# ADR-0004: Alertas evaluadas en el worker y entregadas en proceso, sin cola externa

## Estado

Aceptado.

## Contexto

El Sprint 4 añade alertas tempranas (RF-10) que deben notificarse por correo y
webhook. Había que decidir dónde evaluar las reglas, cómo entregar las
notificaciones sin afectar al motor de escaneo y cómo evitar que los webhooks,
una URL que introduce el cliente, se conviertan en un vector de SSRF.

## Decisión

1. **Evaluación tras cada escaneo completado**, en el propio worker y fuera de
   la transacción del escaneo. La sincronización de hallazgos informa qué
   hallazgos pasaron a `OPEN` (nuevos o reabiertos): solo eso puede generar una
   alerta, así un problema persistente no alerta en cada escaneo. Un error al
   evaluar alertas se registra y nunca marca el escaneo como fallido.
2. **Entrega asíncrona en el mismo proceso**: las alertas se guardan de forma
   síncrona (rápido) y el envío se lanza en segundo plano, con seguimiento para
   esperarlo al apagar. El resultado por canal se guarda en `alerts.deliveries`.
   No se introduce una cola externa (Redis/BullMQ), por el mismo motivo que en
   ADR-0002.
3. **Webhooks con la política del escáner**: solo HTTPS a hosts públicos, IP
   validada en cada envío (conexión directa, nombre en Host/SNI, TLS
   verificado) y sin seguir redirecciones. Las URL se consideran secretos y se
   devuelven enmascaradas.

## Consecuencias

- Si el proceso se reinicia justo después de crear una alerta y antes de
  entregarla, esa notificación se pierde (la alerta sí queda visible en la
  plataforma). Es aceptable para el MVP; si deja de serlo, la entrega pasa a
  una cola con reintentos sin cambiar el modelo de datos.
- Un proveedor lento no bloquea el worker, pero sí consume conexiones del
  proceso; `ALERT_DELIVERY_TIMEOUT_MS` acota cada envío.
- Añadir un tipo de alerta (p. ej. caída anómala del score) es añadir una
  regla pura en `alert-rules.ts`; canales y entrega se reutilizan.
