# ADR-0007: Registro de auditoría, recuperación de cuenta, invitaciones y MFA

## Estado

Aceptado.

## Contexto

Los bloques 1 y 2 cerraron los riesgos de escanear activos ajenos y de vulnerabilidades
no detectadas. Quedaban tres carencias que un cliente real de SaaS exige antes de
confiar en la plataforma para varias personas de su organización:

1. **Nadie podía ver quién hizo qué.** Sin trazabilidad, un incidente (un activo
   borrado, un hallazgo marcado como falso positivo indebidamente) no se puede
   investigar. Es el requisito RNF-06 del documento.
2. **Perder la contraseña era un callejón sin salida para el usuario** y una carga
   operativa para el ADMIN (tenía que restablecerla él mismo desde Usuarios). Y no
   había forma de sumar personas a la organización sin repartir una contraseña
   inicial por un canal informal.
3. **Ninguna cuenta tenía un segundo factor.** Con la protección de fuerza bruta del
   bloque 1 ya no se puede adivinar una contraseña por ensayo, pero una contraseña
   filtrada (reutilizada, phishing) sigue bastando para entrar.

## Decisión

1. **Registro de auditoría (`audit_log`)** como un servicio global (`AuditService`,
   `@Global()`) que cualquier módulo invoca con `record()`. Nunca lanza ni retrasa la
   acción auditada: un fallo de escritura queda en el log del servidor. El actor se
   desnormaliza (nombre y correo) para que la fila siga siendo legible aunque el
   usuario se elimine. La IP viaja por `AsyncLocalStorage` (`RequestContextMiddleware`)
   en vez de pasarse como parámetro por cada servicio, para no ensuciar las firmas de
   métodos que ya existían.
2. **Recuperación de contraseña y invitaciones comparten el mismo mecanismo**
   (`AccountToken`): un token de un solo uso del que solo se guarda el hash sha256,
   con caducidad y un tipo (`PASSWORD_RESET` o `INVITATION`). Emitir uno nuevo caduca
   el anterior del mismo destino, así que un enlace viejo reenviado no sirve. La
   respuesta de "olvidé mi contraseña" es siempre la misma exista o no la cuenta.
3. **MFA con TOTP (RFC 6238) implementado con `node:crypto`**, sin librerías de
   terceros: es un algoritmo simple, bien especificado, y evitar una dependencia externa
   para algo que protege el login reduce superficie de ataque de la cadena de
   suministro. Se valida contra los vectores de prueba oficiales de los RFC 4226 y
   6238. El login en dos pasos usa un JWT intermedio de 5 minutos con un `purpose`
   propio que el resto de la API rechaza como sesión, en vez de guardar estado de
   sesión a medias en el servidor.
4. **`MailerService` compartido** entre las alertas (RF-10) y los correos de cuenta:
   ambos ya necesitaban SMTP, plantillas HTML simples y el mismo comportamiento sin
   `SMTP_HOST` (marcar `SKIPPED` en vez de fallar).
5. Los códigos incorrectos del segundo paso del login cuentan para el bloqueo de la
   cuenta (`LoginProtectionService`), igual que una contraseña incorrecta: si no,
   la protección contra fuerza bruta del bloque 1 tendría un agujero.

## Alternativas descartadas

- **Bibliotecas de TOTP** (`otplib`, `speakeasy`): el algoritmo es pequeño y estable;
  una dependencia más en el flujo de autenticación no compensa frente a 200 líneas
  propias y validadas contra los RFC.
- **Sesiones de servidor para el segundo paso del login** (en vez de un JWT
  intermedio): añadiría estado y una tabla más solo para una ventana de 5 minutos.
- **SMS como segundo factor**: depende de un proveedor de pago y de que el número siga
  siendo del usuario; TOTP no tiene coste marginal y funciona sin conectividad móvil.

## Consecuencias

- Sin `SMTP_HOST` configurado, la recuperación de contraseña y las invitaciones no
  llegan por correo; el flujo manual (ADMIN restablece o crea el usuario) sigue
  disponible como respaldo, y la interfaz lo indica.
- Si un usuario pierde el dispositivo del MFA y agota los códigos de recuperación,
  necesita que un ADMIN se lo desactive; esa acción queda auditada.
- DKIM del bloque 2 no puede enumerar selectores propios del cliente; queda anotado en
  el roadmap junto con el resto de mejoras de seguridad del correo.
