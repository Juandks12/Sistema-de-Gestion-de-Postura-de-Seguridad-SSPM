# ADR-0005: Verificación de propiedad de activos y protección del inicio de sesión

## Estado

Aceptado.

## Contexto

Para vender la plataforma como SaaS había dos riesgos que la declaración de
autorización y el login básico no cubrían:

1. **Uso contra terceros.** Cualquiera podía registrar el dominio de otra
   empresa, marcar "tengo autorización" y escanearlo desde nuestros servidores:
   riesgo legal (sección 1.6.3), quejas de abuso y la IP del servicio en
   listas negras.
2. **Fuerza bruta y registro masivo.** El login no limitaba intentos y el
   registro público permitía crear organizaciones sin freno.

## Decisión

1. **Verificación obligatoria antes de escanear**, con un token por
   organización publicado como registro TXT en `_sspm-verification.<dominio>`
   (cubre subdominios) o como archivo `/.well-known/sspm-verification.txt`
   (única opción para IPs). Es el mismo modelo que usan Google Search Console
   o Let's Encrypt, conocido por los administradores de TI.
   - Token por organización y no por activo: un único registro DNS verifica
     todo un dominio y sus subdominios presentes y futuros.
   - El archivo se consulta sin seguir redirecciones, reutilizando el cliente
     HTTP del escáner (IP validada, protección SSRF).
   - La exigencia se aplica en la API (manual y auditoría completa), en el
     planificador y de nuevo en el worker.
2. **Bloqueo por cuenta en PostgreSQL** (`login_attempts`), con la clave
   sha256 del correo, aplicado también a correos inexistentes (no revela
   cuentas) y válido con varias instancias.
3. **Límites por IP** en login y registro con `@nestjs/throttler`, en memoria
   de cada instancia, y `TRUST_PROXY` para usar la IP real detrás de Nginx.

## Consecuencias

- Los activos existentes quedan sin verificar tras la migración: hay que
  verificarlos antes de volver a escanearlos. Es intencionado (seguro por
  defecto).
- Una verificación no caduca: si un dominio cambia de dueño, la organización
  anterior seguiría pudiendo escanearlo. Mejora futura: reverificar la prueba
  DNS antes de cada auditoría programada.
- Los límites por IP son por instancia; con varias réplicas el límite
  efectivo se multiplica. Si hace falta precisión, el almacenamiento del
  throttler puede pasar a Redis sin cambiar las rutas. El bloqueo por cuenta
  ya es global.
- Un atacante podría bloquear temporalmente la cuenta de otro usuario
  fallando a propósito (denegación de servicio acotada a 15 minutos). Se
  acepta frente al riesgo de fuerza bruta; el administrador puede
  desbloquearla restableciendo la contraseña.
