/**
 * Catálogo de acciones del registro de auditoría (RNF-06). La clave se guarda
 * en `audit_log.action`; la etiqueta sirve para la interfaz y los filtros.
 */
export const AUDIT_ACTIONS = {
  'auth.register': 'Registro de la organización',
  'auth.login': 'Inicio de sesión',
  'auth.password_change': 'Cambio de contraseña propia',
  'auth.password_reset_requested': 'Solicitud de restablecimiento de contraseña',
  'auth.password_reset': 'Contraseña restablecida por correo',
  'auth.mfa_enabled': 'Verificación en dos pasos activada',
  'auth.mfa_disabled': 'Verificación en dos pasos desactivada',
  'auth.mfa_recovery_used': 'Código de recuperación usado',
  'user.create': 'Usuario creado',
  'user.update': 'Usuario modificado',
  'user.password_reset': 'Contraseña asignada por un administrador',
  'user.mfa_disabled': 'Verificación en dos pasos desactivada por un administrador',
  'user.invite': 'Invitación enviada',
  'user.invite_resent': 'Invitación reenviada',
  'user.invite_cancelled': 'Invitación cancelada',
  'user.invite_accepted': 'Invitación aceptada',
  'asset.create': 'Activo registrado',
  'asset.update': 'Activo modificado',
  'asset.delete': 'Activo eliminado',
  'asset.verified': 'Propiedad del activo verificada',
  'finding.review': 'Hallazgo revisado',
  'alert_channel.create': 'Canal de alertas creado',
  'alert_channel.update': 'Canal de alertas modificado',
  'alert_channel.delete': 'Canal de alertas eliminado',
  'monitoring.update': 'Monitoreo continuo cambiado',
  'organization.update': 'Organización modificada',
} as const;

export type AuditAction = keyof typeof AUDIT_ACTIONS;

export function isAuditAction(value: string): value is AuditAction {
  return value in AUDIT_ACTIONS;
}
