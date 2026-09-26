import { escapeHtml, OutgoingMail } from '../common/mail/mailer.service';

/** Correos de cuenta (restablecer contraseña e invitaciones). Texto y HTML sencillos. */

function layout(title: string, bodyHtml: string, actionUrl: string, actionLabel: string): string {
  return (
    `<div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#1f2937;max-width:560px">` +
    `<p style="margin:0 0 4px;font-size:12px;color:#6b7280">SSPM · Postura de seguridad</p>` +
    `<h2 style="margin:0 0 12px;font-size:18px">${escapeHtml(title)}</h2>` +
    bodyHtml +
    `<p style="margin:16px 0"><a href="${escapeHtml(actionUrl)}" style="background:#2563eb;color:#ffffff;padding:10px 16px;border-radius:8px;text-decoration:none;display:inline-block">${escapeHtml(actionLabel)}</a></p>` +
    `<p style="margin:0;font-size:12px;color:#6b7280">Si el botón no funciona, copia este enlace en el navegador:<br>${escapeHtml(actionUrl)}</p>` +
    `</div>`
  );
}

export function passwordResetEmail(to: string, fullName: string, url: string, ttlMinutes: number): OutgoingMail {
  const title = 'Restablecer tu contraseña';
  return {
    to,
    subject: '[SSPM] Restablecer tu contraseña',
    text:
      `Hola ${fullName}:\n\n` +
      `Recibimos una solicitud para restablecer la contraseña de tu cuenta en SSPM.\n` +
      `Abre este enlace para elegir una contraseña nueva (caduca en ${ttlMinutes} minutos y solo sirve una vez):\n\n${url}\n\n` +
      `Si no lo solicitaste, ignora este correo: tu contraseña no cambia.\n`,
    html: layout(
      title,
      `<p style="margin:0 0 8px;line-height:1.5">Hola ${escapeHtml(fullName)}: recibimos una solicitud para restablecer la contraseña de tu cuenta.</p>` +
        `<p style="margin:0 0 8px;line-height:1.5">El enlace caduca en <strong>${ttlMinutes} minutos</strong> y solo sirve una vez. Si no lo solicitaste, ignora este correo: tu contraseña no cambia.</p>`,
      url,
      'Elegir contraseña nueva',
    ),
  };
}

export function invitationEmail(
  to: string,
  organizationName: string,
  invitedBy: string,
  roleLabel: string,
  url: string,
  ttlHours: number,
): OutgoingMail {
  const title = `Invitación a ${organizationName} en SSPM`;
  return {
    to,
    subject: `[SSPM] ${invitedBy} te invita a ${organizationName}`,
    text:
      `${invitedBy} te ha invitado a unirte a "${organizationName}" en SSPM con el rol de ${roleLabel}.\n\n` +
      `Acepta la invitación y crea tu contraseña en este enlace (caduca en ${ttlHours} horas):\n\n${url}\n\n` +
      `Si no esperabas esta invitación, puedes ignorar este correo.\n`,
    html: layout(
      title,
      `<p style="margin:0 0 8px;line-height:1.5"><strong>${escapeHtml(invitedBy)}</strong> te ha invitado a unirte a <strong>${escapeHtml(organizationName)}</strong> con el rol de ${escapeHtml(roleLabel)}.</p>` +
        `<p style="margin:0 0 8px;line-height:1.5">La invitación caduca en ${ttlHours} horas. Si no la esperabas, ignora este correo.</p>`,
      url,
      'Aceptar la invitación',
    ),
  };
}

export const ROLE_EMAIL_LABEL: Record<string, string> = {
  ADMIN: 'administrador',
  ANALYST: 'analista',
  VIEWER: 'solo lectura (gerencia)',
};
