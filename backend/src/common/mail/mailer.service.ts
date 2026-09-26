import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createTransport, Transporter } from 'nodemailer';

export interface OutgoingMail {
  to: string | string[];
  subject: string;
  text: string;
  html: string;
}

export interface MailResult {
  ok: boolean;
  /** SENT, FAILED o SKIPPED (sin SMTP configurado). */
  status: 'SENT' | 'FAILED' | 'SKIPPED';
  detail?: string;
  error?: string;
}

/**
 * Envío de correo por SMTP, compartido por las alertas (RF-10) y los correos
 * de cuenta (restablecer contraseña, invitaciones). Sin `SMTP_HOST` los envíos
 * se marcan SKIPPED en lugar de fallar.
 */
@Injectable()
export class MailerService {
  private readonly logger = new Logger(MailerService.name);
  private transporter?: Transporter;

  constructor(private readonly config: ConfigService) {}

  get enabled(): boolean {
    return Boolean(this.config.get<string>('SMTP_HOST'));
  }

  private get timeoutMs(): number {
    return this.config.get<number>('ALERT_DELIVERY_TIMEOUT_MS') ?? 10000;
  }

  private mailer(): Transporter {
    if (!this.transporter) {
      const user = this.config.get<string>('SMTP_USER');
      this.transporter = createTransport({
        host: this.config.get<string>('SMTP_HOST'),
        port: this.config.get<number>('SMTP_PORT') ?? 587,
        secure: this.config.get<boolean>('SMTP_SECURE') === true,
        auth: user ? { user, pass: this.config.get<string>('SMTP_PASSWORD') } : undefined,
        connectionTimeout: this.timeoutMs,
        greetingTimeout: this.timeoutMs,
        socketTimeout: this.timeoutMs,
        // El contenido lo genera la plataforma: nunca se leen archivos ni URLs al construir el mensaje.
        disableFileAccess: true,
        disableUrlAccess: true,
      });
    }
    return this.transporter;
  }

  async send(mail: OutgoingMail): Promise<MailResult> {
    if (!this.enabled) {
      return { ok: false, status: 'SKIPPED', error: 'El servidor de correo (SMTP) no está configurado' };
    }
    try {
      const recipients = Array.isArray(mail.to) ? mail.to : [mail.to];
      const info = await this.mailer().sendMail({
        from: this.config.get<string>('SMTP_FROM'),
        to: recipients,
        subject: mail.subject.replace(/[\r\n]+/g, ' ').slice(0, 250),
        text: mail.text,
        html: mail.html,
      });
      return { ok: true, status: 'SENT', detail: `Aceptado para ${recipients.length} destinatario(s) (${info.messageId ?? 'sin id'})` };
    } catch (err) {
      const message = ((err as Error).message ?? 'Error desconocido').slice(0, 480);
      this.logger.warn(`Envío de correo fallido: ${message}`);
      return { ok: false, status: 'FAILED', error: message };
    }
  }
}

export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
