import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AlertChannelType } from '@prisma/client';
import { createTransport, Transporter } from 'nodemailer';
import { buildWebhookBody, NotificationMessage, postWebhook, severityTag, webhookFormat } from './webhook';

export type DeliveryStatus = 'SENT' | 'FAILED' | 'SKIPPED';

export interface DeliveryResult {
  channelId: string;
  channelType: AlertChannelType;
  channelName: string;
  status: DeliveryStatus;
  detail?: string;
  error?: string;
  at: string;
}

export interface ChannelTarget {
  id: string;
  type: AlertChannelType;
  name: string;
  target: string;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function parseRecipients(target: string): string[] {
  return target
    .split(/[,;\s]+/)
    .map((r) => r.trim().toLowerCase())
    .filter(Boolean);
}

/** Envía una notificación por el canal indicado (secciones 10.2 y 10.3). */
@Injectable()
export class AlertNotifierService {
  private readonly logger = new Logger(AlertNotifierService.name);
  private transporter?: Transporter;

  constructor(private readonly config: ConfigService) {}

  private get timeoutMs(): number {
    return this.config.get<number>('ALERT_DELIVERY_TIMEOUT_MS') ?? 10000;
  }

  private get allowPrivate(): boolean {
    return this.config.get<boolean>('ALLOW_PRIVATE_TARGETS') === true;
  }

  get emailEnabled(): boolean {
    return Boolean(this.config.get<string>('SMTP_HOST'));
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

  async send(channel: ChannelTarget, msg: NotificationMessage): Promise<DeliveryResult> {
    const base = { channelId: channel.id, channelType: channel.type, channelName: channel.name };
    const at = () => new Date().toISOString();
    try {
      if (channel.type === AlertChannelType.EMAIL) {
        if (!this.emailEnabled) {
          return { ...base, status: 'SKIPPED', error: 'El servidor de correo (SMTP) no está configurado', at: at() };
        }
        const recipients = parseRecipients(channel.target);
        const info = await this.mailer().sendMail({
          from: this.config.get<string>('SMTP_FROM'),
          to: recipients,
          subject: `[SSPM][${severityTag(msg.severity)}] ${msg.title}`.replace(/[\r\n]+/g, ' ').slice(0, 250),
          text: `${msg.title}\n\n${msg.message}\n\nOrganización: ${msg.organizationName}\nVer en la plataforma: ${msg.url}\n`,
          html:
            `<div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#1f2937">` +
            `<p style="margin:0 0 4px;font-size:12px;color:#6b7280">SSPM · ${escapeHtml(msg.organizationName)} · Severidad ${escapeHtml(severityTag(msg.severity))}</p>` +
            `<h2 style="margin:0 0 12px;font-size:18px">${escapeHtml(msg.title)}</h2>` +
            `<p style="margin:0 0 16px;line-height:1.5">${escapeHtml(msg.message)}</p>` +
            `<p><a href="${escapeHtml(msg.url)}" style="color:#2563eb">Ver en la plataforma</a></p>` +
            `</div>`,
        });
        return { ...base, status: 'SENT', detail: `Aceptado para ${recipients.length} destinatario(s) (${info.messageId ?? 'sin id'})`, at: at() };
      }

      const result = await postWebhook(channel.target, buildWebhookBody(webhookFormat(new URL(channel.target)), msg), {
        allowPrivate: this.allowPrivate,
        timeoutMs: this.timeoutMs,
      });
      return result.ok
        ? { ...base, status: 'SENT', detail: result.detail, at: at() }
        : { ...base, status: 'FAILED', error: result.error, at: at() };
    } catch (err) {
      const message = (err as Error).message ?? 'Error desconocido';
      this.logger.warn(`Canal ${channel.id} (${channel.type}): ${message}`);
      return { ...base, status: 'FAILED', error: message.slice(0, 480), at: at() };
    }
  }
}
