import { AssetType, FindingSeverity } from '@prisma/client';
import { isFQDN } from 'class-validator';
import { isIP } from 'node:net';
import { Agent, request } from 'undici';
import { isNonPublicHostname, isPrivateOrReservedIp } from '../common/utils/network.util';
import { ScanExecutionError } from '../scans/scan.errors';
import { resolveScanTarget } from '../scans/target-resolver';
import { USER_AGENT } from '../scans/web/http-client';

/** Contenido común de una notificación, independiente del canal. */
export interface NotificationMessage {
  kind: 'alert' | 'test';
  alertId?: string;
  type: string;
  severity: FindingSeverity;
  title: string;
  message: string;
  organizationName: string;
  asset?: { value: string; name: string | null } | null;
  /** Enlace a la plataforma para ver el detalle. */
  url: string;
  createdAt: Date;
}

export type WebhookFormat = 'slack' | 'discord' | 'generic';

export type UrlValidation = { ok: true; url: URL } | { ok: false; reason: string };

/**
 * Valida la URL de un webhook antes de guardarla y antes de cada envío.
 * El servidor hará una petición saliente a esta URL, así que se aplica la
 * misma política que al escáner (sección 11.3): solo HTTPS hacia hosts
 * públicos, sin credenciales embebidas. En modo laboratorio se admiten HTTP
 * y hosts privados para poder probar con servicios locales.
 */
export function validateWebhookUrl(raw: string, allowPrivate: boolean): UrlValidation {
  let url: URL;
  try {
    url = new URL(raw.trim());
  } catch {
    return { ok: false, reason: 'La URL del webhook no es válida' };
  }
  if (raw.length > 1000) {
    return { ok: false, reason: 'La URL del webhook es demasiado larga (máximo 1000 caracteres)' };
  }
  if (url.protocol !== 'https:' && !(allowPrivate && url.protocol === 'http:')) {
    return { ok: false, reason: 'El webhook debe usar HTTPS' };
  }
  if (url.username || url.password) {
    return { ok: false, reason: 'La URL del webhook no puede incluir usuario ni contraseña' };
  }
  const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (isIP(host)) {
    if (!allowPrivate && isPrivateOrReservedIp(host)) {
      return { ok: false, reason: 'El webhook apunta a una dirección privada o reservada' };
    }
  } else if (!allowPrivate && (!isFQDN(host, { require_tld: true }) || isNonPublicHostname(host))) {
    return { ok: false, reason: 'El webhook debe apuntar a un dominio público' };
  }
  return { ok: true, url };
}

export function webhookFormat(url: URL): WebhookFormat {
  const host = url.hostname.toLowerCase();
  if (host === 'hooks.slack.com') return 'slack';
  if ((host === 'discord.com' || host === 'discordapp.com') && url.pathname.startsWith('/api/webhooks/')) {
    return 'discord';
  }
  return 'generic';
}

/** Oculta el token de la URL (los webhooks de Slack/Discord son secretos). */
export function maskUrl(raw: string): string {
  try {
    const url = new URL(raw);
    const path = url.pathname.length > 1 ? `/…${url.pathname.slice(-4)}` : '/';
    return `${url.protocol}//${url.host}${path}`;
  } catch {
    return '…';
  }
}

const SEVERITY_TAG: Record<FindingSeverity, string> = {
  CRITICAL: 'CRÍTICA',
  HIGH: 'ALTA',
  MEDIUM: 'MEDIA',
  LOW: 'BAJA',
  INFO: 'INFO',
};

export function severityTag(severity: FindingSeverity): string {
  return SEVERITY_TAG[severity];
}

export function buildWebhookBody(format: WebhookFormat, msg: NotificationMessage): Record<string, unknown> {
  const heading = `[${SEVERITY_TAG[msg.severity]}] ${msg.title}`;
  if (format === 'slack') {
    return { text: `*${heading}*\n${msg.message}\n<${msg.url}|Ver en SSPM> · ${msg.organizationName}` };
  }
  if (format === 'discord') {
    const content = `**${heading}**\n${msg.message}\n${msg.url}`;
    return { username: 'SSPM', content: content.length > 2000 ? `${content.slice(0, 1997)}...` : content };
  }
  return {
    source: 'sspm',
    event: msg.kind === 'test' ? 'alert.test' : 'alert.created',
    organization: msg.organizationName,
    alert: {
      id: msg.alertId ?? null,
      type: msg.type,
      severity: msg.severity,
      title: msg.title,
      message: msg.message,
      asset: msg.asset ?? null,
      url: msg.url,
      createdAt: msg.createdAt.toISOString(),
    },
  };
}

export type SendResult = { ok: true; detail: string } | { ok: false; error: string };

/**
 * Envía el webhook sin seguir redirecciones, conectando a la IP ya validada
 * (el nombre viaja en Host/SNI) para que un cambio de DNS no pueda desviar la
 * petición a la red interna. El certificado TLS sí se valida.
 */
export async function postWebhook(
  rawUrl: string,
  body: Record<string, unknown>,
  options: { allowPrivate: boolean; timeoutMs: number },
): Promise<SendResult> {
  const check = validateWebhookUrl(rawUrl, options.allowPrivate);
  if (!check.ok) return { ok: false, error: check.reason };
  const { url } = check;

  const hostname = url.hostname.replace(/^\[|\]$/g, '');
  const hostIsIp = isIP(hostname) !== 0;
  let address: string;
  try {
    const target = await resolveScanTarget(hostname, hostIsIp ? AssetType.IP : AssetType.DOMAIN, options.allowPrivate);
    address = target.address;
  } catch (err) {
    return { ok: false, error: err instanceof ScanExecutionError ? err.message : `No se pudo resolver ${hostname}` };
  }

  const port = url.port ? Number(url.port) : url.protocol === 'https:' ? 443 : 80;
  const pinned = isIP(address) === 6 ? `[${address}]` : address;
  const agent = new Agent({
    connect: { servername: hostIsIp ? undefined : hostname, timeout: options.timeoutMs },
    connections: 1,
  });
  try {
    const res = await request(`${url.protocol}//${pinned}:${port}${url.pathname}${url.search}`, {
      dispatcher: agent,
      method: 'POST',
      headers: {
        host: url.port ? `${url.hostname}:${url.port}` : url.hostname,
        'content-type': 'application/json',
        'user-agent': USER_AGENT,
      },
      body: JSON.stringify(body),
      headersTimeout: options.timeoutMs,
      bodyTimeout: options.timeoutMs,
    });
    await res.body.dump({ limit: 64 * 1024 }).catch(() => undefined);
    if (res.statusCode >= 200 && res.statusCode < 300) {
      return { ok: true, detail: `HTTP ${res.statusCode}` };
    }
    return { ok: false, error: `El webhook respondió HTTP ${res.statusCode}` };
  } catch (err) {
    const e = err as { code?: string; message?: string };
    return { ok: false, error: `No se pudo entregar el webhook: ${e.code ?? e.message ?? 'error de red'}` };
  } finally {
    await agent.close().catch(() => undefined);
  }
}
