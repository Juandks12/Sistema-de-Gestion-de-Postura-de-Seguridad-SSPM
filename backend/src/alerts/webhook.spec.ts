import { FindingSeverity } from '@prisma/client';
import { buildWebhookBody, maskUrl, NotificationMessage, postWebhook, validateWebhookUrl, webhookFormat } from './webhook';

const msg: NotificationMessage = {
  kind: 'alert',
  alertId: 'alert-1',
  type: 'CRITICAL_FINDING',
  severity: FindingSeverity.CRITICAL,
  title: 'Hallazgo crítico en tienda.example.com',
  message: 'Archivo .env expuesto.',
  organizationName: 'Demo PyME',
  asset: { value: 'tienda.example.com', name: 'Tienda' },
  url: 'https://app.sspm.example/assets/a1',
  createdAt: new Date('2026-09-26T12:00:00Z'),
};

describe('validateWebhookUrl', () => {
  it('acepta URLs HTTPS públicas', () => {
    expect(validateWebhookUrl('https://hooks.slack.com/services/T0/B0/XYZ', false).ok).toBe(true);
    expect(validateWebhookUrl('https://example.org:8443/hook?x=1', false).ok).toBe(true);
  });

  it('exige HTTPS fuera del modo laboratorio', () => {
    expect(validateWebhookUrl('http://example.org/hook', false)).toMatchObject({ ok: false, reason: expect.stringContaining('HTTPS') });
    expect(validateWebhookUrl('ftp://example.org/hook', false).ok).toBe(false);
    expect(validateWebhookUrl('http://127.0.0.1:9000/hook', true).ok).toBe(true);
  });

  it('bloquea destinos internos para evitar SSRF', () => {
    for (const url of [
      'https://127.0.0.1/hook',
      'https://10.0.0.5/hook',
      'https://169.254.169.254/latest/meta-data',
      'https://[::1]/hook',
      'https://localhost/hook',
      'https://intranet/hook',
      'https://api.internal/hook',
    ]) {
      expect(validateWebhookUrl(url, false).ok).toBe(false);
    }
  });

  it('rechaza credenciales embebidas y URLs mal formadas', () => {
    expect(validateWebhookUrl('https://user:pass@example.org/hook', false).ok).toBe(false);
    expect(validateWebhookUrl('no es una url', false).ok).toBe(false);
  });
});

describe('postWebhook', () => {
  it('no conecta a un destino privado aunque la URL llegue sin validar', async () => {
    const result = await postWebhook('https://127.0.0.1:1/hook', {}, { allowPrivate: false, timeoutMs: 1000 });
    expect(result).toMatchObject({ ok: false });
  });
});

describe('formato del webhook', () => {
  it('detecta Slack, Discord o JSON genérico por el host', () => {
    expect(webhookFormat(new URL('https://hooks.slack.com/services/a/b/c'))).toBe('slack');
    expect(webhookFormat(new URL('https://discord.com/api/webhooks/1/abc'))).toBe('discord');
    expect(webhookFormat(new URL('https://discord.com/otra-cosa'))).toBe('generic');
    expect(webhookFormat(new URL('https://example.org/hook'))).toBe('generic');
  });

  it('construye el cuerpo de cada formato', () => {
    expect(buildWebhookBody('slack', msg)).toEqual({ text: expect.stringContaining('*[CRÍTICA] Hallazgo crítico') });
    const discord = buildWebhookBody('discord', msg) as { content: string; username: string };
    expect(discord.username).toBe('SSPM');
    expect(discord.content).toContain(msg.url);
    const generic = buildWebhookBody('generic', msg) as { event: string; alert: { id: string; severity: string } };
    expect(generic.event).toBe('alert.created');
    expect(generic.alert).toMatchObject({ id: 'alert-1', severity: 'CRITICAL' });
    expect((buildWebhookBody('generic', { ...msg, kind: 'test' }) as { event: string }).event).toBe('alert.test');
  });

  it('recorta el contenido de Discord a 2000 caracteres', () => {
    const long = buildWebhookBody('discord', { ...msg, message: 'x'.repeat(5000) }) as { content: string };
    expect(long.content.length).toBe(2000);
  });

  it('enmascara el token de la URL', () => {
    expect(maskUrl('https://hooks.slack.com/services/T000/B000/SECRETTOKEN1234')).toBe('https://hooks.slack.com/…1234');
    expect(maskUrl('https://example.org/')).toBe('https://example.org/');
  });
});
