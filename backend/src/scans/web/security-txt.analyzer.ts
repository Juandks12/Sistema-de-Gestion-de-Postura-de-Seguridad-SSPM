import { FindingDraft } from '../scanner.interface';
import { httpProbe } from './http-client';

export interface SecurityTxtDirectives {
  contact: string[];
  expires: string | null;
  encryption: string[];
  acknowledgments: string[];
  preferredLanguages: string | null;
  canonical: string | null;
  policy: string | null;
  hiring: string | null;
}

export interface SecurityTxtAnalysisResult {
  checked: boolean;
  urlChecked: string;
  status: 'valid' | 'missing' | 'expired' | 'invalid' | 'error';
  directives?: SecurityTxtDirectives;
  error?: string;
  findings: FindingDraft[];
}

export function parseSecurityTxt(content: string): SecurityTxtDirectives {
  const directives: SecurityTxtDirectives = {
    contact: [],
    expires: null,
    encryption: [],
    acknowledgments: [],
    preferredLanguages: null,
    canonical: null,
    policy: null,
    hiring: null,
  };

  const lines = content.split(/\r?\n/);
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;

    const colonIdx = line.indexOf(':');
    if (colonIdx <= 0) continue;

    const key = line.slice(0, colonIdx).trim().toLowerCase();
    const value = line.slice(colonIdx + 1).trim();

    switch (key) {
      case 'contact':
        if (value) directives.contact.push(value);
        break;
      case 'expires':
        if (value && !directives.expires) directives.expires = value;
        break;
      case 'encryption':
        if (value) directives.encryption.push(value);
        break;
      case 'acknowledgments':
        if (value) directives.acknowledgments.push(value);
        break;
      case 'preferred-languages':
        if (value && !directives.preferredLanguages) directives.preferredLanguages = value;
        break;
      case 'canonical':
        if (value && !directives.canonical) directives.canonical = value;
        break;
      case 'policy':
        if (value && !directives.policy) directives.policy = value;
        break;
      case 'hiring':
        if (value && !directives.hiring) directives.hiring = value;
        break;
    }
  }

  return directives;
}

export async function analyzeSecurityTxt(
  baseUrl: string,
  options: {
    signal?: AbortSignal;
    timeoutMs?: number;
    allowPrivate?: boolean;
    pinnedAddress?: string;
  } = {},
): Promise<SecurityTxtAnalysisResult> {
  const findings: FindingDraft[] = [];
  const targetUrl = new URL('/.well-known/security.txt', baseUrl).toString();

  try {
    const probe = await httpProbe(targetUrl, {
      signal: options.signal ?? new AbortController().signal,
      timeoutMs: options.timeoutMs ?? 5000,
      allowPrivate: options.allowPrivate ?? true,
      pinnedAddress: options.pinnedAddress,
      maxBodyBytes: 32 * 1024,
    });

    if (!probe.ok || probe.status !== 200) {
      findings.push({
        ruleId: 'SEC-TXT-MISSING',
        location: targetUrl,
        evidence: {
          url: targetUrl,
          statusCode: probe.ok ? probe.status : null,
          details: 'El archivo /.well-known/security.txt no existe o no responde HTTP 200.',
        },
      });

      return {
        checked: true,
        urlChecked: targetUrl,
        status: 'missing',
        findings,
      };
    }

    const bodyText = probe.body.toString('utf-8');
    const directives = parseSecurityTxt(bodyText);

    // RFC 9116 sección 2.5.3: Contact es obligatorio
    if (directives.contact.length === 0) {
      findings.push({
        ruleId: 'SEC-TXT-INVALID',
        location: targetUrl,
        evidence: {
          url: targetUrl,
          reason: 'Falta la directiva obligatoria Contact: conforme al estándar RFC 9116.',
          foundDirectives: directives,
        },
      });

      return {
        checked: true,
        urlChecked: targetUrl,
        status: 'invalid',
        directives,
        findings,
      };
    }

    // RFC 9116 sección 2.5.5: Expires es obligatorio
    if (!directives.expires) {
      findings.push({
        ruleId: 'SEC-TXT-INVALID',
        location: targetUrl,
        evidence: {
          url: targetUrl,
          reason: 'Falta la directiva obligatoria Expires: conforme al estándar RFC 9116.',
          foundDirectives: directives,
        },
      });

      return {
        checked: true,
        urlChecked: targetUrl,
        status: 'invalid',
        directives,
        findings,
      };
    }

    // Validar fecha de expiración
    const expiresDate = new Date(directives.expires);
    if (isNaN(expiresDate.getTime())) {
      findings.push({
        ruleId: 'SEC-TXT-INVALID',
        location: targetUrl,
        evidence: {
          url: targetUrl,
          reason: `Formato de fecha inválido en la directiva Expires: "${directives.expires}". Debe ser ISO 8601.`,
          foundDirectives: directives,
        },
      });

      return {
        checked: true,
        urlChecked: targetUrl,
        status: 'invalid',
        directives,
        findings,
      };
    }

    const now = new Date();
    if (expiresDate.getTime() < now.getTime()) {
      findings.push({
        ruleId: 'SEC-TXT-EXPIRED',
        location: targetUrl,
        evidence: {
          url: targetUrl,
          expires: directives.expires,
          expiredAt: expiresDate.toISOString(),
          checkedAt: now.toISOString(),
          details: 'La fecha indicada en Expires: se encuentra en el pasado.',
        },
      });

      return {
        checked: true,
        urlChecked: targetUrl,
        status: 'expired',
        directives,
        findings,
      };
    }

    // Archivo válido y vigente conforme a RFC 9116
    return {
      checked: true,
      urlChecked: targetUrl,
      status: 'valid',
      directives,
      findings: [],
    };
  } catch (err) {
    return {
      checked: true,
      urlChecked: targetUrl,
      status: 'error',
      error: err instanceof Error ? err.message : String(err),
      findings: [],
    };
  }
}
