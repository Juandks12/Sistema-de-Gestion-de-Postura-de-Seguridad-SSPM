import { createPublicKey } from 'node:crypto';
import { DnsClient } from '../../common/dns/dns-client';

/**
 * Selectores DKIM habituales. DKIM no permite listar los selectores de un
 * dominio, así que se prueban los de los proveedores más comunes.
 */
export const COMMON_DKIM_SELECTORS = [
  'google', 'selector1', 'selector2', 'default', 'dkim', 'mail', 'k1', 'k2', 'k3', 's1', 's2',
  'smtp', 'email', 'key1', 'key2', 'sig1', 'mandrill', 'mailjet', 'mxvault', 'zoho', 'zmail',
  'protonmail', 'protonmail2', 'protonmail3', 'fm1', 'fm2', 'fm3', 'everlytickey1', 'everlytickey2',
  'smtpapi', 'sendgrid', 'cm', 'hs1', 'hs2', 'amazonses', 'dkim1', 'mail1',
] as const;

export interface DkimKey {
  selector: string;
  keyType: string;
  /** Longitud de la clave RSA en bits (null si no se pudo leer o no es RSA). */
  bits: number | null;
}

export function parseDkimRecord(txt: string): { keyType: string; publicKey: string } | null {
  const tags: Record<string, string> = {};
  for (const part of txt.split(';')) {
    const i = part.indexOf('=');
    if (i <= 0) continue;
    tags[part.slice(0, i).trim().toLowerCase()] = part.slice(i + 1).replace(/\s+/g, '');
  }
  if (tags.v && tags.v.toUpperCase() !== 'DKIM1') return null;
  if (tags.p === undefined) return null;
  return { keyType: (tags.k || 'rsa').toLowerCase(), publicKey: tags.p };
}

export function rsaKeyBits(base64: string): number | null {
  try {
    const key = createPublicKey({ key: Buffer.from(base64, 'base64'), format: 'der', type: 'spki' });
    return key.asymmetricKeyDetails?.modulusLength ?? null;
  } catch {
    return null;
  }
}

/** Claves DKIM publicadas en los selectores habituales. Una clave vacía (p=) está revocada y no cuenta. */
export async function findDkimKeys(domain: string, dns: DnsClient, concurrency = 8): Promise<DkimKey[]> {
  const found: DkimKey[] = [];
  const queue = [...COMMON_DKIM_SELECTORS];
  const worker = async () => {
    for (let selector = queue.shift(); selector; selector = queue.shift()) {
      const records = await dns.txt(`${selector}._domainkey.${domain}`).catch(() => [] as string[]);
      for (const txt of records) {
        const parsed = parseDkimRecord(txt);
        if (!parsed || !parsed.publicKey) continue;
        found.push({
          selector,
          keyType: parsed.keyType,
          bits: parsed.keyType === 'rsa' ? rsaKeyBits(parsed.publicKey) : null,
        });
        break;
      }
    }
  };
  await Promise.all(Array.from({ length: concurrency }, worker));
  return found.sort((a, b) => a.selector.localeCompare(b.selector));
}
