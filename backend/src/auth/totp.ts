import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * TOTP (RFC 6238) sobre HOTP (RFC 4226) con HMAC-SHA1, paso de 30 s y 6
 * dígitos: lo que esperan Google Authenticator, Microsoft Authenticator,
 * 1Password y compañía. Implementado con node:crypto para no añadir
 * dependencias; validado con los vectores de prueba de los RFC.
 */

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(buf: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return out;
}

export function base32Decode(encoded: string): Buffer {
  const clean = encoded.toUpperCase().replace(/[\s=]/g, '');
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const index = BASE32_ALPHABET.indexOf(ch);
    if (index === -1) {
      throw new Error(`Carácter base32 no válido: ${ch}`);
    }
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** Secreto TOTP nuevo: 20 bytes aleatorios en base32 (32 caracteres). */
export function generateTotpSecret(): string {
  return base32Encode(randomBytes(20));
}

/** Código HOTP (RFC 4226) para un contador dado. */
export function hotpCode(secretBase32: string, counter: number, digits = 6): string {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac('sha1', base32Decode(secretBase32)).update(buf).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3];
  return String(binary % 10 ** digits).padStart(digits, '0');
}

/** Código TOTP vigente en `timeMs` (paso de 30 s). */
export function totpCode(secretBase32: string, timeMs = Date.now(), stepSeconds = 30, digits = 6): string {
  return hotpCode(secretBase32, Math.floor(timeMs / 1000 / stepSeconds), digits);
}

/**
 * Comprueba un código admitiendo un desfase de ±`window` pasos (relojes
 * desincronizados). Comparación en tiempo constante.
 */
export function verifyTotp(secretBase32: string, code: string, timeMs = Date.now(), window = 1): boolean {
  const normalized = code.replace(/\s+/g, '');
  if (!/^\d{6}$/.test(normalized)) return false;
  const counter = Math.floor(timeMs / 1000 / 30);
  let ok = false;
  for (let offset = -window; offset <= window; offset += 1) {
    const expected = hotpCode(secretBase32, counter + offset);
    // Sin cortocircuito: se comprueban todas las ventanas siempre.
    if (timingSafeEqual(Buffer.from(expected), Buffer.from(normalized))) ok = true;
  }
  return ok;
}

/** URL otpauth:// que las aplicaciones de autenticación leen del código QR. */
export function otpauthUrl(issuer: string, account: string, secretBase32: string): string {
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(account)}`;
  return `otpauth://totp/${label}?secret=${secretBase32}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}

/** Código de recuperación legible: 10 caracteres en grupos de 5 (p. ej. "K7Q2M-9XH4D"). */
export function generateRecoveryCode(): string {
  const raw = base32Encode(randomBytes(7)).slice(0, 10);
  return `${raw.slice(0, 5)}-${raw.slice(5)}`;
}

export function normalizeRecoveryCode(code: string): string {
  return code.toUpperCase().replace(/[\s-]/g, '');
}
