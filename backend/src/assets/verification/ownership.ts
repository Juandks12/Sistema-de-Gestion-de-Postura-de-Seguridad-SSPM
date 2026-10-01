/**
 * Verificación de propiedad de activos (sección 1.6.3). Funciones puras.
 *
 * La organización demuestra que controla un activo publicando su token:
 * - DNS: registro TXT en `_sspm-verification.<dominio>`. Un registro en un
 *   dominio cubre también todos sus subdominios.
 * - HTTP: archivo `/.well-known/sspm-verification.txt` servido por el propio
 *   host (única opción para direcciones IP).
 */

export const VERIFICATION_DNS_LABEL = '_sspm-verification';
export const VERIFICATION_FILE_PATH = '/.well-known/sspm-verification.txt';
const VALUE_PREFIX = 'sspm-verification=';

/** Contenido que debe publicarse, tanto en el TXT como en el archivo. */
export function expectedProof(organizationToken: string): string {
  return `${VALUE_PREFIX}${organizationToken}`;
}

/**
 * Dominios en los que puede estar la prueba DNS, del más específico al más
 * general, sin bajar de dos etiquetas: para `a.tienda.example.com` se revisan
 * `a.tienda.example.com`, `tienda.example.com` y `example.com`.
 */
export function dnsProofDomains(domain: string): string[] {
  const labels = domain.toLowerCase().replace(/\.$/, '').split('.').filter(Boolean);
  const out: string[] = [];
  for (let i = 0; i <= labels.length - 2; i += 1) {
    out.push(labels.slice(i).join('.'));
  }
  return out;
}

export function dnsRecordName(domain: string): string {
  return `${VERIFICATION_DNS_LABEL}.${domain}`;
}

/** Un registro TXT puede venir partido en fragmentos; se unen antes de comparar. */
export function txtRecordsContain(records: string[][], expected: string): boolean {
  return records.some((chunks) => chunks.join('').trim() === expected);
}

/** El archivo solo vale si su contenido es exactamente la prueba (se toleran espacios y saltos finales). */
export function fileContentMatches(body: string, expected: string): boolean {
  return body.trim() === expected;
}

/** true si `domain` es `scope` o un subdominio suyo. */
export function isCoveredBy(domain: string, scope: string): boolean {
  const d = domain.toLowerCase();
  const s = scope.toLowerCase();
  return d === s || d.endsWith(`.${s}`);
}
