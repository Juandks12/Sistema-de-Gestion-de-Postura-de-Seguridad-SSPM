/**
 * Comparación de versiones de software tal como aparecen en CPE y en los
 * rangos de NVD ("2.4.29", "1.0.2k", "8.2p1", "5.7.0-rc1"...).
 *
 * Reglas:
 * - Se compara por segmentos numéricos o alfabéticos, ignorando separadores.
 * - Un sufijo de pre-lanzamiento (alpha, beta, rc, pre, dev) es anterior a la
 *   versión sin sufijo: 5.7.0-rc1 < 5.7.0.
 * - Cualquier otro sufijo es posterior: 1.0.2 < 1.0.2k.
 * - El sufijo "pN" de OpenSSH portable identifica la misma versión: 7.4p1 = 7.4
 *   (pero 7.4p1 < 7.4p2).
 */

type Token = number | string;

const PRE_RELEASE = /^(alpha|a|beta|b|rc|pre|preview|dev|snapshot|m)$/;

export function tokenize(version: string): Token[] {
  const tokens: Token[] = [];
  for (const match of version.toLowerCase().matchAll(/\d+|[a-z]+/g)) {
    const part = match[0];
    tokens.push(/^\d/.test(part) ? Number(part) : part);
  }
  return tokens;
}

/** Signo de la comparación cuando `rest` son los segmentos que le sobran a una versión. */
function tailSign(rest: Token[]): number {
  if (rest.length === 0) return 0;
  const [first, second] = rest;
  if (typeof first === 'string') {
    if (first === 'p' && typeof second === 'number' && rest.length === 2) return 0;
    return PRE_RELEASE.test(first) ? -1 : 1;
  }
  // 1.2 frente a 1.2.0: los ceros finales no cambian la versión.
  return rest.every((t) => t === 0) ? 0 : 1;
}

/** Negativo si a < b, 0 si son equivalentes y positivo si a > b. */
export function compareVersions(a: string, b: string): number {
  const ta = tokenize(a);
  const tb = tokenize(b);
  const n = Math.min(ta.length, tb.length);
  for (let i = 0; i < n; i += 1) {
    const x = ta[i];
    const y = tb[i];
    if (x === y) continue;
    if (typeof x === 'number' && typeof y === 'number') return x - y;
    if (typeof x === 'string' && typeof y === 'string') {
      const xPre = PRE_RELEASE.test(x);
      const yPre = PRE_RELEASE.test(y);
      if (xPre !== yPre) return xPre ? -1 : 1;
      return x < y ? -1 : 1;
    }
    // Número frente a letra (1.0.1 frente a 1.0a): la letra se considera anterior.
    return typeof x === 'number' ? 1 : -1;
  }
  if (ta.length === tb.length) return 0;
  return ta.length > tb.length ? tailSign(ta.slice(n)) : 0 - tailSign(tb.slice(n)) || 0;
}
