/** Nombre de un certificado de Certificate Transparency. */
export interface CtName {
  name: string;
  /** Inicio de validez del certificado que lo incluye. */
  notBefore: string | null;
}

export interface CandidateHost {
  hostname: string;
  wildcard: boolean;
  lastCertificateAt: Date | null;
}

const HOSTNAME = /^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}$/;

/**
 * Normaliza los nombres de los certificados y se queda con los subdominios
 * estrictos de `domain`: minúsculas, sin punto final, "*.x" cuenta como "x"
 * (comodín), sin correos ni valores no válidos, sin repetir y ordenados.
 * Devuelve como mucho `max` nombres y si hubo que recortar.
 */
export function subdomainsFromCt(names: CtName[], domain: string, max: number): { hosts: CandidateHost[]; truncated: boolean } {
  const suffix = `.${domain}`;
  const byName = new Map<string, CandidateHost>();
  for (const entry of names) {
    for (const raw of entry.name.split(/\s+/)) {
      let name = raw.trim().toLowerCase().replace(/\.$/, '');
      if (!name || name.includes('@')) continue;
      const wildcard = name.startsWith('*.');
      if (wildcard) name = name.slice(2);
      if (name === domain || !name.endsWith(suffix) || !HOSTNAME.test(name)) continue;
      const date = entry.notBefore ? new Date(entry.notBefore) : null;
      const at = date && !Number.isNaN(date.getTime()) ? date : null;
      const existing = byName.get(name);
      if (!existing) {
        byName.set(name, { hostname: name, wildcard, lastCertificateAt: at });
        continue;
      }
      existing.wildcard ||= wildcard;
      if (at && (!existing.lastCertificateAt || at > existing.lastCertificateAt)) existing.lastCertificateAt = at;
    }
  }
  const hosts = [...byName.values()].sort((a, b) => a.hostname.localeCompare(b.hostname));
  return { hosts: hosts.slice(0, max), truncated: hosts.length > max };
}
