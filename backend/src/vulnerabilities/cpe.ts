import { NmapPort } from '../scans/nmap/nmap.types';

/** Software con versión identificado en un puerto abierto. */
export interface DetectedSoftware {
  vendor: string;
  product: string;
  version: string;
  /** "vendor:product": clave de la caché y de la consulta a NVD. */
  key: string;
  /** CPE 2.3 de la versión detectada. */
  cpe: string;
  /** Nombre legible: el producto que informó Nmap o el del CPE. */
  label: string;
  /**
   * El banner indica un paquete de distribución (Ubuntu, Debian, RHEL...).
   * Estas distribuciones corrigen vulnerabilidades sin cambiar el número de
   * versión (backports), así que la coincidencia es menos fiable.
   */
  distroPackage: boolean;
}

const NAME = /^[a-z0-9][a-z0-9._-]{0,99}$/;
const VERSION = /^[0-9][a-z0-9._+-]{0,49}$/i;
const DISTRO = /\b(ubuntu|debian|deb\d+u?\d*|el\d+|red ?hat|rhel|centos|rocky|almalinux|suse|amzn\d*|amazon linux|fedora|raspbian)\b/i;

/**
 * Descompone un CPE de Nmap ("cpe:/a:openbsd:openssh:7.4p1", formato 2.2) o
 * CPE 2.3 ("cpe:2.3:a:openbsd:openssh:7.4p1:*:..."). Solo interesan las
 * aplicaciones (parte "a"): los CPE de sistema operativo que infiere Nmap
 * no son lo bastante precisos para correlacionar CVE.
 */
export function parseCpe(raw: string): { part: string; vendor: string; product: string; version: string | null } | null {
  const value = raw.trim().toLowerCase();
  let fields: string[];
  if (value.startsWith('cpe:2.3:')) {
    fields = value.slice('cpe:2.3:'.length).split(':');
  } else if (value.startsWith('cpe:/')) {
    fields = value.slice('cpe:/'.length).split(':');
  } else {
    return null;
  }
  const [part, vendor, product, version] = fields;
  if (!part || !vendor || !product || !NAME.test(vendor) || !NAME.test(product)) return null;
  const v = version && version !== '*' && version !== '-' ? version : null;
  return { part, vendor, product, version: v };
}

/** Versiones imprecisas de Nmap: "9.6.0 or later", "2.4.X", "1.0 - 1.4". */
const IMPRECISE = /\bor (later|earlier)\b|\.x\b|\s-\s/i;

/** Primer "token" de versión del banner de Nmap: "8.2p1 Ubuntu 4ubuntu0.5" -> "8.2p1". */
function bannerVersion(version: string | undefined): string | null {
  if (!version || IMPRECISE.test(version)) return null;
  const first = version.trim().split(/\s+/)[0];
  return first && VERSION.test(first) ? first : null;
}

/** Software con versión conocida en un puerto abierto, o null si no se puede correlacionar. */
export function detectSoftware(port: NmapPort): DetectedSoftware | null {
  if (port.state !== 'open' || !port.service) return null;
  const service = port.service;
  for (const raw of service.cpe ?? []) {
    const cpe = parseCpe(raw);
    if (!cpe || cpe.part !== 'a') continue;
    const version = cpe.version ?? bannerVersion(service.version);
    if (!version || !VERSION.test(version)) continue;
    const banner = [service.version, service.extraInfo].filter(Boolean).join(' ');
    return {
      vendor: cpe.vendor,
      product: cpe.product,
      version,
      key: `${cpe.vendor}:${cpe.product}`,
      cpe: `cpe:2.3:a:${cpe.vendor}:${cpe.product}:${version}:*:*:*:*:*:*:*`,
      label: service.product?.trim() || cpe.product,
      distroPackage: DISTRO.test(banner),
    };
  }
  return null;
}
