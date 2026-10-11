import { FindingDraft } from '../scanner.interface';
import { HeaderMap } from '../analyzers/headers.analyzer';

export type TechCategory =
  | 'Web Server'
  | 'Framework'
  | 'CMS'
  | 'Programming Language'
  | 'Frontend Library'
  | 'CDN/Proxy';

export interface DetectedTechnology {
  name: string;
  category: TechCategory;
  version?: string;
  confidence: number; // 0 a 100
  eol?: boolean;
  eolNotice?: string;
  matchedFrom: 'header' | 'cookie' | 'meta' | 'script' | 'body';
}

export interface TechFingerprintInput {
  finalUrl: string;
  status: number;
  headers: HeaderMap;
  bodyText?: string;
}

export interface TechFingerprintResult {
  technologies: DetectedTechnology[];
  findings: FindingDraft[];
}

function first(val: string | string[] | undefined): string | undefined {
  if (Array.isArray(val)) return val[0];
  return val;
}

function allCookies(val: string | string[] | undefined): string[] {
  if (val === undefined) return [];
  return Array.isArray(val) ? val : [val];
}

interface EolRule {
  isEol: (v: string) => boolean;
  notice: string;
}

const EOL_RULES: Record<string, EolRule> = {
  PHP: {
    isEol: (v) => {
      const match = /^(\d+)\.(\d+)/.exec(v);
      if (!match) return false;
      const major = parseInt(match[1], 10);
      const minor = parseInt(match[2], 10);
      return major < 8 || (major === 8 && minor < 2); // PHP < 8.2 está en EOL
    },
    notice: 'PHP < 8.2 ha finalizado su soporte de seguridad oficial (EOL).',
  },
  Apache: {
    isEol: (v) => {
      const match = /^2\.(\d+)(?:\.(\d+))?/.exec(v);
      if (!match) return false;
      const minor = parseInt(match[1], 10);
      const patch = parseInt(match[2] ?? '0', 10);
      return minor < 4 || (minor === 4 && patch < 49); // Apache < 2.4.49 vulnerable a Path Traversal
    },
    notice: 'Apache < 2.4.49 contiene vulnerabilidades críticas conocidas (CVE-2021-41773).',
  },
  Nginx: {
    isEol: (v) => {
      const match = /^(\d+)\.(\d+)/.exec(v);
      if (!match) return false;
      const major = parseInt(match[1], 10);
      const minor = parseInt(match[2], 10);
      return major === 1 && minor < 18; // Nginx < 1.18 en desuso
    },
    notice: 'Nginx rama < 1.18 no recibe mantenimiento activo.',
  },
  WordPress: {
    isEol: (v) => {
      const match = /^(\d+)\.(\d+)/.exec(v);
      if (!match) return false;
      const major = parseInt(match[1], 10);
      return major < 6; // WordPress < 6.0
    },
    notice: 'WordPress < 6.0 carece de parches para múltiples fallos de seguridad.',
  },
  'Microsoft-IIS': {
    isEol: (v) => {
      const match = /^(\d+)/.exec(v);
      if (!match) return false;
      return parseInt(match[1], 10) < 10; // IIS < 10 (IIS 6, 7, 8) en EOL
    },
    notice: 'Microsoft IIS < 10.0 corre sobre sistemas operativos Windows Server en EOL.',
  },
  jQuery: {
    isEol: (v) => {
      const match = /^(\d+)/.exec(v);
      if (!match) return false;
      return parseInt(match[1], 10) < 3; // jQuery 1.x / 2.x
    },
    notice: 'jQuery < 3.5 es vulnerable a Cross-Site Scripting (XSS) y Prototype Pollution.',
  },
};

/**
 * Realiza fingerprinting tecnológico a partir de cabeceras, cookies y contenido HTML.
 */
export function fingerprintTechnologies(input: TechFingerprintInput): TechFingerprintResult {
  const url = new URL(input.finalUrl);
  const location = `${url.protocol}//${url.host}/`;
  const headersLower: Record<string, string | string[] | undefined> = {};
  for (const [k, v] of Object.entries(input.headers)) {
    headersLower[k.toLowerCase()] = v;
  }

  const serverHeader = first(headersLower['server']) ?? '';
  const poweredByHeader = first(headersLower['x-powered-by']) ?? '';
  const generatorHeader = first(headersLower['x-generator']) ?? '';
  const cookies = allCookies(headersLower['set-cookie']).join('; ');
  const body = input.bodyText ?? '';

  const techMap = new Map<string, DetectedTechnology>();

  const addTech = (tech: DetectedTechnology) => {
    const existing = techMap.get(tech.name);
    if (!existing || (!existing.version && tech.version) || (existing.confidence < tech.confidence)) {
      if (tech.version && EOL_RULES[tech.name]) {
        const eolRule = EOL_RULES[tech.name];
        if (eolRule.isEol(tech.version)) {
          tech.eol = true;
          tech.eolNotice = eolRule.notice;
        }
      }
      techMap.set(tech.name, tech);
    }
  };

  // 1. Servidores Web en Server
  if (/nginx/i.test(serverHeader)) {
    const versionMatch = /nginx\/([0-9.]+)/i.exec(serverHeader);
    addTech({
      name: 'Nginx',
      category: 'Web Server',
      version: versionMatch ? versionMatch[1] : undefined,
      confidence: 100,
      matchedFrom: 'header',
    });
  } else if (/apache/i.test(serverHeader)) {
    const versionMatch = /apache\/([0-9.]+)/i.exec(serverHeader);
    addTech({
      name: 'Apache',
      category: 'Web Server',
      version: versionMatch ? versionMatch[1] : undefined,
      confidence: 100,
      matchedFrom: 'header',
    });
  } else if (/microsoft-iis/i.test(serverHeader)) {
    const versionMatch = /microsoft-iis\/([0-9.]+)/i.exec(serverHeader);
    addTech({
      name: 'Microsoft-IIS',
      category: 'Web Server',
      version: versionMatch ? versionMatch[1] : undefined,
      confidence: 100,
      matchedFrom: 'header',
    });
  } else if (/caddy/i.test(serverHeader)) {
    addTech({
      name: 'Caddy',
      category: 'Web Server',
      confidence: 95,
      matchedFrom: 'header',
    });
  } else if (/litespeed/i.test(serverHeader)) {
    addTech({
      name: 'LiteSpeed',
      category: 'Web Server',
      confidence: 95,
      matchedFrom: 'header',
    });
  } else if (/cloudflare/i.test(serverHeader)) {
    addTech({
      name: 'Cloudflare',
      category: 'CDN/Proxy',
      confidence: 100,
      matchedFrom: 'header',
    });
  } else if (/gunicorn/i.test(serverHeader)) {
    const versionMatch = /gunicorn\/([0-9.]+)/i.exec(serverHeader);
    addTech({
      name: 'Gunicorn',
      category: 'Web Server',
      version: versionMatch ? versionMatch[1] : undefined,
      confidence: 95,
      matchedFrom: 'header',
    });
  }

  // 2. Lenguajes y Entornos en X-Powered-By o cookies
  if (/php/i.test(poweredByHeader)) {
    const versionMatch = /php\/([0-9.]+)/i.exec(poweredByHeader);
    addTech({
      name: 'PHP',
      category: 'Programming Language',
      version: versionMatch ? versionMatch[1] : undefined,
      confidence: 100,
      matchedFrom: 'header',
    });
  } else if (/phpsessid/i.test(cookies)) {
    addTech({
      name: 'PHP',
      category: 'Programming Language',
      confidence: 85,
      matchedFrom: 'cookie',
    });
  }

  if (/express/i.test(poweredByHeader)) {
    addTech({
      name: 'Express.js',
      category: 'Framework',
      confidence: 95,
      matchedFrom: 'header',
    });
    addTech({
      name: 'Node.js',
      category: 'Programming Language',
      confidence: 90,
      matchedFrom: 'header',
    });
  } else if (/connect\.sid/i.test(cookies)) {
    addTech({
      name: 'Node.js',
      category: 'Programming Language',
      confidence: 85,
      matchedFrom: 'cookie',
    });
  }

  if (/asp\.net/i.test(poweredByHeader) || headersLower['x-aspnet-version']) {
    const v = first(headersLower['x-aspnet-version']);
    addTech({
      name: 'ASP.NET',
      category: 'Framework',
      version: v ? String(v).trim() : undefined,
      confidence: 100,
      matchedFrom: 'header',
    });
  } else if (/asp\.net_sessionid/i.test(cookies)) {
    addTech({
      name: 'ASP.NET',
      category: 'Framework',
      confidence: 90,
      matchedFrom: 'cookie',
    });
  }

  if (/jsessionid/i.test(cookies)) {
    addTech({
      name: 'Java',
      category: 'Programming Language',
      confidence: 85,
      matchedFrom: 'cookie',
    });
  }

  if (/next\.js/i.test(poweredByHeader) || /_next\/static/i.test(body)) {
    addTech({
      name: 'Next.js',
      category: 'Framework',
      confidence: 95,
      matchedFrom: /next\.js/i.test(poweredByHeader) ? 'header' : 'script',
    });
    addTech({
      name: 'React',
      category: 'Frontend Library',
      confidence: 95,
      matchedFrom: 'script',
    });
  }

  // 3. CMS y Frameworks en HTML / Cookies
  if (/wordpress/i.test(generatorHeader) || /wp-(?:content|includes)/i.test(body) || /wordpress_test_cookie/i.test(cookies)) {
    const wpVersion = /<meta[^>]+name=["']generator["'][^>]+content=["']WordPress\s+([0-9.]+)/i.exec(body);
    addTech({
      name: 'WordPress',
      category: 'CMS',
      version: wpVersion ? wpVersion[1] : undefined,
      confidence: 95,
      matchedFrom: wpVersion ? 'meta' : 'body',
    });
    addTech({
      name: 'PHP',
      category: 'Programming Language',
      confidence: 90,
      matchedFrom: 'body',
    });
  }

  if (/drupal/i.test(generatorHeader) || headersLower['x-drupal-cache'] !== undefined || /Drupal\s+([0-9.]+)/i.test(body)) {
    const drupalVer = /Drupal\s+([0-9.]+)/i.exec(generatorHeader) ?? /Drupal\s+([0-9.]+)/i.exec(body);
    addTech({
      name: 'Drupal',
      category: 'CMS',
      version: drupalVer ? drupalVer[1] : undefined,
      confidence: 95,
      matchedFrom: generatorHeader ? 'header' : 'body',
    });
  }

  if (/joomla/i.test(body) || /<meta[^>]+content=["']Joomla/i.test(body)) {
    const joomlaVer = /Joomla!?\s+([0-9.]+)/i.exec(body);
    addTech({
      name: 'Joomla',
      category: 'CMS',
      version: joomlaVer ? joomlaVer[1] : undefined,
      confidence: 90,
      matchedFrom: 'body',
    });
  }

  if (/laravel_session/i.test(cookies)) {
    addTech({
      name: 'Laravel',
      category: 'Framework',
      confidence: 90,
      matchedFrom: 'cookie',
    });
    addTech({
      name: 'PHP',
      category: 'Programming Language',
      confidence: 90,
      matchedFrom: 'cookie',
    });
  }

  if (/csrftoken/i.test(cookies) && /sessionid/i.test(cookies)) {
    addTech({
      name: 'Django',
      category: 'Framework',
      confidence: 85,
      matchedFrom: 'cookie',
    });
    addTech({
      name: 'Python',
      category: 'Programming Language',
      confidence: 85,
      matchedFrom: 'cookie',
    });
  }

  // 4. Frontend libraries
  if (/data-reactroot/i.test(body) || /react(?:\.production|\.development)?\.min\.js/i.test(body)) {
    addTech({
      name: 'React',
      category: 'Frontend Library',
      confidence: 90,
      matchedFrom: 'body',
    });
  }

  if (/data-v-[a-f0-9]{6,8}/i.test(body) || /vue(?:\.runtime|\.min)?\.js/i.test(body)) {
    addTech({
      name: 'Vue.js',
      category: 'Frontend Library',
      confidence: 90,
      matchedFrom: 'body',
    });
  }

  const angularMatch = /ng-version=["']([0-9.]+)["']/i.exec(body);
  if (angularMatch) {
    addTech({
      name: 'Angular',
      category: 'Frontend Library',
      version: angularMatch[1],
      confidence: 95,
      matchedFrom: 'meta',
    });
  }

  const jqueryMatch = /jquery[.-]([0-9.]+)(?:\.min)?\.js/i.exec(body);
  if (jqueryMatch) {
    addTech({
      name: 'jQuery',
      category: 'Frontend Library',
      version: jqueryMatch[1],
      confidence: 90,
      matchedFrom: 'script',
    });
  }

  const technologies = Array.from(techMap.values()).sort((a, b) => b.confidence - a.confidence);

  // Generar hallazgos si se detectan componentes en EOL
  const findings: FindingDraft[] = [];
  for (const tech of technologies) {
    if (tech.eol) {
      findings.push({
        ruleId: 'HDR-EOL-TECH',
        location: `${location}#tech:${tech.name.toLowerCase()}`,
        title: `Tecnología web en Fin de Ciclo de Vida: ${tech.name} ${tech.version ?? ''}`.trim(),
        evidence: {
          technology: tech.name,
          version: tech.version,
          category: tech.category,
          notice: tech.eolNotice,
          matchedFrom: tech.matchedFrom,
        },
      });
    }
  }

  return { technologies, findings };
}
