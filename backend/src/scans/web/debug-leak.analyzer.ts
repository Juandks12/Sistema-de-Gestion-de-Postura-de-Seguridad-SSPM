import { randomBytes } from 'node:crypto';
import { FindingDraft } from '../scanner.interface';
import { httpProbe, HttpProbeOptions } from './http-client';

export interface DebugLeakAnalysisResult {
  analyzed: boolean;
  stackTraceDetected: boolean;
  framework?: string;
  sampleStackTrace?: string;
  internalPathsDisclosed: string[];
  debugHeadersFound: string[];
  findings: FindingDraft[];
}

interface StackTracePattern {
  framework: string;
  regex: RegExp;
}

const STACK_TRACE_PATTERNS: StackTracePattern[] = [
  // Node.js / Express / V8
  {
    framework: 'Node.js / Express',
    regex: /(?:Error|TypeError|ReferenceError|SyntaxError|RangeError):[^\n]+[\r\n]+\s+at\s+[^\n]+:\d+:\d+/i,
  },
  {
    framework: 'V8 / Node.js',
    regex: /\bat\s+(?:async\s+)?[a-zA-Z0-9_$.<>]+\s+\([^)]+:\d+:\d+\)/,
  },
  // Python / Django / Flask / Werkzeug
  {
    framework: 'Python / Django / Flask',
    regex: /Traceback \(most recent call last\):/i,
  },
  {
    framework: 'Python',
    regex: /File\s+"[^"]+\.py",\s+line\s+\d+,\s+in\s+/i,
  },
  {
    framework: 'Django / Werkzeug Debugger',
    regex: /(?:django\.core\.exceptions|werkzeug\.debug|ZeroDivisionError|NameError|KeyError):[^\n]+/i,
  },
  // PHP
  {
    framework: 'PHP',
    regex: /(?:Fatal error|Parse error|Warning|Notice):\s+[^\n]+in\s+\/[^\n]+\.php\s+on\s+line\s+\d+/i,
  },
  {
    framework: 'PHP / Xdebug',
    regex: /(?:Stack trace:|Call Stack:)\s*\n#\d+\s+[^\n]+/i,
  },
  // Java / Spring Boot
  {
    framework: 'Java / Spring',
    regex: /(?:java\.[a-z.]+(?:Exception|Error)|org\.springframework\.[a-z.]+(?:Exception|Error)):[^\n]+/i,
  },
  {
    framework: 'Java JVM',
    regex: /\s+at\s+([a-zA-Z0-9_$]+\.)+[a-zA-Z0-9_$]+\([a-zA-Z0-9_$]+\.java:\d+\)/,
  },
  {
    framework: 'Spring Boot Whitelabel',
    regex: /Whitelabel Error Page[\s\S]*?There was an unexpected error \(type=[^,]+,\s*status=500\)/i,
  },
  // .NET / ASP.NET
  {
    framework: 'ASP.NET / C#',
    regex: /\[(?:NullReferenceException|HttpException|SqlException|ArgumentException|InvalidOperationException):[^\n]+\]/i,
  },
  {
    framework: 'ASP.NET',
    regex: /Server Error in '.*?' Application\./i,
  },
  {
    framework: '.NET CLR',
    regex: /\s+at\s+System\.[a-zA-Z0-9_.]+\s+in\s+[a-zA-Z]:\\[^\n]+:line\s+\d+/i,
  },
  // Ruby on Rails
  {
    framework: 'Ruby on Rails',
    regex: /(?:ActionController::RoutingError|ActiveRecord::RecordNotFound|ActionView::Template::Error):[^\n]+/i,
  },
];

const UNIX_PATH_REGEX =
  /(?:\/var\/www\/|\/home\/[a-zA-Z0-9_-]+\/|\/app\/(?:src|server|node_modules)\/|\/opt\/[a-zA-Z0-9_-]+\/|\/srv\/[a-zA-Z0-9_-]+\/)[a-zA-Z0-9_./-]+\.(?:ts|js|php|py|java|cs|rb|go|json|yml|yaml|env)/g;

const WINDOWS_PATH_REGEX =
  /[a-zA-Z]:\\(?:inetpub|Users|app|services|var|sites|wwwroot)\\[a-zA-Z0-9_.\\-]+\.(?:ts|js|php|py|cs|dll|config)/gi;

const WORKSPACE_PATH_REGEX =
  /\/workspace\/[a-zA-Z0-9_./-]+\.(?:ts|js|py|php)/g;

const DEBUG_HEADERS = [
  'x-debug-token',
  'x-debug-token-link',
  'x-aspnet-version',
];

/**
 * Inspecciona el contenido de texto y las cabeceras HTTP en busca de trazas de error (Stack Traces)
 * y rutas internas del sistema de archivos.
 */
export function inspectContentForDebugLeaks(
  text: string,
  headers: Record<string, string | string[]>,
  sourceUrl: string,
): DebugLeakAnalysisResult {
  const findings: FindingDraft[] = [];
  const internalPathsDisclosed = new Set<string>();
  const debugHeadersFound: string[] = [];

  // 1. Detección de Stack Traces
  let stackTraceDetected = false;
  let framework: string | undefined;
  let sampleStackTrace: string | undefined;

  for (const pattern of STACK_TRACE_PATTERNS) {
    const match = text.match(pattern.regex);
    if (match) {
      stackTraceDetected = true;
      framework = pattern.framework;
      sampleStackTrace = match[0].trim().slice(0, 300);
      break;
    }
  }

  // 2. Detección de cabeceras de depuración activas
  for (const h of DEBUG_HEADERS) {
    if (headers[h]) {
      debugHeadersFound.push(h);
    }
  }

  // Si hay token de debug de Symfony pero no hubo traza de texto, se considera leak de depuración
  if (headers['x-debug-token']) {
    stackTraceDetected = true;
    framework = framework ?? 'Symfony Profiler';
  }

  if (stackTraceDetected) {
    findings.push({
      ruleId: 'WEB-DEBUG-STACKTRACE-LEAK',
      location: sourceUrl,
      title: `Fuga de trazas de depuración o Stack Trace en producción (${framework || 'Genérico'})`,
      evidence: {
        sourceUrl,
        framework: framework ?? 'Desconocido',
        sampleSnippet: sampleStackTrace ?? 'Cabecera de depuración activa',
        debugHeaders: debugHeadersFound,
      },
    });
  }

  // 3. Detección de rutas internas del sistema de archivos
  const unixMatches = text.match(UNIX_PATH_REGEX) || [];
  for (const p of unixMatches) internalPathsDisclosed.add(p);

  const winMatches = text.match(WINDOWS_PATH_REGEX) || [];
  for (const p of winMatches) internalPathsDisclosed.add(p);

  const wsMatches = text.match(WORKSPACE_PATH_REGEX) || [];
  for (const p of wsMatches) internalPathsDisclosed.add(p);

  const pathList = Array.from(internalPathsDisclosed);
  if (pathList.length > 0) {
    findings.push({
      ruleId: 'WEB-INTERNAL-PATH-DISCLOSURE',
      location: sourceUrl,
      title: `Divulgación de rutas internas del sistema de archivos (${pathList.length} detectadas)`,
      evidence: {
        sourceUrl,
        disclosedPathsCount: pathList.length,
        samplePaths: pathList.slice(0, 10),
      },
    });
  }

  return {
    analyzed: true,
    stackTraceDetected,
    framework,
    sampleStackTrace,
    internalPathsDisclosed: pathList,
    debugHeadersFound,
    findings,
  };
}

/**
 * Sondea activamente el activo provocando respuestas de error (canary 404 y sondeo de parámetros)
 * para identificar si el entorno de producción divulga información de depuración o rutas internas.
 */
export async function probeAndAnalyzeDebugLeaks(
  baseUrl: string,
  probeOptions: HttpProbeOptions,
): Promise<DebugLeakAnalysisResult> {
  const cleanBase = baseUrl.replace(/\/+$/, '');
  const canaryToken = randomBytes(6).toString('hex');
  const probeUrls = [
    `${cleanBase}/_sspm_debug_canary_${canaryToken}`,
    `${cleanBase}/?_sspm_dbg=1'&probe=";--`,
  ];

  const allDisclosedPaths = new Set<string>();
  const allDebugHeaders = new Set<string>();
  const aggregatedFindings: FindingDraft[] = [];
  let anyStackTrace = false;
  let detectedFramework: string | undefined;
  let sampleTrace: string | undefined;

  for (const probeUrl of probeUrls) {
    if (probeOptions.signal.aborted) break;

    const res = await httpProbe(probeUrl, {
      ...probeOptions,
      maxRedirects: 1,
    });

    if (res.ok) {
      const bodyText = res.body.toString('utf8');
      const inspection = inspectContentForDebugLeaks(bodyText, res.headers, res.finalUrl || probeUrl);

      if (inspection.stackTraceDetected) {
        anyStackTrace = true;
        detectedFramework = detectedFramework || inspection.framework;
        sampleTrace = sampleTrace || inspection.sampleStackTrace;
      }

      for (const p of inspection.internalPathsDisclosed) allDisclosedPaths.add(p);
      for (const h of inspection.debugHeadersFound) allDebugHeaders.add(h);

      for (const finding of inspection.findings) {
        if (!aggregatedFindings.some((f) => f.ruleId === finding.ruleId)) {
          aggregatedFindings.push(finding);
        }
      }
    }
  }

  return {
    analyzed: true,
    stackTraceDetected: anyStackTrace,
    framework: detectedFramework,
    sampleStackTrace: sampleTrace,
    internalPathsDisclosed: Array.from(allDisclosedPaths),
    debugHeadersFound: Array.from(allDebugHeaders),
    findings: aggregatedFindings,
  };
}
