import { FindingDraft } from '../scanner.interface';
import { httpProbe, HttpProbeOptions } from './http-client';

export interface UnauthenticatedOperation {
  method: string;
  path: string;
  reason: string;
}

export interface QuerySecretParam {
  method: string;
  path: string;
  paramName: string;
}

export interface OpenApiAnalysisResult {
  analyzed: boolean;
  specType: 'openapi_v3' | 'swagger_v2' | 'unknown';
  specVersion?: string;
  sourceUrl: string;
  totalEndpoints: number;
  totalOperations: number;
  unauthenticatedOperations: UnauthenticatedOperation[];
  querySecretParams: QuerySecretParam[];
  internalHosts: string[];
  findings: FindingDraft[];
}

const SENSITIVE_PATH_REGEX =
  /\/(?:admin|auth|users?|accounts?|roles?|permissions?|keys?|tokens?|secrets?|config|settings|payments?|checkout|orders?|billing|refund|export|internal|private|upload|backup|password|reset-password)\b/i;

const SENSITIVE_PARAM_REGEX =
  /^(?:api[-_]?key|access[-_]?token|auth[-_]?token|client[-_]?secret|password|private[-_]?key|jwt|bearer|secret|token|apikey)$/i;

const PRIVATE_IP_REGEX =
  /^(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3})$/;

const INTERNAL_DOMAIN_REGEX =
  /(?:\.|\/|^)(?:local|internal|lan|corp|priv|home|intranet|cluster\.local)$/i;

function extractHostname(raw: string): string {
  try {
    const u = new URL(raw.includes('://') ? raw : `http://${raw}`);
    return u.hostname;
  } catch {
    return raw.replace(/^[a-z]+:\/\//i, '').split('/')[0].split(':')[0];
  }
}

export const OPENAPI_CANDIDATE_PATHS = [
  '/openapi.json',
  '/swagger.json',
  '/v2/api-docs',
  '/v3/api-docs',
  '/api-docs',
  '/api/swagger.json',
  '/api/openapi.json',
];

/**
 * Analiza una especificación OpenAPI v3 o Swagger v2 en busca de riesgos de seguridad:
 * 1. Operaciones sensibles sin autenticación (API-DOCS-UNAUTHENTICATED-OPERATIONS)
 * 2. Parámetros de autenticación o secretos en Query String (API-QUERY-SECRET-PARAM)
 * 3. Divulgación de IPs privadas o hostnames internos en servidores (API-INTERNAL-HOST-EXPOSED)
 */
export function analyzeOpenApiSpec(
  rawContent: string | Record<string, unknown>,
  sourceUrl: string,
): OpenApiAnalysisResult {
  let spec: Record<string, unknown>;
  if (typeof rawContent === 'string') {
    try {
      spec = JSON.parse(rawContent) as Record<string, unknown>;
    } catch {
      return {
        analyzed: false,
        specType: 'unknown',
        sourceUrl,
        totalEndpoints: 0,
        totalOperations: 0,
        unauthenticatedOperations: [],
        querySecretParams: [],
        internalHosts: [],
        findings: [],
      };
    }
  } else {
    spec = rawContent;
  }

  if (!spec || typeof spec !== 'object') {
    return {
      analyzed: false,
      specType: 'unknown',
      sourceUrl,
      totalEndpoints: 0,
      totalOperations: 0,
      unauthenticatedOperations: [],
      querySecretParams: [],
      internalHosts: [],
      findings: [],
    };
  }

  let specType: 'openapi_v3' | 'swagger_v2' | 'unknown' = 'unknown';
  let specVersion: string | undefined;

  if (typeof spec.openapi === 'string') {
    specType = 'openapi_v3';
    specVersion = spec.openapi;
  } else if (typeof spec.swagger === 'string') {
    specType = 'swagger_v2';
    specVersion = spec.swagger;
  }

  if (specType === 'unknown' && !spec.paths) {
    return {
      analyzed: false,
      specType: 'unknown',
      sourceUrl,
      totalEndpoints: 0,
      totalOperations: 0,
      unauthenticatedOperations: [],
      querySecretParams: [],
      internalHosts: [],
      findings: [],
    };
  }

  const findings: FindingDraft[] = [];
  const unauthenticatedOperations: UnauthenticatedOperation[] = [];
  const querySecretParams: QuerySecretParam[] = [];
  const internalHostsSet = new Set<string>();

  // Verificar esquemas de seguridad globales
  const hasGlobalSecurity = Array.isArray(spec.security) && spec.security.length > 0;

  // Analizar servidores / hosts internos
  const candidateHosts: string[] = [];
  if (typeof spec.host === 'string') {
    candidateHosts.push(spec.host);
  }
  if (Array.isArray(spec.servers)) {
    for (const server of spec.servers) {
      if (server && typeof server === 'object' && typeof (server as { url?: unknown }).url === 'string') {
        candidateHosts.push((server as { url: string }).url);
      }
    }
  }

  for (const hostStr of candidateHosts) {
    const hostname = extractHostname(hostStr);
    if (PRIVATE_IP_REGEX.test(hostname)) {
      internalHostsSet.add(hostname);
    } else if (INTERNAL_DOMAIN_REGEX.test(hostname) || hostname === 'localhost') {
      internalHostsSet.add(hostname);
    }
  }

  const internalHosts = Array.from(internalHostsSet);
  if (internalHosts.length > 0) {
    findings.push({
      ruleId: 'API-INTERNAL-HOST-EXPOSED',
      location: sourceUrl,
      title: `Hostnames o direcciones IP internas divulgadas en especificación OpenAPI (${internalHosts.slice(0, 3).join(', ')})`,
      evidence: {
        sourceUrl,
        internalHosts,
      },
    });
  }

  const paths = (spec.paths && typeof spec.paths === 'object') ? (spec.paths as Record<string, unknown>) : {};
  const pathKeys = Object.keys(paths);
  const totalEndpoints = pathKeys.length;
  let totalOperations = 0;

  const HTTP_METHODS = ['get', 'post', 'put', 'delete', 'patch', 'options', 'head'];

  for (const path of pathKeys) {
    const pathItem = paths[path];
    if (!pathItem || typeof pathItem !== 'object') continue;

    const pathItemObj = pathItem as Record<string, unknown>;
    const pathParameters = Array.isArray(pathItemObj.parameters) ? (pathItemObj.parameters as Record<string, unknown>[]) : [];

    for (const method of HTTP_METHODS) {
      const operation = pathItemObj[method];
      if (!operation || typeof operation !== 'object') continue;

      totalOperations++;
      const opObj = operation as Record<string, unknown>;
      const opMethod = method.toUpperCase();

      // 1. Evaluación de autenticación
      let isOperationAuthenticated = hasGlobalSecurity;
      if (Array.isArray(opObj.security)) {
        isOperationAuthenticated = opObj.security.length > 0;
      }

      if (!isOperationAuthenticated) {
        const isStateModifying = ['POST', 'PUT', 'DELETE', 'PATCH'].includes(opMethod);
        const isSensitivePath = SENSITIVE_PATH_REGEX.test(path);

        if (isStateModifying || isSensitivePath) {
          unauthenticatedOperations.push({
            method: opMethod,
            path,
            reason: isSensitivePath
              ? 'Ruta crítica o administrativa sin control de acceso'
              : 'Operación mutativa de estado sin esquema de seguridad requerido',
          });
        }
      }

      // 2. Evaluación de secretos en query parameters
      const opParameters = Array.isArray(opObj.parameters) ? (opObj.parameters as Record<string, unknown>[]) : [];
      const combinedParams = [...pathParameters, ...opParameters];

      for (const param of combinedParams) {
        if (!param || typeof param !== 'object') continue;
        const paramIn = typeof param.in === 'string' ? param.in.toLowerCase() : '';
        const paramName = typeof param.name === 'string' ? param.name : '';

        if (paramIn === 'query' && SENSITIVE_PARAM_REGEX.test(paramName)) {
          querySecretParams.push({
            method: opMethod,
            path,
            paramName,
          });
        }
      }
    }
  }

  // Hallazgo: Operaciones sensibles sin autenticación
  if (unauthenticatedOperations.length > 0) {
    findings.push({
      ruleId: 'API-DOCS-UNAUTHENTICATED-OPERATIONS',
      location: `${sourceUrl} (${unauthenticatedOperations.length} operaciones)`,
      title: `Operaciones sensibles sin autenticación expuestas en documentación OpenAPI (${unauthenticatedOperations.length} detectadas)`,
      evidence: {
        sourceUrl,
        totalOperations,
        unauthenticatedCount: unauthenticatedOperations.length,
        sampleOperations: unauthenticatedOperations.slice(0, 10),
      },
    });
  }

  // Hallazgo: Parámetros de secreto en Query
  if (querySecretParams.length > 0) {
    findings.push({
      ruleId: 'API-QUERY-SECRET-PARAM',
      location: `${sourceUrl} (${querySecretParams.length} parámetros)`,
      title: `Parámetros confidenciales o secretos transmitidos en cadena de consulta (${querySecretParams.length} detectados)`,
      evidence: {
        sourceUrl,
        totalSecretsInQuery: querySecretParams.length,
        sampleParams: querySecretParams.slice(0, 10),
      },
    });
  }

  return {
    analyzed: true,
    specType,
    specVersion,
    sourceUrl,
    totalEndpoints,
    totalOperations,
    unauthenticatedOperations,
    querySecretParams,
    internalHosts,
    findings,
  };
}

/**
 * Sondea activamente rutas conocidas de especificaciones OpenAPI y analiza la primera encontrada.
 */
export async function probeAndAnalyzeOpenApi(
  baseUrl: string,
  probeOptions: HttpProbeOptions,
): Promise<OpenApiAnalysisResult | null> {
  const cleanBase = baseUrl.replace(/\/+$/, '');

  for (const candidate of OPENAPI_CANDIDATE_PATHS) {
    if (probeOptions.signal.aborted) break;

    const probeUrl = `${cleanBase}${candidate}`;
    const res = await httpProbe(probeUrl, {
      ...probeOptions,
      maxRedirects: 2,
    });

    if (res.ok && res.status === 200) {
      const contentType = res.contentType.toLowerCase();
      const bodyText = res.body.toString('utf8');

      const isJson = contentType.includes('json') || bodyText.trim().startsWith('{');
      const hasOpenApiSignature =
        bodyText.includes('"openapi"') ||
        bodyText.includes('"swagger"') ||
        bodyText.includes('"paths"');

      if (isJson && hasOpenApiSignature) {
        return analyzeOpenApiSpec(bodyText, res.finalUrl || probeUrl);
      }
    }
  }

  return null;
}
