import { FindingDraft } from '../scanner.interface';
import { httpProbe, HttpProbeOptions } from './http-client';

export interface CmsEcommerceAnalysisResult {
  findings: FindingDraft[];
  wpUserEnumerationExposed: boolean;
  wpXmlRpcEnabled: boolean;
  wpDebugLogExposed: boolean;
  graphqlIntrospectionActive: boolean;
}

/**
 * Analiza riesgos críticos específicos de CMS y tiendas en línea (WordPress / WooCommerce,
 * APIs REST y GraphQL).
 */
export async function analyzeCmsAndEcommercePlatform(
  baseUrl: string,
  probeOptions: HttpProbeOptions,
): Promise<CmsEcommerceAnalysisResult> {
  const base = new URL(baseUrl);
  const baseOrigin = base.origin;
  const findings: FindingDraft[] = [];

  let wpUserEnumerationExposed = false;
  let wpXmlRpcEnabled = false;
  let wpDebugLogExposed = false;
  let graphqlIntrospectionActive = false;

  // 1. Detección de Enumeración de Usuarios en WordPress / WooCommerce (/wp-json/wp/v2/users)
  try {
    const wpUsersUrl = `${baseOrigin}/wp-json/wp/v2/users`;
    const usersProbe = await httpProbe(wpUsersUrl, {
      ...probeOptions,
      maxRedirects: 2,
      maxBodyBytes: 64 * 1024,
    });

    if (usersProbe.ok && usersProbe.status === 200 && usersProbe.contentType.includes('application/json')) {
      try {
        const data = JSON.parse(usersProbe.body.toString('utf8'));
        if (Array.isArray(data) && data.length > 0 && data[0].slug && data[0].name) {
          wpUserEnumerationExposed = true;
          const userSlugs = data.map((u: { slug?: string }) => u.slug).filter(Boolean);

          findings.push({
            ruleId: 'CMS-WP-USER-ENUMERATION',
            location: wpUsersUrl,
            title: `Enumeración de usuarios administradores expuesta en WordPress / WooCommerce (/wp-json/wp/v2/users)`,
            evidence: {
              url: wpUsersUrl,
              discoveredUsersCount: data.length,
              sampleUsers: userSlugs.slice(0, 5),
              impact: 'Facilita ataques directos de fuerza bruta y credential stuffing con usuarios legítimos de la tienda.',
            },
          });
        }
      } catch {
        // No es JSON válido
      }
    }
  } catch {
    // Ignorar fallo de conexión
  }

  // 2. Detección de XML-RPC habilitado en WordPress (/xmlrpc.php)
  try {
    const xmlRpcUrl = `${baseOrigin}/xmlrpc.php`;
    const xmlRpcProbe = await httpProbe(xmlRpcUrl, {
      ...probeOptions,
      method: 'GET',
      maxRedirects: 1,
      maxBodyBytes: 16 * 1024,
    });

    if (xmlRpcProbe.ok) {
      const text = xmlRpcProbe.body.toString('utf8');
      const isXmlRpcActive =
        (xmlRpcProbe.status === 200 || xmlRpcProbe.status === 405) &&
        /XML-RPC server accepts POST requests only|XML-RPC/i.test(text);

      if (isXmlRpcActive) {
        wpXmlRpcEnabled = true;
        findings.push({
          ruleId: 'CMS-WP-XMLRPC-ENABLED',
          location: xmlRpcUrl,
          title: `Interfaz XML-RPC activa en WordPress / WooCommerce (/xmlrpc.php)`,
          evidence: {
            url: xmlRpcUrl,
            status: xmlRpcProbe.status,
            responseSnippet: text.slice(0, 150),
            impact: 'Permite ataques de fuerza bruta masiva multicall y amplificación DDoS.',
          },
        });
      }
    }
  } catch {
    // Ignorar
  }

  // 3. Detección de debug.log expuesto (/wp-content/debug.log)
  try {
    const debugLogUrl = `${baseOrigin}/wp-content/debug.log`;
    const debugProbe = await httpProbe(debugLogUrl, {
      ...probeOptions,
      maxRedirects: 1,
      maxBodyBytes: 32 * 1024,
    });

    if (debugProbe.ok && debugProbe.status === 200) {
      const logText = debugProbe.body.toString('utf8');
      if (/PHP (?:Notice|Warning|Fatal error)|Stack trace:/i.test(logText) || /\[\d{2}-[a-zA-Z]{3}-\d{4}/.test(logText)) {
        wpDebugLogExposed = true;
        findings.push({
          ruleId: 'CMS-WP-DEBUG-LOG-EXPOSED',
          location: debugLogUrl,
          title: `Archivo debug.log de WordPress expuesto públicamente con trazas de errores y base de datos`,
          evidence: {
            url: debugLogUrl,
            status: debugProbe.status,
            lineSample: logText.split('\n')[0]?.slice(0, 150),
          },
        });
      }
    }
  } catch {
    // Ignorar
  }

  // 4. Sondeo Activo de Introspección GraphQL
  const graphqlTargets = [`${baseOrigin}/graphql`, `${baseOrigin}/api/graphql`];
  for (const gqlUrl of graphqlTargets) {
    if (probeOptions.signal.aborted || graphqlIntrospectionActive) break;

    try {
      const introspectionQuery = JSON.stringify({
        query: '{ __schema { queryType { name } types { name } } }',
      });

      const gqlProbe = await httpProbe(gqlUrl, {
        ...probeOptions,
        method: 'POST',
        headers: {
          'content-type': 'application/json',
        },
        body: introspectionQuery,
        maxRedirects: 1,
        maxBodyBytes: 128 * 1024,
      });

      if (gqlProbe.ok && gqlProbe.status === 200 && gqlProbe.contentType.includes('json')) {
        const gqlText = gqlProbe.body.toString('utf8');
        if (/"data"\s*:\s*\{\s*"__schema"/i.test(gqlText)) {
          graphqlIntrospectionActive = true;
          findings.push({
            ruleId: 'API-GRAPHQL-INTROSPECTION',
            location: gqlUrl,
            title: `Introspección activa de GraphQL expone el esquema completo de la API del comercio`,
            evidence: {
              url: gqlUrl,
              introspectionEnabled: true,
              schemaSample: gqlText.slice(0, 200),
              impact: 'Cualquier usuario anónimo puede mapear todas las mutaciones, consultas y modelos internos de la tienda.',
            },
          });
        }
      }
    } catch {
      // Ignorar fallo de endpoint GraphQL
    }
  }

  return {
    findings,
    wpUserEnumerationExposed,
    wpXmlRpcEnabled,
    wpDebugLogExposed,
    graphqlIntrospectionActive,
  };
}
