import {
  analyzeOpenApiSpec,
  probeAndAnalyzeOpenApi,
} from './openapi-security.analyzer';
import { httpProbe } from './http-client';

jest.mock('./http-client', () => ({
  ...jest.requireActual('./http-client'),
  httpProbe: jest.fn(),
}));

describe('OpenApiSecurityAnalyzer', () => {
  const mockedHttpProbe = httpProbe as unknown as jest.Mock;

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('analyzeOpenApiSpec', () => {
    it('detecta operaciones sensibles sin autenticación en OpenAPI v3', () => {
      const spec = {
        openapi: '3.0.1',
        info: { title: 'Test API', version: '1.0' },
        paths: {
          '/api/users': {
            get: { summary: 'List users' },
            post: { summary: 'Create user' },
          },
          '/api/products': {
            get: { summary: 'List public products' },
          },
          '/api/orders/{id}': {
            delete: { summary: 'Delete order' },
          },
        },
      };

      const result = analyzeOpenApiSpec(spec, 'https://example.com/openapi.json');
      expect(result.analyzed).toBe(true);
      expect(result.specType).toBe('openapi_v3');
      expect(result.totalEndpoints).toBe(3);
      expect(result.totalOperations).toBe(4);

      // GET /api/users (sensitive path), POST /api/users (mutative), DELETE /api/orders/{id} (mutative)
      // GET /api/products is public and not sensitive
      expect(result.unauthenticatedOperations.length).toBe(3);

      const unauthFinding = result.findings.find(
        (f) => f.ruleId === 'API-DOCS-UNAUTHENTICATED-OPERATIONS',
      );
      expect(unauthFinding).toBeDefined();
      expect(unauthFinding?.title).toMatch(/Operaciones sensibles sin autenticación/);
    });

    it('respeta esquemas de seguridad globales y por operación', () => {
      const spec = {
        openapi: '3.0.0',
        security: [{ bearerAuth: [] }],
        paths: {
          '/api/admin/config': {
            get: { summary: 'Admin config' }, // Authenticated via global
          },
          '/api/public/status': {
            get: { summary: 'Status' },
          },
          '/api/override/unprotected': {
            post: {
              summary: 'Unprotected webhook',
              security: [], // Explicitly unauthenticated override!
            },
          },
        },
      };

      const result = analyzeOpenApiSpec(spec, 'https://example.com/openapi.json');
      expect(result.analyzed).toBe(true);
      // Only the POST with security: [] override is unauthenticated and sensitive
      expect(result.unauthenticatedOperations.length).toBe(1);
      expect(result.unauthenticatedOperations[0]).toEqual({
        method: 'POST',
        path: '/api/override/unprotected',
        reason: 'Operación mutativa de estado sin esquema de seguridad requerido',
      });
    });

    it('detecta parámetros de autenticación y secretos en Query String', () => {
      const spec = {
        swagger: '2.0',
        info: { title: 'Legacy Swagger', version: '2.0' },
        paths: {
          '/api/export': {
            get: {
              summary: 'Export data',
              parameters: [
                { name: 'api_key', in: 'query', type: 'string' },
                { name: 'format', in: 'query', type: 'string' },
              ],
            },
          },
          '/api/payment': {
            post: {
              summary: 'Process payment',
              parameters: [
                { name: 'client_secret', in: 'query', type: 'string' },
              ],
            },
          },
        },
      };

      const result = analyzeOpenApiSpec(spec, 'https://example.com/swagger.json');
      expect(result.analyzed).toBe(true);
      expect(result.specType).toBe('swagger_v2');
      expect(result.querySecretParams.length).toBe(2);

      const secretParamFinding = result.findings.find(
        (f) => f.ruleId === 'API-QUERY-SECRET-PARAM',
      );
      expect(secretParamFinding).toBeDefined();
      expect(secretParamFinding?.evidence?.totalSecretsInQuery).toBe(2);
    });

    it('detecta IPs privadas o hostnames internos en servers y host', () => {
      const spec = {
        openapi: '3.0.2',
        servers: [
          { url: 'https://api.internal.corp/v1', description: 'Internal production' },
          { url: 'http://192.168.1.100:8080', description: 'Internal test backend' },
          { url: 'https://api.public.com', description: 'Public gateway' },
        ],
        paths: {
          '/ping': {
            get: { summary: 'Ping' },
          },
        },
      };

      const result = analyzeOpenApiSpec(spec, 'https://api.public.com/openapi.json');
      expect(result.analyzed).toBe(true);
      expect(result.internalHosts.length).toBe(2);

      const hostFinding = result.findings.find(
        (f) => f.ruleId === 'API-INTERNAL-HOST-EXPOSED',
      );
      expect(hostFinding).toBeDefined();
      expect(hostFinding?.evidence?.internalHosts).toEqual(
        expect.arrayContaining(['api.internal.corp', '192.168.1.100']),
      );
    });

    it('maneja strings JSON inválidos o specs vacías sin romper', () => {
      const resultInvalid = analyzeOpenApiSpec('invalid json {{', 'https://example.com/api');
      expect(resultInvalid.analyzed).toBe(false);
      expect(resultInvalid.findings).toHaveLength(0);

      const resultEmpty = analyzeOpenApiSpec({}, 'https://example.com/api');
      expect(resultEmpty.analyzed).toBe(false);
      expect(resultEmpty.findings).toHaveLength(0);
    });
  });

  describe('probeAndAnalyzeOpenApi', () => {
    it('sondea candidatos y analiza la primera respuesta válida', async () => {
      const mockSpec = {
        openapi: '3.0.0',
        paths: {
          '/admin/users': {
            delete: { summary: 'Delete user' },
          },
        },
      };

      mockedHttpProbe
        // /openapi.json -> 404
        .mockResolvedValueOnce({
          ok: true,
          status: 404,
          contentType: 'text/html',
          body: Buffer.from('Not found'),
        })
        // /swagger.json -> 200 with OpenAPI spec
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          finalUrl: 'https://example.com/swagger.json',
          contentType: 'application/json',
          body: Buffer.from(JSON.stringify(mockSpec)),
        });

      const outcome = await probeAndAnalyzeOpenApi('https://example.com', {
        allowPrivate: false,
        signal: new AbortController().signal,
      });

      expect(outcome).not.toBeNull();
      expect(outcome?.analyzed).toBe(true);
      expect(outcome?.sourceUrl).toBe('https://example.com/swagger.json');
      expect(outcome?.unauthenticatedOperations).toHaveLength(1);
    });

    it('retorna null si ningún endpoint OpenAPI responde satisfactoriamente', async () => {
      mockedHttpProbe.mockResolvedValue({
        ok: true,
        status: 404,
        contentType: 'text/html',
        body: Buffer.from('Not found'),
      });

      const outcome = await probeAndAnalyzeOpenApi('https://example.com', {
        allowPrivate: false,
        signal: new AbortController().signal,
      });

      expect(outcome).toBeNull();
    });
  });
});
