import * as crypto from 'crypto';
import { GcpConnectorService } from './gcp-connector.service';

describe('GcpConnectorService', () => {
  let service: GcpConnectorService;
  let fetchSpy: jest.SpyInstance;
  let testPrivateKey: string;

  beforeAll(() => {
    // Generar un par de claves RSA real para probar la firma criptográfica RS256
    const { privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    testPrivateKey = privateKey;
  });

  beforeEach(() => {
    service = new GcpConnectorService();
    fetchSpy = jest.spyOn(global, 'fetch');
  });

  afterEach(() => {
    fetchSpy.mockRestore();
  });

  it('debe parsear credenciales desde un Service Account JSON string', () => {
    const saJson = JSON.stringify({
      type: 'service_account',
      project_id: 'sec-audit-prod-01',
      client_email: 'sspm-auditor@sec-audit-prod-01.iam.gserviceaccount.com',
      private_key: testPrivateKey,
    });

    const parsed = service.parseCredentials({
      projectId: '',
      serviceAccountJson: saJson,
    });

    expect(parsed.projectId).toBe('sec-audit-prod-01');
    expect(parsed.clientEmail).toBe('sspm-auditor@sec-audit-prod-01.iam.gserviceaccount.com');
    expect(parsed.privateKey).toBe(testPrivateKey.trim());
  });

  it('debe generar un JWT firmado con RS256 válido', () => {
    const jwt = service.createSignedJwt(
      'sspm-auditor@sec-audit-prod-01.iam.gserviceaccount.com',
      testPrivateKey,
    );

    expect(jwt).toBeDefined();
    const parts = jwt.split('.');
    expect(parts.length).toBe(3);

    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));

    expect(header.alg).toBe('RS256');
    expect(claims.iss).toBe('sspm-auditor@sec-audit-prod-01.iam.gserviceaccount.com');
    expect(claims.aud).toBe('https://oauth2.googleapis.com/token');
  });

  it('debe obtener token de acceso e intercambiarlo exitosamente con Google OAuth2', async () => {
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({
        access_token: 'ya29.mock-google-token',
        expires_in: 3599,
        token_type: 'Bearer',
      }),
    } as any);

    const res = await service.acquireAccessToken({
      projectId: 'sec-audit-prod-01',
      clientEmail: 'sspm-auditor@sec-audit-prod-01.iam.gserviceaccount.com',
      privateKey: testPrivateKey,
    });

    expect(res.accessToken).toBe('ya29.mock-google-token');
    expect(res.expiresIn).toBe(3599);
    expect(res.projectId).toBe('sec-audit-prod-01');
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(fetchSpy).toHaveBeenCalledWith(
      'https://oauth2.googleapis.com/token',
      expect.objectContaining({ method: 'POST' }),
    );
  });

  it('debe verificar conectividad exitosa contra Cloud Resource Manager', async () => {
    fetchSpy
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          access_token: 'ya29.mock-google-token',
          expires_in: 3599,
        }),
      } as any)
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          projectId: 'sec-audit-prod-01',
          projectNumber: '123456789012',
          name: 'Proyecto Producción Principal GCP',
          lifecycleState: 'ACTIVE',
        }),
      } as any);

    const result = await service.verifyConnection({
      projectId: 'sec-audit-prod-01',
      clientEmail: 'sspm-auditor@sec-audit-prod-01.iam.gserviceaccount.com',
      privateKey: testPrivateKey,
    });

    expect(result.valid).toBe(true);
    expect(result.projectId).toBe('sec-audit-prod-01');
    expect(result.projectNumber).toBe('123456789012');
    expect(result.displayName).toBe('Proyecto Producción Principal GCP');
    expect(result.state).toBe('ACTIVE');
    expect(result.latencyMs).toBeGreaterThanOrEqual(0);
  });

  it('retorna valid=false cuando Google OAuth2 rechaza la clave privada', async () => {
    fetchSpy.mockResolvedValueOnce({
      ok: false,
      status: 400,
      json: async () => ({
        error: 'invalid_grant',
        error_description: 'Invalid JWT Signature.',
      }),
    } as any);

    const result = await service.verifyConnection({
      projectId: 'sec-audit-prod-01',
      clientEmail: 'sspm-auditor@sec-audit-prod-01.iam.gserviceaccount.com',
      privateKey: testPrivateKey,
    });

    expect(result.valid).toBe(false);
    expect(result.error).toContain('Invalid JWT Signature');
  });

  it('retorna valid=false cuando la Service Account carece de permisos sobre el proyecto (HTTP 403)', async () => {
    fetchSpy
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          access_token: 'ya29.mock-google-token',
          expires_in: 3599,
        }),
      } as any)
      .mockResolvedValueOnce({
        ok: false,
        status: 403,
        json: async () => ({
          error: {
            code: 403,
            message: 'The caller does not have permission on project sec-audit-prod-01',
            status: 'PERMISSION_DENIED',
          },
        }),
      } as any);

    const result = await service.verifyConnection({
      projectId: 'sec-audit-prod-01',
      clientEmail: 'sspm-auditor@sec-audit-prod-01.iam.gserviceaccount.com',
      privateKey: testPrivateKey,
    });

    expect(result.valid).toBe(false);
    expect(result.error).toContain('The caller does not have permission');
  });
});
