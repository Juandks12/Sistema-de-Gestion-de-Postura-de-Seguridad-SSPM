import { AzureConnectorService } from './azure-connector.service';

describe('AzureConnectorService', () => {
  let service: AzureConnectorService;
  let fetchSpy: jest.SpyInstance;

  beforeEach(() => {
    service = new AzureConnectorService();
    fetchSpy = jest.spyOn(global, 'fetch');
  });

  afterEach(() => {
    fetchSpy.mockRestore();
  });

  it('obtiene token OAuth2 de Entra ID y verifica la suscripción en Azure ARM', async () => {
    fetchSpy
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          access_token: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.mock-azure-token',
          expires_in: 3599,
        }),
      } as any)
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          subscriptionId: 'b1234567-89ab-cdef-0123-456789abcdef',
          displayName: 'Suscripción Producción Corporativa',
          state: 'Enabled',
        }),
      } as any);

    const res = await service.verifyConnection({
      subscriptionId: 'b1234567-89ab-cdef-0123-456789abcdef',
      tenantId: 'a1111111-2222-3333-4444-555555555555',
      clientId: 'c9999999-8888-7777-6666-555555555555',
      clientSecret: 'super-secret-entra-value',
    });

    expect(res.valid).toBe(true);
    expect(res.subscriptionId).toBe('b1234567-89ab-cdef-0123-456789abcdef');
    expect(res.displayName).toBe('Suscripción Producción Corporativa');
    expect(res.state).toBe('Enabled');
    expect(fetchSpy).toHaveBeenCalledTimes(2);
  });

  it('retorna valid=false cuando Entra ID rechaza el Client Secret', async () => {
    fetchSpy.mockResolvedValueOnce({
      ok: false,
      status: 401,
      json: async () => ({
        error: 'invalid_client',
        error_description: 'AADSTS7000215: Invalid client secret provided.\r\nTrace ID: 123',
      }),
    } as any);

    const res = await service.verifyConnection({
      subscriptionId: 'b1234567-89ab-cdef-0123-456789abcdef',
      tenantId: 'a1111111-2222-3333-4444-555555555555',
      clientId: 'c9999999-8888-7777-6666-555555555555',
      clientSecret: 'wrong-secret',
    });

    expect(res.valid).toBe(false);
    expect(res.error).toContain('AADSTS7000215: Invalid client secret provided.');
  });

  it('retorna valid=false cuando el Service Principal no tiene permisos Reader sobre la suscripción (HTTP 403)', async () => {
    fetchSpy
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          access_token: 'valid-token-without-rbac',
          expires_in: 3599,
        }),
      } as any)
      .mockResolvedValueOnce({
        ok: false,
        status: 403,
        json: async () => ({
          error: {
            code: 'AuthorizationFailed',
            message: 'The client does not have authorization to perform action Microsoft.Resources/subscriptions/read.',
          },
        }),
      } as any);

    const res = await service.verifyConnection({
      subscriptionId: 'b1234567-89ab-cdef-0123-456789abcdef',
      tenantId: 'a1111111-2222-3333-4444-555555555555',
      clientId: 'c9999999-8888-7777-6666-555555555555',
      clientSecret: 'valid-secret',
    });

    expect(res.valid).toBe(false);
    expect(res.error).toContain('does not have authorization');
  });
});
