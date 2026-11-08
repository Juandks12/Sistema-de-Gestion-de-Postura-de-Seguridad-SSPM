import { JiraConnectorService } from './jira-connector.service';
import { FindingSeverity, TicketingProvider } from '@prisma/client';

describe('JiraConnectorService', () => {
  let service: JiraConnectorService;
  const originalFetch = global.fetch;

  beforeEach(() => {
    service = new JiraConnectorService();
  });

  afterEach(() => {
    global.fetch = originalFetch;
    jest.restoreAllMocks();
  });

  describe('testConnection', () => {
    it('debe validar la conexión y devolver los tipos de issue soportados si las credenciales son válidas', async () => {
      global.fetch = jest
        .fn()
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({ displayName: 'SecOps Agent' }),
        } as any)
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({
            name: 'Security Operations',
            key: 'SEC',
            issueTypes: [{ name: 'Bug' }, { name: 'Task' }],
          }),
        } as any);

      const result = await service.testConnection(
        'https://myorg.atlassian.net',
        'SEC',
        { email: 'dev@org.com', apiToken: 'token123' },
      );

      expect(result.ok).toBe(true);
      expect(result.provider).toBe(TicketingProvider.JIRA);
      expect(result.projectName).toBe('Security Operations');
      expect(result.availableIssueTypes).toEqual(['Bug', 'Task']);
    });

    it('debe manejar error de autenticación 401', async () => {
      global.fetch = jest.fn().mockResolvedValue({
        ok: false,
        status: 401,
        text: async () => 'Invalid credentials',
      } as any);

      const result = await service.testConnection(
        'https://myorg.atlassian.net',
        'SEC',
        { email: 'dev@org.com', apiToken: 'bad-token' },
      );

      expect(result.ok).toBe(false);
      expect(result.error).toContain('401');
    });

    it('debe manejar error 404 cuando el proyecto no existe', async () => {
      global.fetch = jest
        .fn()
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({ displayName: 'SecOps Agent' }),
        } as any)
        .mockResolvedValueOnce({
          ok: false,
          status: 404,
          text: async () => 'Not Found',
        } as any);

      const result = await service.testConnection(
        'https://myorg.atlassian.net',
        'NONEXISTENT',
        { email: 'dev@org.com', apiToken: 'token123' },
      );

      expect(result.ok).toBe(false);
      expect(result.error).toContain('NONEXISTENT');
    });
  });

  describe('createIssue', () => {
    it('debe formatear ADF, mapear severidad y retornar clave y URL de issue', async () => {
      global.fetch = jest.fn().mockResolvedValue({
        ok: true,
        status: 201,
        json: async () => ({
          id: '10045',
          key: 'SEC-101',
          self: 'https://myorg.atlassian.net/rest/api/3/issue/10045',
        }),
      } as any);

      const result = await service.createIssue(
        'https://myorg.atlassian.net',
        'SEC',
        'Bug',
        { email: 'dev@org.com', apiToken: 'token123' },
        {
          findingId: 'f-1',
          title: 'Exposición de Cabecera HSTS',
          description: 'El dominio no envía Strict-Transport-Security.',
          recommendation: 'Configurar HSTS con max-age=31536000.',
          severity: FindingSeverity.HIGH,
          cvssScore: 7.5,
          category: 'WEB_SECURITY' as any,
          assetValue: 'inmero.co',
          location: 'https://inmero.co',
          ruleId: 'SEC-HEADER-HSTS',
          cweId: 'CWE-319',
          owaspCategory: 'A05:2021-Security Misconfiguration',
        },
      );

      expect(result.key).toBe('SEC-101');
      expect(result.url).toBe('https://myorg.atlassian.net/browse/SEC-101');
      expect(result.status).toBe('Open');
    });
  });

  describe('getIssueStatus', () => {
    it('debe detectar correctamente si el issue está completado (done category)', async () => {
      global.fetch = jest.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          fields: {
            status: {
              name: 'Done',
              statusCategory: { key: 'done' },
            },
          },
        }),
      } as any);

      const status = await service.getIssueStatus(
        'https://myorg.atlassian.net',
        { email: 'dev@org.com', apiToken: 'token123' },
        'SEC-101',
      );

      expect(status.status).toBe('Done');
      expect(status.isClosed).toBe(true);
    });

    it('debe marcar isClosed como false si está en progreso', async () => {
      global.fetch = jest.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          fields: {
            status: {
              name: 'In Progress',
              statusCategory: { key: 'indeterminate' },
            },
          },
        }),
      } as any);

      const status = await service.getIssueStatus(
        'https://myorg.atlassian.net',
        { email: 'dev@org.com', apiToken: 'token123' },
        'SEC-101',
      );

      expect(status.status).toBe('In Progress');
      expect(status.isClosed).toBe(false);
    });
  });
});
