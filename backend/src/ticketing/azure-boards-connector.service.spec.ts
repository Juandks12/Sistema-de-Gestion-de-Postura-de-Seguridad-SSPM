import { AzureBoardsConnectorService } from './azure-boards-connector.service';
import { FindingSeverity, TicketingProvider } from '@prisma/client';

describe('AzureBoardsConnectorService', () => {
  let service: AzureBoardsConnectorService;
  const originalFetch = global.fetch;

  beforeEach(() => {
    service = new AzureBoardsConnectorService();
  });

  afterEach(() => {
    global.fetch = originalFetch;
    jest.restoreAllMocks();
  });

  describe('testConnection', () => {
    it('debe validar la conexión con Azure DevOps Boards y listar los tipos de work item', async () => {
      global.fetch = jest.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          value: [{ name: 'Bug' }, { name: 'Issue' }, { name: 'Task' }],
        }),
      } as any);

      const result = await service.testConnection(
        'https://dev.azure.com/devops-sre-lab',
        'DevOps - SRE',
        { personalAccessToken: 'my-pat' },
      );

      expect(result.ok).toBe(true);
      expect(result.provider).toBe(TicketingProvider.AZURE_BOARDS);
      expect(result.projectName).toBe('DevOps - SRE');
      expect(result.availableIssueTypes).toEqual(['Bug', 'Issue', 'Task']);
    });

    it('debe manejar error de autenticación 401', async () => {
      global.fetch = jest.fn().mockResolvedValue({
        ok: false,
        status: 401,
        text: async () => 'Invalid PAT token',
      } as any);

      const result = await service.testConnection(
        'https://dev.azure.com/devops-sre-lab',
        'DevOps - SRE',
        { personalAccessToken: 'invalid-pat' },
      );

      expect(result.ok).toBe(false);
      expect(result.error).toContain('401');
    });
  });

  describe('createWorkItem', () => {
    it('debe enviar documento JSON Patch y devolver ID, URL web y estado inicial', async () => {
      global.fetch = jest.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          id: 190,
          fields: {
            'System.State': 'To Do',
          },
          _links: {
            html: {
              href: 'https://dev.azure.com/devops-sre-lab/DevOps%20-%20SRE/_workitems/edit/190',
            },
          },
        }),
      } as any);

      const result = await service.createWorkItem(
        'https://dev.azure.com/devops-sre-lab',
        'DevOps - SRE',
        'Issue',
        { personalAccessToken: 'my-pat' },
        {
          findingId: 'f-2',
          title: 'Vulnerabilidad Crítica OpenSSL RCE',
          description: 'Buffer overflow en manejo de certificados X.509.',
          recommendation: 'Actualizar a OpenSSL 3.0.12 inmediatamente.',
          severity: FindingSeverity.CRITICAL,
          cvssScore: 9.8,
          category: 'VULNERABILITY' as any,
          assetValue: '45.33.32.156',
          location: '45.33.32.156:443',
          ruleId: 'VULN-KNOWN-CVE',
          cweId: 'CWE-119',
        },
      );

      expect(result.key).toBe('190');
      expect(result.url).toContain('/_workitems/edit/190');
      expect(result.status).toBe('To Do');
    });
  });

  describe('getWorkItemStatus', () => {
    it('debe detectar work items en estado Closed/Done como isClosed: true', async () => {
      global.fetch = jest.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          id: 190,
          fields: {
            'System.State': 'Closed',
          },
        }),
      } as any);

      const status = await service.getWorkItemStatus(
        'https://dev.azure.com/devops-sre-lab',
        { personalAccessToken: 'my-pat' },
        '#190',
      );

      expect(status.status).toBe('Closed');
      expect(status.isClosed).toBe(true);
    });

    it('debe detectar work items en estado Doing como isClosed: false', async () => {
      global.fetch = jest.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          id: 190,
          fields: {
            'System.State': 'Doing',
          },
        }),
      } as any);

      const status = await service.getWorkItemStatus(
        'https://dev.azure.com/devops-sre-lab',
        { personalAccessToken: 'my-pat' },
        '190',
      );

      expect(status.status).toBe('Doing');
      expect(status.isClosed).toBe(false);
    });
  });
});
