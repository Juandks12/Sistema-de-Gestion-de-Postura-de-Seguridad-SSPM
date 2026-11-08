import { BadRequestException } from '@nestjs/common';
import { FindingSeverity, FindingStatus, TicketingAutoCreateThreshold, TicketingProvider, UserRole } from '@prisma/client';
import { AuditService } from '../audit/audit.service';
import { CryptoVaultService } from '../common/crypto/crypto-vault.service';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { PrismaService } from '../prisma/prisma.service';
import { AzureBoardsConnectorService } from './azure-boards-connector.service';
import { JiraConnectorService } from './jira-connector.service';
import { TicketingService } from './ticketing.service';

describe('TicketingService', () => {
  let service: TicketingService;
  let prisma: jest.Mocked<any>;
  let cryptoVault: jest.Mocked<any>;
  let jiraConnector: jest.Mocked<any>;
  let azureBoardsConnector: jest.Mocked<any>;
  let audit: jest.Mocked<any>;

  const mockUser: AuthUser = {
    id: 'user-123',
    email: 'admin@secops.local',
    fullName: 'Admin SecOps',
    role: UserRole.ADMIN,
    organizationId: 'org-abc',
  };

  beforeEach(() => {
    prisma = {
      ticketingIntegration: {
        findUnique: jest.fn(),
        upsert: jest.fn(),
        deleteMany: jest.fn(),
        updateMany: jest.fn(),
      },
      finding: {
        findFirst: jest.fn(),
        findMany: jest.fn(),
        update: jest.fn(),
      },
    };

    cryptoVault = {
      encrypt: jest.fn((val: string) => `enc:${val}`),
      decrypt: jest.fn((enc: string) => enc.replace(/^enc:/, '')),
    };

    jiraConnector = {
      testConnection: jest.fn(),
      createIssue: jest.fn(),
      getIssueStatus: jest.fn(),
    };

    azureBoardsConnector = {
      testConnection: jest.fn(),
      createWorkItem: jest.fn(),
      getWorkItemStatus: jest.fn(),
    };

    audit = {
      record: jest.fn(),
    };

    service = new TicketingService(
      prisma as unknown as PrismaService,
      cryptoVault as unknown as CryptoVaultService,
      jiraConnector as unknown as JiraConnectorService,
      azureBoardsConnector as unknown as AzureBoardsConnectorService,
      audit as unknown as AuditService,
    );
  });

  describe('getConfig', () => {
    it('debe devolver configured: false si la organización no tiene integración configurada', async () => {
      prisma.ticketingIntegration.findUnique.mockResolvedValue(null);

      const result = await service.getConfig('org-abc');

      expect(result).toEqual({ configured: false });
    });

    it('debe devolver un resumen seguro sin credenciales sensibles si existe integración', async () => {
      prisma.ticketingIntegration.findUnique.mockResolvedValue({
        id: 'int-1',
        provider: TicketingProvider.JIRA,
        enabled: true,
        instanceUrl: 'https://myorg.atlassian.net',
        projectKey: 'SEC',
        issueType: 'Bug',
        autoCreateThreshold: TicketingAutoCreateThreshold.CRITICAL,
        credentialsEncrypted: 'enc:secret',
        lastTestedAt: new Date(),
        lastTestStatus: 'SUCCESS',
        lastTestError: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      const result = await service.getConfig('org-abc');

      expect(result).not.toBeNull();
      expect(result?.configured).toBe(true);
      expect(result?.provider).toBe(TicketingProvider.JIRA);
      expect(result?.projectKey).toBe('SEC');
      expect(result?.maskedCredentials).toBeDefined();
      expect((result as any).credentialsEncrypted).toBeUndefined();
    });
  });

  describe('configureIntegration', () => {
    it('debe validar conectividad, cifrar credenciales y guardar la integración', async () => {
      jiraConnector.testConnection.mockResolvedValue({
        ok: true,
        provider: TicketingProvider.JIRA,
        projectName: 'Security',
        availableIssueTypes: ['Bug'],
      });

      prisma.ticketingIntegration.upsert.mockResolvedValue({ id: 'int-1' });
      prisma.ticketingIntegration.findUnique.mockResolvedValue({
        id: 'int-1',
        provider: TicketingProvider.JIRA,
        enabled: true,
        instanceUrl: 'https://myorg.atlassian.net',
        projectKey: 'SEC',
        issueType: 'Bug',
        autoCreateThreshold: TicketingAutoCreateThreshold.DISABLED,
        credentialsEncrypted: 'enc:data',
        lastTestedAt: new Date(),
        lastTestStatus: 'SUCCESS',
        lastTestError: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      const result = await service.configureIntegration(mockUser, {
        provider: TicketingProvider.JIRA,
        instanceUrl: 'https://myorg.atlassian.net',
        projectKey: 'SEC',
        credentials: { email: 'admin@org.com', apiToken: 'token123' },
      });

      expect(jiraConnector.testConnection).toHaveBeenCalled();
      expect(cryptoVault.encrypt).toHaveBeenCalled();
      expect(prisma.ticketingIntegration.upsert).toHaveBeenCalled();
      expect(audit.record).toHaveBeenCalledWith(
        expect.objectContaining({ action: 'ticketing.configure' }),
      );
      expect(result.projectKey).toBe('SEC');
    });

    it('debe rechazar la configuración si el test de conexión falla', async () => {
      jiraConnector.testConnection.mockResolvedValue({
        ok: false,
        provider: TicketingProvider.JIRA,
        error: 'Credenciales inválidas',
      });

      await expect(
        service.configureIntegration(mockUser, {
          provider: TicketingProvider.JIRA,
          instanceUrl: 'https://myorg.atlassian.net',
          projectKey: 'SEC',
          credentials: { email: 'bad@org.com', apiToken: 'bad' },
        }),
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('createTicketForFinding', () => {
    it('debe crear un ticket en Jira y avanzar el hallazgo de OPEN a IN_PROGRESS', async () => {
      prisma.finding.findFirst.mockResolvedValue({
        id: 'finding-1',
        organizationId: 'org-abc',
        title: 'Certificado SSL Caducado',
        description: 'El certificado expiró hace 5 días.',
        recommendation: 'Renovar con Let\'s Encrypt.',
        severity: FindingSeverity.HIGH,
        status: FindingStatus.OPEN,
        location: 'example.com:443',
        ruleId: 'SSL-EXPIRED',
        ticketKey: null,
        asset: { value: 'example.com' },
      });

      prisma.ticketingIntegration.findUnique.mockResolvedValue({
        organizationId: 'org-abc',
        provider: TicketingProvider.JIRA,
        enabled: true,
        instanceUrl: 'https://myorg.atlassian.net',
        projectKey: 'SEC',
        issueType: 'Bug',
        credentialsEncrypted: 'enc:{"email":"admin@org.com","apiToken":"tok"}',
      });

      jiraConnector.createIssue.mockResolvedValue({
        key: 'SEC-200',
        url: 'https://myorg.atlassian.net/browse/SEC-200',
        status: 'Open',
      });

      const result = await service.createTicketForFinding(mockUser, 'finding-1');

      expect(result.key).toBe('SEC-200');
      expect(prisma.finding.update).toHaveBeenCalledWith({
        where: { id: 'finding-1' },
        data: expect.objectContaining({
          ticketKey: 'SEC-200',
          ticketUrl: 'https://myorg.atlassian.net/browse/SEC-200',
          ticketStatus: 'Open',
          status: FindingStatus.IN_PROGRESS,
        }),
      });
      expect(audit.record).toHaveBeenCalledWith(
        expect.objectContaining({ action: 'ticketing.create_ticket' }),
      );
    });

    it('debe arrojar error si el hallazgo ya tiene un ticket vinculado', async () => {
      prisma.finding.findFirst.mockResolvedValue({
        id: 'finding-1',
        organizationId: 'org-abc',
        ticketKey: 'SEC-100',
      });

      await expect(
        service.createTicketForFinding(mockUser, 'finding-1'),
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('syncFindingTicket', () => {
    it('debe actualizar el estado del ticket y avanzar el hallazgo a VERIFYING si el ticket remoto fue cerrado', async () => {
      prisma.finding.findFirst.mockResolvedValue({
        id: 'finding-1',
        organizationId: 'org-abc',
        ticketKey: 'SEC-200',
        ticketProvider: TicketingProvider.JIRA,
        status: FindingStatus.IN_PROGRESS,
      });

      prisma.ticketingIntegration.findUnique.mockResolvedValue({
        organizationId: 'org-abc',
        provider: TicketingProvider.JIRA,
        instanceUrl: 'https://myorg.atlassian.net',
        credentialsEncrypted: 'enc:{"email":"a@b.com","apiToken":"t"}',
      });

      jiraConnector.getIssueStatus.mockResolvedValue({
        status: 'Done',
        isClosed: true,
      });

      const result = await service.syncFindingTicket(mockUser, 'finding-1');

      expect(result.status).toBe('Done');
      expect(result.isClosed).toBe(true);
      expect(result.findingStatus).toBe(FindingStatus.VERIFYING);
      expect(prisma.finding.update).toHaveBeenCalledWith({
        where: { id: 'finding-1' },
        data: expect.objectContaining({
          ticketStatus: 'Done',
          status: FindingStatus.VERIFYING,
        }),
      });
      expect(audit.record).toHaveBeenCalledWith(
        expect.objectContaining({ action: 'ticketing.sync_ticket' }),
      );
    });
  });
});
