import { BadRequestException, ConflictException, NotFoundException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { CloudAccountStatus, CloudAuthType, CloudProvider } from '@prisma/client';
import { CryptoVaultService } from '../common/crypto/crypto-vault.service';
import { CloudAccountsService } from './cloud-accounts.service';

describe('CloudAccountsService', () => {
  let service: CloudAccountsService;
  let prismaMock: any;
  let cryptoVault: CryptoVaultService;
  let awsConnectorMock: { verifyConnection: jest.Mock };
  let azureConnectorMock: { verifyConnection: jest.Mock };

  beforeEach(() => {
    prismaMock = {
      cloudAccount: {
        findMany: jest.fn(),
        findFirst: jest.fn(),
        findUnique: jest.fn(),
        create: jest.fn(),
        update: jest.fn(),
        delete: jest.fn(),
      },
      asset: {
        upsert: jest.fn(),
        update: jest.fn(),
        delete: jest.fn(),
      },
    };

    const configMock = {
      get: jest.fn((k: string) => (k === 'CLOUD_CREDENTIALS_ENCRYPTION_KEY' ? 'test-master-key-32-chars-minimum!' : null)),
    } as unknown as ConfigService;

    cryptoVault = new CryptoVaultService(configMock);
    awsConnectorMock = { verifyConnection: jest.fn() };
    azureConnectorMock = { verifyConnection: jest.fn() };

    service = new CloudAccountsService(
      prismaMock,
      cryptoVault,
      awsConnectorMock as any,
      azureConnectorMock as any,
    );
  });

  describe('getOnboardingTemplates', () => {
    it('genera un External ID determinístico por organización y plantillas CloudFormation/CLI', () => {
      const tpl = service.getOnboardingTemplates('a647713e-5371-43c1-832b-076da5903add');

      expect(tpl.awsExternalId).toBe('sspm-org-a647713e537143c1');
      expect(tpl.awsCloudFormationYaml).toContain('SSPMCloudAuditorRole');
      expect(tpl.awsCloudFormationYaml).toContain('arn:aws:iam::aws:policy/SecurityAudit');
      expect(tpl.azureCliSnippet).toContain('az ad sp create-for-rbac');
    });
  });

  describe('createAccount', () => {
    it('registra una cuenta AWS, cifra las credenciales con AES-256-GCM, crea el activo padre y nunca expone encryptedCredentials', async () => {
      prismaMock.cloudAccount.findUnique.mockResolvedValueOnce(null);
      awsConnectorMock.verifyConnection.mockResolvedValueOnce({
        valid: true,
        accountId: '123456789012',
        arn: 'arn:aws:iam::123456789012:role/SSPM-Role',
        latencyMs: 120,
      });
      prismaMock.asset.upsert.mockResolvedValueOnce({
        id: 'asset-cloud-1',
        value: 'aws:123456789012',
      });

      prismaMock.cloudAccount.create.mockImplementationOnce(async ({ data }: any) => ({
        id: 'ca-1',
        ...data,
        resourceCount: 0,
        failingFindingCount: 0,
        createdAt: new Date(),
        updatedAt: new Date(),
      }));

      const res = await service.createAccount('org-1', 'user-1', {
        provider: CloudProvider.AWS,
        name: 'AWS Producción',
        authType: CloudAuthType.ACCESS_KEYS,
        accountOrSubscriptionId: '123456789012',
        awsAccessKeyId: 'AKIAEXAMPLE123',
        awsSecretAccessKey: 'super-secret-aws-key',
      });

      expect(res.account.status).toBe(CloudAccountStatus.CONNECTED);
      expect(res.account.hasCredentialsStored).toBe(true);
      expect((res.account as any).encryptedCredentials).toBeUndefined();
      expect(res.verification?.valid).toBe(true);
      expect(prismaMock.asset.upsert).toHaveBeenCalledTimes(1);
    });

    it('lanza ConflictException si la cuenta ya está registrada en la organización', async () => {
      prismaMock.cloudAccount.findUnique.mockResolvedValueOnce({ id: 'existing-id' });

      await expect(
        service.createAccount('org-1', 'user-1', {
          provider: CloudProvider.AWS,
          name: 'AWS Duplicada',
          authType: CloudAuthType.ROLE_ARN,
          accountOrSubscriptionId: '123456789012',
          awsRoleArn: 'arn:aws:iam::123456789012:role/Role',
        }),
      ).rejects.toThrow(ConflictException);
    });

    it('valida campos obligatorios según el proveedor y tipo de autenticación', async () => {
      await expect(
        service.createAccount('org-1', 'user-1', {
          provider: CloudProvider.AZURE,
          name: 'Azure Incompleto',
          authType: CloudAuthType.SERVICE_PRINCIPAL,
          accountOrSubscriptionId: 'sub-123',
          // faltan azureTenantId, azureClientId, azureClientSecret
        }),
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('verifyExistingAccount', () => {
    it('descifra las credenciales almacenadas y actualiza el estado a CONNECTED tras verificar en Azure', async () => {
      const encrypted = cryptoVault.encryptJson({
        azureClientId: 'client-id-1',
        azureClientSecret: 'secret-value-1',
      });

      prismaMock.cloudAccount.findFirst.mockResolvedValueOnce({
        id: 'ca-azure-1',
        organizationId: 'org-1',
        provider: CloudProvider.AZURE,
        name: 'Azure Corp',
        authType: CloudAuthType.SERVICE_PRINCIPAL,
        status: CloudAccountStatus.ERROR,
        accountOrSubscriptionId: 'sub-uuid-123',
        azureTenantId: 'tenant-uuid-456',
        encryptedCredentials: encrypted,
        assetId: 'asset-az-1',
      });

      azureConnectorMock.verifyConnection.mockResolvedValueOnce({
        valid: true,
        subscriptionId: 'sub-uuid-123',
        displayName: 'Azure Corp',
        state: 'Enabled',
        latencyMs: 95,
      });

      prismaMock.cloudAccount.update.mockImplementationOnce(async ({ data }: any) => ({
        id: 'ca-azure-1',
        organizationId: 'org-1',
        provider: CloudProvider.AZURE,
        name: 'Azure Corp',
        authType: CloudAuthType.SERVICE_PRINCIPAL,
        status: data.status,
        lastAuditError: data.lastAuditError,
        accountOrSubscriptionId: 'sub-uuid-123',
        encryptedCredentials: encrypted,
      }));
      prismaMock.asset.update.mockResolvedValueOnce({});

      const res = await service.verifyExistingAccount('org-1', 'ca-azure-1');

      expect(azureConnectorMock.verifyConnection).toHaveBeenCalledWith({
        subscriptionId: 'sub-uuid-123',
        tenantId: 'tenant-uuid-456',
        clientId: 'client-id-1',
        clientSecret: 'secret-value-1',
      });
      expect(res.account.status).toBe(CloudAccountStatus.CONNECTED);
      expect(res.account.lastAuditError).toBeNull();
    });

    it('lanza NotFoundException si la cuenta no pertenece a la organización', async () => {
      prismaMock.cloudAccount.findFirst.mockResolvedValueOnce(null);

      await expect(service.verifyExistingAccount('org-1', 'non-existent')).rejects.toThrow(
        NotFoundException,
      );
    });
  });
});
