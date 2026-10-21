import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import {
  AssetCriticality,
  AssetType,
  CloudAccount,
  CloudAccountStatus,
  CloudAuthType,
  CloudProvider,
  VerificationMethod,
} from '@prisma/client';
import { CryptoVaultService } from '../common/crypto/crypto-vault.service';
import { PrismaService } from '../prisma/prisma.service';
import {
  AwsConnectorService,
  AwsVerificationResult,
} from './connectors/aws-connector.service';
import {
  AzureConnectorService,
  AzureVerificationResult,
} from './connectors/azure-connector.service';
import { CSPM_RULES, CspmRuleDefinition } from './cspm.catalog';
import {
  CreateCloudAccountDto,
  TestCloudConnectionDto,
  UpdateCloudAccountDto,
} from './dto/cloud-account.dto';

export interface StoredCloudCredentials {
  awsAccessKeyId?: string;
  awsSecretAccessKey?: string;
  awsSessionToken?: string;
  azureClientId?: string;
  azureClientSecret?: string;
}

export type SanitizedCloudAccount = Omit<CloudAccount, 'encryptedCredentials'> & {
  hasCredentialsStored: boolean;
};

@Injectable()
export class CloudAccountsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly cryptoVault: CryptoVaultService,
    private readonly awsConnector: AwsConnectorService,
    private readonly azureConnector: AzureConnectorService,
  ) {}

  /**
   * Genera un External ID único y determinístico por organización para proteger
   * la relación de confianza IAM AssumeRole contra el ataque Confused Deputy.
   */
  generateExternalId(organizationId: string): string {
    const clean = organizationId.replace(/[^a-zA-Z0-9]/g, '').slice(0, 16);
    return `sspm-org-${clean}`;
  }

  /**
   *Elimina el campo encryptedCredentials antes de exponer la cuenta por la API.
   */
  sanitizeAccount(account: CloudAccount): SanitizedCloudAccount {
    const { encryptedCredentials, ...rest } = account;
    return {
      ...rest,
      hasCredentialsStored: Boolean(encryptedCredentials),
    };
  }

  /**
   * Devuelve las plantillas de onboarding (CloudFormation, AWS CLI y Azure CLI)
   * preconfiguradas con el External ID de la organización.
   */
  getOnboardingTemplates(organizationId: string) {
    const externalId = this.generateExternalId(organizationId);

    const awsCloudFormationYaml = [
      'AWSTemplateFormatVersion: "2010-09-09"',
      'Description: "Rol de auditoria CSPM de solo lectura (Least Privilege) para SSPM Platform"',
      'Parameters:',
      '  ExternalId:',
      '    Type: String',
      `    Default: "${externalId}"`,
      'Resources:',
      '  SSPMCloudAuditorRole:',
      '    Type: "AWS::IAM::Role"',
      '    Properties:',
      '      RoleName: "SSPM-Cloud-Auditor-Role"',
      '      AssumeRolePolicyDocument:',
      '        Version: "2012-10-17"',
      '        Statement:',
      '          - Effect: Allow',
      '            Principal:',
      '              AWS: "*"',
      '            Action: "sts:AssumeRole"',
      '            Condition:',
      '              StringEquals:',
      '                "sts:ExternalId": !Ref ExternalId',
      '      ManagedPolicyArns:',
      '        - "arn:aws:iam::aws:policy/SecurityAudit"',
      'Outputs:',
      '  RoleArn:',
      '    Description: "Copie este Role ARN en la plataforma SSPM"',
      '    Value: !GetAtt SSPMCloudAuditorRole.Arn',
    ].join('\n');

    const awsCliSnippet = [
      '# 1. Crear usuario o rol de auditoría de solo lectura en AWS:',
      'aws iam create-user --user-name sspm-cloud-auditor',
      'aws iam attach-user-policy --user-name sspm-cloud-auditor --policy-arn arn:aws:iam::aws:policy/SecurityAudit',
      'aws iam create-access-key --user-name sspm-cloud-auditor',
    ].join('\n');

    const azureCliSnippet = [
      '# 1. Crear Service Principal con rol Reader en su suscripción de Azure:',
      'az ad sp create-for-rbac --name "SSPM-Cloud-Auditor" --role "Reader" --scopes "/subscriptions/<SUBSCRIPTION_ID>"',
      '# 2. (Opcional) Agregar rol Security Reader para telemetría de Defender for Cloud:',
      'az role assignment create --assignee "<APP_ID>" --role "Security Reader" --scope "/subscriptions/<SUBSCRIPTION_ID>"',
    ].join('\n');

    return {
      awsExternalId: externalId,
      awsCloudFormationYaml,
      awsCliSnippet,
      azureCliSnippet,
    };
  }

  /**
   * Lista el catálogo de reglas CSPM soportadas, con filtro opcional por proveedor.
   */
  listCspmRules(provider?: CloudProvider): readonly CspmRuleDefinition[] {
    if (!provider) return CSPM_RULES;
    return CSPM_RULES.filter((r) => r.provider === provider);
  }

  /**
   * Lista todas las cuentas cloud registradas por la organización.
   */
  async listAccounts(organizationId: string): Promise<SanitizedCloudAccount[]> {
    const accounts = await this.prisma.cloudAccount.findMany({
      where: { organizationId },
      orderBy: { createdAt: 'desc' },
    });
    return accounts.map((a) => this.sanitizeAccount(a));
  }

  /**
   * Obtiene el detalle de una cuenta cloud específica.
   */
  async getAccountById(organizationId: string, accountId: string): Promise<SanitizedCloudAccount> {
    const account = await this.prisma.cloudAccount.findFirst({
      where: { id: accountId, organizationId },
    });
    if (!account) {
      throw new NotFoundException(`Cuenta cloud no encontrada: ${accountId}`);
    }
    return this.sanitizeAccount(account);
  }

  /**
   * Prueba la conexión contra AWS o Azure sin persistir cambios en la base de datos.
   */
  async testConnection(
    organizationId: string,
    dto: TestCloudConnectionDto,
  ): Promise<AwsVerificationResult | AzureVerificationResult> {
    if (dto.provider === CloudProvider.AWS) {
      return this.awsConnector.verifyConnection({
        authType: dto.authType,
        accountId: dto.accountOrSubscriptionId.trim(),
        roleArn: dto.awsRoleArn,
        externalId: dto.awsExternalId || this.generateExternalId(organizationId),
        accessKeyId: dto.awsAccessKeyId,
        secretAccessKey: dto.awsSecretAccessKey,
        sessionToken: dto.awsSessionToken,
      });
    }

    if (dto.provider === CloudProvider.AZURE) {
      if (!dto.azureTenantId || !dto.azureClientId || !dto.azureClientSecret) {
        throw new BadRequestException(
          'Para probar la conexión con Azure se requieren Tenant ID, Client ID y Client Secret.',
        );
      }
      return this.azureConnector.verifyConnection({
        subscriptionId: dto.accountOrSubscriptionId.trim(),
        tenantId: dto.azureTenantId,
        clientId: dto.azureClientId,
        clientSecret: dto.azureClientSecret,
      });
    }

    throw new BadRequestException(`Proveedor de nube no soportado: ${dto.provider}`);
  }

  /**
   * Registra una nueva cuenta de AWS o suscripción de Azure, cifra sus credenciales
   * con AES-256-GCM, vincula un activo en el inventario y verifica la conectividad.
   */
  async createAccount(
    organizationId: string,
    userId: string,
    dto: CreateCloudAccountDto,
  ): Promise<{
    account: SanitizedCloudAccount;
    verification: AwsVerificationResult | AzureVerificationResult | null;
  }> {
    this.validateCreateDto(dto);

    const normalizedAccountId = dto.accountOrSubscriptionId.trim();

    const existing = await this.prisma.cloudAccount.findUnique({
      where: {
        organizationId_provider_accountOrSubscriptionId: {
          organizationId,
          provider: dto.provider,
          accountOrSubscriptionId: normalizedAccountId,
        },
      },
    });

    if (existing) {
      throw new ConflictException(
        `La cuenta o suscripción ${normalizedAccountId} (${dto.provider}) ya está registrada en su organización.`,
      );
    }

    const externalId =
      dto.provider === CloudProvider.AWS
        ? dto.awsExternalId?.trim() || this.generateExternalId(organizationId)
        : null;

    const credsToStore: StoredCloudCredentials = {
      awsAccessKeyId: dto.awsAccessKeyId?.trim() || undefined,
      awsSecretAccessKey: dto.awsSecretAccessKey?.trim() || undefined,
      awsSessionToken: dto.awsSessionToken?.trim() || undefined,
      azureClientId: dto.azureClientId?.trim() || undefined,
      azureClientSecret: dto.azureClientSecret?.trim() || undefined,
    };

    const hasAnySecret = Object.values(credsToStore).some(Boolean);
    const encryptedCredentials = hasAnySecret
      ? this.cryptoVault.encryptJson(credsToStore)
      : null;

    let status: CloudAccountStatus = CloudAccountStatus.PENDING;
    let lastAuditError: string | null = null;
    let verification: AwsVerificationResult | AzureVerificationResult | null = null;

    if (dto.verifyOnCreate !== false) {
      verification = await this.testConnection(organizationId, {
        provider: dto.provider,
        authType: dto.authType,
        accountOrSubscriptionId: normalizedAccountId,
        azureTenantId: dto.azureTenantId,
        azureClientId: dto.azureClientId,
        azureClientSecret: dto.azureClientSecret,
        awsRoleArn: dto.awsRoleArn,
        awsExternalId: externalId ?? undefined,
        awsAccessKeyId: dto.awsAccessKeyId,
        awsSecretAccessKey: dto.awsSecretAccessKey,
        awsSessionToken: dto.awsSessionToken,
      });

      if (verification.valid) {
        status = CloudAccountStatus.CONNECTED;
      } else {
        status = CloudAccountStatus.ERROR;
        lastAuditError = verification.error ?? 'Error al verificar conectividad con el proveedor cloud.';
      }
    }

    const assetValue = `${dto.provider.toLowerCase()}:${normalizedAccountId}`;
    const defaultRegions =
      dto.monitoredRegions && dto.monitoredRegions.length > 0
        ? dto.monitoredRegions
        : dto.provider === CloudProvider.AWS
          ? ['us-east-1', 'us-west-2']
          : ['eastus', 'westus2'];

    // Crear o reutilizar el activo padre en la tabla assets
    const asset = await this.prisma.asset.upsert({
      where: {
        organizationId_value: {
          organizationId,
          value: assetValue,
        },
      },
      update: {
        name: dto.name.trim(),
        isActive: true,
        verifiedAt: status === CloudAccountStatus.CONNECTED ? new Date() : undefined,
      },
      create: {
        organizationId,
        type: AssetType.CLOUD_ACCOUNT,
        value: assetValue,
        name: dto.name.trim(),
        description: `Cuenta Cloud ${dto.provider} (${normalizedAccountId}) conectada para evaluación CSPM`,
        criticality: AssetCriticality.HIGH,
        tags: ['cloud', dto.provider.toLowerCase(), 'cspm'],
        authorizationConfirmed: true,
        authorizedAt: new Date(),
        createdById: userId,
        verifiedAt: status === CloudAccountStatus.CONNECTED ? new Date() : null,
        verificationMethod: VerificationMethod.PRE_AUTHORIZED,
      },
    });

    const created = await this.prisma.cloudAccount.create({
      data: {
        organizationId,
        provider: dto.provider,
        name: dto.name.trim(),
        authType: dto.authType,
        status,
        accountOrSubscriptionId: normalizedAccountId,
        azureTenantId: dto.azureTenantId?.trim() || null,
        awsRoleArn: dto.awsRoleArn?.trim() || null,
        awsExternalId: externalId,
        encryptedCredentials,
        monitoredRegions: defaultRegions,
        assetId: asset.id,
        lastAuditError,
      },
    });

    return {
      account: this.sanitizeAccount(created),
      verification,
    };
  }

  /**
   * Re-verifica la conexión de una cuenta cloud existente descifrando sus credenciales.
   */
  async verifyExistingAccount(
    organizationId: string,
    accountId: string,
  ): Promise<{
    account: SanitizedCloudAccount;
    verification: AwsVerificationResult | AzureVerificationResult;
  }> {
    const { account, credentials } = await this.getDecryptedCredentials(organizationId, accountId);

    const verification = await this.testConnection(organizationId, {
      provider: account.provider,
      authType: account.authType,
      accountOrSubscriptionId: account.accountOrSubscriptionId,
      azureTenantId: account.azureTenantId ?? undefined,
      azureClientId: credentials.azureClientId,
      azureClientSecret: credentials.azureClientSecret,
      awsRoleArn: account.awsRoleArn ?? undefined,
      awsExternalId: account.awsExternalId ?? undefined,
      awsAccessKeyId: credentials.awsAccessKeyId,
      awsSecretAccessKey: credentials.awsSecretAccessKey,
      awsSessionToken: credentials.awsSessionToken,
    });

    const newStatus = verification.valid ? CloudAccountStatus.CONNECTED : CloudAccountStatus.ERROR;
    const newError = verification.valid ? null : (verification.error ?? 'Fallo de verificación');

    const updated = await this.prisma.cloudAccount.update({
      where: { id: account.id },
      data: {
        status: newStatus,
        lastAuditError: newError,
      },
    });

    if (verification.valid && account.assetId) {
      await this.prisma.asset.update({
        where: { id: account.assetId },
        data: {
          verifiedAt: new Date(),
          verificationMethod: VerificationMethod.PRE_AUTHORIZED,
        },
      }).catch(() => undefined);
    }

    return {
      account: this.sanitizeAccount(updated),
      verification,
    };
  }

  /**
   * Actualiza parámetros o rota credenciales de una cuenta cloud existente.
   */
  async updateAccount(
    organizationId: string,
    accountId: string,
    dto: UpdateCloudAccountDto,
  ): Promise<SanitizedCloudAccount> {
    const { account, credentials } = await this.getDecryptedCredentials(organizationId, accountId);

    const mergedCreds: StoredCloudCredentials = {
      awsAccessKeyId: dto.awsAccessKeyId !== undefined ? dto.awsAccessKeyId.trim() : credentials.awsAccessKeyId,
      awsSecretAccessKey: dto.awsSecretAccessKey !== undefined ? dto.awsSecretAccessKey.trim() : credentials.awsSecretAccessKey,
      awsSessionToken: dto.awsSessionToken !== undefined ? dto.awsSessionToken.trim() : credentials.awsSessionToken,
      azureClientId: dto.azureClientId !== undefined ? dto.azureClientId.trim() : credentials.azureClientId,
      azureClientSecret: dto.azureClientSecret !== undefined ? dto.azureClientSecret.trim() : credentials.azureClientSecret,
    };

    const hasAnySecret = Object.values(mergedCreds).some(Boolean);
    const encryptedCredentials = hasAnySecret ? this.cryptoVault.encryptJson(mergedCreds) : null;

    const updated = await this.prisma.cloudAccount.update({
      where: { id: account.id },
      data: {
        name: dto.name !== undefined ? dto.name.trim() : undefined,
        awsRoleArn: dto.awsRoleArn !== undefined ? dto.awsRoleArn.trim() : undefined,
        monitoredRegions: dto.monitoredRegions !== undefined ? dto.monitoredRegions : undefined,
        encryptedCredentials,
      },
    });

    if (dto.name && account.assetId) {
      await this.prisma.asset.update({
        where: { id: account.assetId },
        data: { name: dto.name.trim() },
      }).catch(() => undefined);
    }

    return this.sanitizeAccount(updated);
  }

  /**
   * Elimina una cuenta cloud y desactiva o elimina su activo padre asociado.
   */
  async deleteAccount(organizationId: string, accountId: string): Promise<{ deleted: true }> {
    const account = await this.prisma.cloudAccount.findFirst({
      where: { id: accountId, organizationId },
    });
    if (!account) {
      throw new NotFoundException(`Cuenta cloud no encontrada: ${accountId}`);
    }

    await this.prisma.cloudAccount.delete({
      where: { id: account.id },
    });

    if (account.assetId) {
      await this.prisma.asset.delete({
        where: { id: account.assetId },
      }).catch(() => undefined);
    }

    return { deleted: true };
  }

  /**
   * Método interno para recuperar la cuenta y descifrar sus credenciales en memoria
   * durante la verificación o escaneo de postura CSPM.
   */
  async getDecryptedCredentials(
    organizationId: string,
    accountId: string,
  ): Promise<{ account: CloudAccount; credentials: StoredCloudCredentials }> {
    const account = await this.prisma.cloudAccount.findFirst({
      where: { id: accountId, organizationId },
    });
    if (!account) {
      throw new NotFoundException(`Cuenta cloud no encontrada: ${accountId}`);
    }

    let credentials: StoredCloudCredentials = {};
    if (account.encryptedCredentials) {
      credentials = this.cryptoVault.decryptJson<StoredCloudCredentials>(
        account.encryptedCredentials,
      );
    }

    return { account, credentials };
  }

  private validateCreateDto(dto: CreateCloudAccountDto): void {
    if (dto.provider === CloudProvider.AWS) {
      if (dto.authType !== CloudAuthType.ROLE_ARN && dto.authType !== CloudAuthType.ACCESS_KEYS) {
        throw new BadRequestException(
          'Para cuentas AWS el tipo de autenticación debe ser ROLE_ARN o ACCESS_KEYS.',
        );
      }
      if (dto.authType === CloudAuthType.ROLE_ARN && !dto.awsRoleArn?.trim()) {
        throw new BadRequestException(
          'Debe proporcionar el ARN del rol IAM (awsRoleArn) para el modo ROLE_ARN.',
        );
      }
      if (
        dto.authType === CloudAuthType.ACCESS_KEYS &&
        (!dto.awsAccessKeyId?.trim() || !dto.awsSecretAccessKey?.trim())
      ) {
        throw new BadRequestException(
          'Debe proporcionar Access Key ID y Secret Access Key para el modo ACCESS_KEYS.',
        );
      }
    } else if (dto.provider === CloudProvider.AZURE) {
      if (dto.authType !== CloudAuthType.SERVICE_PRINCIPAL) {
        throw new BadRequestException(
          'Para suscripciones Azure el tipo de autenticación debe ser SERVICE_PRINCIPAL.',
        );
      }
      if (!dto.azureTenantId?.trim() || !dto.azureClientId?.trim() || !dto.azureClientSecret?.trim()) {
        throw new BadRequestException(
          'Para conectar una suscripción de Azure se requieren Tenant ID, Client ID y Client Secret.',
        );
      }
    }
  }
}
