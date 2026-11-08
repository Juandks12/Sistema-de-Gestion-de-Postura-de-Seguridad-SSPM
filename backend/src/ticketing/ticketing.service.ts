import {
  BadRequestException,
  ConflictException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { FindingSeverity, FindingStatus, TicketingAutoCreateThreshold, TicketingProvider } from '@prisma/client';
import { AuditService } from '../audit/audit.service';
import { CryptoVaultService } from '../common/crypto/crypto-vault.service';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { resolveComplianceControls, resolveSecurityTaxonomy } from '../findings/grc-taxonomy.catalog';
import { PrismaService } from '../prisma/prisma.service';
import { AzureBoardsConnectorService } from './azure-boards-connector.service';
import { BulkTicketFindingsDto } from './dto/bulk-ticket-findings.dto';
import { ConfigureTicketingDto } from './dto/configure-ticketing.dto';
import { CreateFindingTicketDto } from './dto/create-finding-ticket.dto';
import { TestTicketingDto } from './dto/test-ticketing.dto';
import { JiraConnectorService } from './jira-connector.service';
import {
  AzureBoardsCredentials,
  CreatedTicketResult,
  JiraCredentials,
  TestConnectionResult,
  TicketingConfigSummary,
  TicketingFindingPayload,
  TicketStatusResult,
} from './ticketing.types';

@Injectable()
export class TicketingService {
  private readonly logger = new Logger(TicketingService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly cryptoVault: CryptoVaultService,
    private readonly jiraConnector: JiraConnectorService,
    private readonly azureBoardsConnector: AzureBoardsConnectorService,
    private readonly audit: AuditService,
  ) {}

  /**
   * Obtiene la configuración activa de ticketing de la organización (sin exponer secretos).
   */
  async getConfig(organizationId: string): Promise<TicketingConfigSummary> {
    const integration = await this.prisma.ticketingIntegration.findUnique({
      where: { organizationId },
    });

    if (!integration) {
      return { configured: false };
    }

    return {
      configured: true,
      provider: integration.provider,
      enabled: integration.enabled,
      instanceUrl: integration.instanceUrl,
      projectKey: integration.projectKey,
      issueType: integration.issueType,
      autoCreateThreshold: integration.autoCreateThreshold,
      lastTestedAt: integration.lastTestedAt,
      lastTestStatus: integration.lastTestStatus,
      lastTestError: integration.lastTestError,
      maskedCredentials: '••••••••••••••••',
    };
  }

  /**
   * Prueba conectividad y permisos con Jira o Azure Boards.
   */
  async testIntegration(
    organizationId: string,
    dto: TestTicketingDto,
  ): Promise<TestConnectionResult> {
    let credentials = dto.credentials;

    // Si no se pasaron credenciales en claro en el DTO, intentar descifrar las guardadas
    if (!credentials || Object.keys(credentials).length === 0) {
      const stored = await this.prisma.ticketingIntegration.findUnique({ where: { organizationId } });
      if (!stored) {
        throw new BadRequestException('No hay credenciales registradas para probar. Proporcione las credenciales en la petición.');
      }
      try {
        const decrypted = this.cryptoVault.decrypt(stored.credentialsEncrypted);
        credentials = JSON.parse(decrypted);
      } catch (err) {
        throw new BadRequestException(`No se pudieron descifrar las credenciales almacenadas: ${(err as Error).message}`);
      }
    }

    if (!credentials) {
      throw new BadRequestException('No se especificaron credenciales para la prueba.');
    }

    let result: TestConnectionResult;

    if (dto.provider === TicketingProvider.JIRA) {
      const jiraCreds: JiraCredentials = {
        email: credentials.email ?? '',
        apiToken: credentials.apiToken ?? '',
      };
      if (!jiraCreds.email || !jiraCreds.apiToken) {
        throw new BadRequestException('Las credenciales de Jira deben incluir email y apiToken.');
      }
      result = await this.jiraConnector.testConnection(dto.instanceUrl, dto.projectKey, jiraCreds);
    } else {
      const azureCreds: AzureBoardsCredentials = {
        personalAccessToken: credentials.personalAccessToken ?? credentials.pat ?? '',
      };
      if (!azureCreds.personalAccessToken) {
        throw new BadRequestException('Las credenciales de Azure Boards deben incluir personalAccessToken.');
      }
      result = await this.azureBoardsConnector.testConnection(dto.instanceUrl, dto.projectKey, azureCreds);
    }

    // Actualizar auditoría del último test si existe integración guardada
    await this.prisma.ticketingIntegration.updateMany({
      where: { organizationId },
      data: {
        lastTestedAt: new Date(),
        lastTestStatus: result.ok ? 'SUCCESS' : 'FAILED',
        lastTestError: result.error ? result.error.slice(0, 500) : null,
      },
    });

    return result;
  }

  /**
   * Guarda o actualiza la configuración de integración cifrando las credenciales con AES-256-GCM.
   */
  async configureIntegration(
    actor: AuthUser,
    dto: ConfigureTicketingDto,
  ): Promise<TicketingConfigSummary> {
    const organizationId = actor.organizationId;
    // 1. Probar conectividad antes de persistir
    const test = await this.testIntegration(organizationId, {
      provider: dto.provider,
      instanceUrl: dto.instanceUrl,
      projectKey: dto.projectKey,
      credentials: dto.credentials,
    });

    if (!test.ok) {
      throw new BadRequestException(`No se pudo verificar la integración: ${test.error}`);
    }

    // 2. Cifrar credenciales
    const encryptedPayload = this.cryptoVault.encrypt(JSON.stringify(dto.credentials));

    // 3. Persistir en base de datos
    const saved = await this.prisma.ticketingIntegration.upsert({
      where: { organizationId },
      create: {
        organizationId,
        provider: dto.provider,
        enabled: dto.enabled ?? true,
        instanceUrl: dto.instanceUrl.trim().replace(/\/+$/, ''),
        projectKey: dto.projectKey.trim(),
        issueType: dto.issueType?.trim() || (dto.provider === TicketingProvider.JIRA ? 'Bug' : 'Issue'),
        autoCreateThreshold: dto.autoCreateThreshold ?? TicketingAutoCreateThreshold.DISABLED,
        credentialsEncrypted: encryptedPayload,
        config: dto.config ? JSON.parse(JSON.stringify(dto.config)) : undefined,
        lastTestedAt: new Date(),
        lastTestStatus: 'SUCCESS',
        lastTestError: null,
      },
      update: {
        provider: dto.provider,
        enabled: dto.enabled ?? true,
        instanceUrl: dto.instanceUrl.trim().replace(/\/+$/, ''),
        projectKey: dto.projectKey.trim(),
        issueType: dto.issueType?.trim() || (dto.provider === TicketingProvider.JIRA ? 'Bug' : 'Issue'),
        autoCreateThreshold: dto.autoCreateThreshold ?? TicketingAutoCreateThreshold.DISABLED,
        credentialsEncrypted: encryptedPayload,
        config: dto.config ? JSON.parse(JSON.stringify(dto.config)) : undefined,
        lastTestedAt: new Date(),
        lastTestStatus: 'SUCCESS',
        lastTestError: null,
      },
    });

    this.audit.record({
      organizationId,
      action: 'ticketing.configure',
      actor: { id: actor.id, email: actor.email, fullName: actor.fullName },
      target: { type: 'ticketing_integration', id: saved.id, label: dto.provider },
      detail: {
        provider: dto.provider,
        instanceUrl: dto.instanceUrl,
        projectKey: dto.projectKey,
        autoCreateThreshold: dto.autoCreateThreshold,
      },
    });

    const summary = await this.getConfig(organizationId);
    if (!summary) {
      throw new BadRequestException('Error al recuperar configuración guardada.');
    }
    return summary;
  }

  /**
   * Elimina la integración de ticketing de la organización.
   */
  async deleteIntegration(actor: AuthUser): Promise<{ ok: boolean }> {
    await this.prisma.ticketingIntegration.deleteMany({
      where: { organizationId: actor.organizationId },
    });

    this.audit.record({
      organizationId: actor.organizationId,
      action: 'ticketing.delete',
      actor: { id: actor.id, email: actor.email, fullName: actor.fullName },
      target: { type: 'ticketing_integration' },
    });

    return { ok: true };
  }

  /**
   * Crea un ticket en Jira o Azure Boards para un hallazgo específico.
   */
  async createTicketForFinding(
    actor: AuthUser,
    findingId: string,
    dto?: CreateFindingTicketDto,
  ): Promise<CreatedTicketResult> {
    const finding = await this.prisma.finding.findFirst({
      where: { id: findingId, organizationId: actor.organizationId },
      include: { asset: true },
    });

    if (!finding) {
      throw new NotFoundException('Hallazgo no encontrado en su organización.');
    }

    if (finding.ticketKey && finding.ticketUrl) {
      throw new ConflictException(
        `Este hallazgo ya tiene un ticket vinculado en ${finding.ticketProvider} (${finding.ticketKey}).`,
      );
    }

    const integration = await this.prisma.ticketingIntegration.findUnique({
      where: { organizationId: actor.organizationId },
    });

    if (!integration || !integration.enabled) {
      throw new BadRequestException('No hay ninguna integración de ticketing activa configurada en su organización.');
    }

    const rawCredentials = JSON.parse(this.cryptoVault.decrypt(integration.credentialsEncrypted));
    const issueType = dto?.issueType || integration.issueType;

    // Resolver taxonomía (CWE, OWASP, MITRE) y controles GRC del hallazgo
    const taxonomy = resolveSecurityTaxonomy(finding.ruleId, finding.category, finding.evidence);
    const complianceControls = resolveComplianceControls(finding.ruleId, finding.evidence);

    const payload: TicketingFindingPayload = {
      findingId: finding.id,
      title: finding.title,
      description: finding.description,
      severity: finding.severity,
      cvssScore: finding.cvssScore ? Number(finding.cvssScore) : null,
      location: finding.location,
      ruleId: finding.ruleId,
      category: finding.category,
      cweId: taxonomy.cweId,
      owaspCategory: taxonomy.owaspCategory,
      mitreAttackTechnique: taxonomy.mitreAttackTechnique,
      complianceControls,
      recommendation: finding.recommendation,
      evidence: finding.evidence,
      assetValue: finding.asset.value,
      dueDate: finding.dueDate,
      customNotes: dto?.notes,
    };

    let result: CreatedTicketResult;

    if (integration.provider === TicketingProvider.JIRA) {
      result = await this.jiraConnector.createIssue(
        integration.instanceUrl,
        integration.projectKey,
        issueType,
        rawCredentials as JiraCredentials,
        payload,
      );
    } else {
      result = await this.azureBoardsConnector.createWorkItem(
        integration.instanceUrl,
        integration.projectKey,
        issueType,
        rawCredentials as AzureBoardsCredentials,
        payload,
      );
    }

    // Actualizar el hallazgo: vincular ticket y mover estado a IN_PROGRESS si estaba OPEN
    await this.prisma.finding.update({
      where: { id: finding.id },
      data: {
        ticketProvider: integration.provider,
        ticketKey: result.key,
        ticketUrl: result.url,
        ticketStatus: result.status,
        ticketSyncedAt: new Date(),
        status: finding.status === FindingStatus.OPEN ? FindingStatus.IN_PROGRESS : finding.status,
      },
    });

    this.audit.record({
      organizationId: actor.organizationId,
      action: 'ticketing.create_ticket',
      actor: { id: actor.id, email: actor.email, fullName: actor.fullName },
      target: { type: 'finding', id: finding.id, label: finding.ruleId },
      detail: {
        provider: integration.provider,
        ticketKey: result.key,
        ticketUrl: result.url,
        ruleId: finding.ruleId,
      },
    });

    return result;
  }

  /**
   * Crea tickets de remediación masivamente para varios hallazgos seleccionados.
   */
  async createTicketsBulk(
    actor: AuthUser,
    dto: BulkTicketFindingsDto,
  ): Promise<{
    total: number;
    created: number;
    failed: number;
    results: Array<{ findingId: string; ticketKey: string; ticketUrl: string }>;
    errors: Array<{ findingId: string; reason: string }>;
  }> {
    const results: Array<{ findingId: string; ticketKey: string; ticketUrl: string }> = [];
    const errors: Array<{ findingId: string; reason: string }> = [];

    for (const findingId of dto.findingIds) {
      try {
        const ticket = await this.createTicketForFinding(actor, findingId, { notes: dto.notes });
        results.push({ findingId, ticketKey: ticket.key, ticketUrl: ticket.url });
      } catch (err) {
        errors.push({ findingId, reason: (err as Error).message });
      }
    }

    this.audit.record({
      organizationId: actor.organizationId,
      action: 'ticketing.bulk_ticket',
      actor: { id: actor.id, email: actor.email, fullName: actor.fullName },
      target: { type: 'finding' },
      detail: {
        requestedCount: dto.findingIds.length,
        createdCount: results.length,
        failedCount: errors.length,
      },
    });

    return {
      total: dto.findingIds.length,
      created: results.length,
      failed: errors.length,
      results,
      errors,
    };
  }

  /**
   * Consulta el estado actual del ticket en Jira / Azure Boards y actualiza el hallazgo.
   */
  async syncFindingTicket(actor: AuthUser, findingId: string): Promise<TicketStatusResult & { findingStatus: FindingStatus }> {
    const finding = await this.prisma.finding.findFirst({
      where: { id: findingId, organizationId: actor.organizationId },
    });

    if (!finding) {
      throw new NotFoundException('Hallazgo no encontrado.');
    }

    if (!finding.ticketKey || !finding.ticketProvider) {
      throw new BadRequestException('El hallazgo no tiene ningún ticket vinculado.');
    }

    const integration = await this.prisma.ticketingIntegration.findUnique({
      where: { organizationId: actor.organizationId },
    });

    if (!integration) {
      throw new BadRequestException('No hay integración de ticketing configurada.');
    }

    const rawCredentials = JSON.parse(this.cryptoVault.decrypt(integration.credentialsEncrypted));
    let statusResult: TicketStatusResult;

    if (finding.ticketProvider === TicketingProvider.JIRA) {
      statusResult = await this.jiraConnector.getIssueStatus(
        integration.instanceUrl,
        rawCredentials as JiraCredentials,
        finding.ticketKey,
      );
    } else {
      statusResult = await this.azureBoardsConnector.getWorkItemStatus(
        integration.instanceUrl,
        rawCredentials as AzureBoardsCredentials,
        finding.ticketKey,
      );
    }

    // Si en Jira/Azure el ticket fue completado o cerrado y el hallazgo está en OPEN o IN_PROGRESS,
    // se avanza a VERIFYING para que el próximo escaneo confirme la resolución técnica.
    let newFindingStatus = finding.status;
    if (statusResult.isClosed && (finding.status === FindingStatus.OPEN || finding.status === FindingStatus.IN_PROGRESS)) {
      newFindingStatus = FindingStatus.VERIFYING;
    }

    await this.prisma.finding.update({
      where: { id: finding.id },
      data: {
        ticketStatus: statusResult.status,
        ticketSyncedAt: new Date(),
        status: newFindingStatus,
      },
    });

    this.audit.record({
      organizationId: actor.organizationId,
      action: 'ticketing.sync_ticket',
      actor: { id: actor.id, email: actor.email, fullName: actor.fullName },
      target: { type: 'finding', id: finding.id, label: finding.ruleId },
      detail: {
        ticketKey: finding.ticketKey,
        previousStatus: finding.ticketStatus,
        newStatus: statusResult.status,
        findingStatus: newFindingStatus,
      },
    });

    return { ...statusResult, findingStatus: newFindingStatus };
  }

  /**
   * Hook de auto-creación tras un escaneo completado: evalúa hallazgos nuevos contra el umbral configurado.
   */
  async autoCreateTicketsForScan(organizationId: string, findingIds: string[]): Promise<void> {
    const integration = await this.prisma.ticketingIntegration.findUnique({
      where: { organizationId },
    });

    if (!integration || !integration.enabled || integration.autoCreateThreshold === TicketingAutoCreateThreshold.DISABLED) {
      return;
    }

    const threshold = integration.autoCreateThreshold;
    const severityEligible = (s: FindingSeverity): boolean => {
      if (threshold === TicketingAutoCreateThreshold.CRITICAL) return s === FindingSeverity.CRITICAL;
      if (threshold === TicketingAutoCreateThreshold.HIGH) return s === FindingSeverity.CRITICAL || s === FindingSeverity.HIGH;
      if (threshold === TicketingAutoCreateThreshold.MEDIUM) {
        return s === FindingSeverity.CRITICAL || s === FindingSeverity.HIGH || s === FindingSeverity.MEDIUM;
      }
      return false;
    };

    const findings = await this.prisma.finding.findMany({
      where: {
        id: { in: findingIds },
        organizationId,
        ticketKey: null,
      },
    });

    const eligible = findings.filter((f) => severityEligible(f.severity));
    if (eligible.length === 0) return;

    const systemUser: AuthUser = {
      id: '00000000-0000-0000-0000-000000000000',
      email: 'system@sspm.local',
      fullName: 'Sistema SSPM Automático',
      role: 'ADMIN',
      organizationId,
    };

    for (const f of eligible.slice(0, 10)) {
      try {
        await this.createTicketForFinding(systemUser, f.id, {
          notes: `[Auto-Ticket] Creado automáticamente tras escaneo de postura según política de severidad (${threshold}).`,
        });
      } catch (err) {
        this.logger.warn(`No se pudo auto-crear ticket para hallazgo ${f.id}: ${(err as Error).message}`);
      }
    }
  }
}
