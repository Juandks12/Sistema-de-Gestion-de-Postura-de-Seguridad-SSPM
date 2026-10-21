import {
  BadRequestException,
  Injectable,
  Logger,
} from '@nestjs/common';
import {
  AssetCriticality,
  AssetType,
  CloudAccountStatus,
  CloudProvider,
  CloudResourceType,
  FindingCategory,
  FindingSeverity,
  FindingStatus,
  Prisma,
  RiskScoreTrigger,
  VerificationMethod,
} from '@prisma/client';
import { fingerprintOf } from '../findings/findings.service';
import { PrismaService } from '../prisma/prisma.service';
import { RiskScoresService } from '../risk/risk-scores.service';
import {
  CloudAccountsService,
  SanitizedCloudAccount,
} from './cloud-accounts.service';
import { CSPM_RULES_MAP } from './cspm.catalog';
import { AwsCspmEvaluatorService } from './evaluators/aws-cspm.evaluator';
import { AzureCspmEvaluatorService } from './evaluators/azure-cspm.evaluator';
import {
  CloudAuditExecutionResult,
  CloudAuditStats,
} from './evaluators/cspm-evaluator.types';

export interface ListCloudResourcesFilter {
  provider?: CloudProvider;
  cloudAccountId?: string;
  resourceType?: CloudResourceType;
  hasActiveFindings?: boolean;
  search?: string;
}

export interface CloudAuditResponse {
  account: SanitizedCloudAccount;
  simulated: boolean;
  evaluatedRulesCount: number;
  evaluatedAt: string;
  durationMs: number;
  warnings: string[];
  stats: CloudAuditStats;
}

/**
 * Calcula la fecha límite (SLA) automática según la severidad del hallazgo CSPM
 * (Sección 5.2 del plan maestro):
 * - CRITICAL: 24 horas
 * - HIGH: 7 días
 * - MEDIUM: 30 días
 * - LOW / INFO: 90 días
 */
export function computeDefaultCspmDueDate(
  severity: FindingSeverity,
  fromDate: Date = new Date(),
): Date {
  const hourMs = 60 * 60 * 1000;
  const dayMs = 24 * hourMs;

  switch (severity) {
    case FindingSeverity.CRITICAL:
      return new Date(fromDate.getTime() + 24 * hourMs);
    case FindingSeverity.HIGH:
      return new Date(fromDate.getTime() + 7 * dayMs);
    case FindingSeverity.MEDIUM:
      return new Date(fromDate.getTime() + 30 * dayMs);
    case FindingSeverity.LOW:
    case FindingSeverity.INFO:
    default:
      return new Date(fromDate.getTime() + 90 * dayMs);
  }
}

function emptySeverityCounts(): Record<FindingSeverity, number> {
  return {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0,
  };
}

@Injectable()
export class CloudScanService {
  private readonly logger = new Logger(CloudScanService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly cloudAccounts: CloudAccountsService,
    private readonly awsEvaluator: AwsCspmEvaluatorService,
    private readonly azureEvaluator: AzureCspmEvaluatorService,
    private readonly riskScores: RiskScoresService,
  ) {}

  /**
   * Ejecuta una auditoría completa de postura CSPM sobre una cuenta cloud registrada:
   * 1. Recolecta el inventario de recursos y evalúa las reglas CSPM de AWS o Azure.
   * 2. Persiste y actualiza los recursos en `cloud_resources`.
   * 3. Normaliza y deduplica los hallazgos en `findings` mediante fingerprint SHA-256,
   *    asignando SLA automático por severidad y guías de remediación CLI / IaC.
   * 4. Auto-resuelve (`RESOLVED`) aquellos hallazgos que dejaron de reproducirse.
   * 5. Actualiza el Security Score del activo y de la organización.
   */
  async runAccountAudit(
    organizationId: string,
    accountId: string,
    options?: { simulate?: boolean; actorId?: string },
  ): Promise<CloudAuditResponse> {
    const startTime = Date.now();
    const { account, credentials } =
      await this.cloudAccounts.getDecryptedCredentials(organizationId, accountId);

    let executionResult: CloudAuditExecutionResult;
    try {
      if (account.provider === CloudProvider.AWS) {
        executionResult = await this.awsEvaluator.evaluateAccount({
          authInput: {
            authType: account.authType,
            accountId: account.accountOrSubscriptionId,
            roleArn: account.awsRoleArn,
            externalId: account.awsExternalId,
            accessKeyId: credentials.awsAccessKeyId,
            secretAccessKey: credentials.awsSecretAccessKey,
            sessionToken: credentials.awsSessionToken,
          },
          monitoredRegions: account.monitoredRegions,
          simulate: options?.simulate,
        });
      } else if (account.provider === CloudProvider.AZURE) {
        executionResult = await this.azureEvaluator.evaluateSubscription({
          authInput: {
            subscriptionId: account.accountOrSubscriptionId,
            tenantId: account.azureTenantId ?? '',
            clientId: credentials.azureClientId ?? '',
            clientSecret: credentials.azureClientSecret ?? '',
          },
          monitoredRegions: account.monitoredRegions,
          simulate: options?.simulate,
        });
      } else {
        throw new BadRequestException(
          `Proveedor cloud no soportado: ${account.provider}`,
        );
      }
    } catch (err) {
      const errorMessage =
        err instanceof Error
          ? err.message
          : 'Error de conexión al auditar la cuenta cloud';

      await this.prisma.cloudAccount.update({
        where: { id: account.id },
        data: {
          status: CloudAccountStatus.ERROR,
          lastAuditError: errorMessage.slice(0, 500),
        },
      });

      throw new BadRequestException(
        `No se pudo completar la auditoría CSPM para ${account.name}: ${errorMessage}`,
      );
    }

    const now = new Date();

    // Asegurar que la cuenta cloud tenga su activo padre vinculado en `assets`
    let assetId = account.assetId;
    if (!assetId) {
      const assetValue = `${account.provider.toLowerCase()}:${account.accountOrSubscriptionId}`;
      const asset = await this.prisma.asset.upsert({
        where: {
          organizationId_value: {
            organizationId,
            value: assetValue,
          },
        },
        update: {
          name: account.name,
          isActive: true,
          lastScannedAt: now,
          verifiedAt: now,
        },
        create: {
          organizationId,
          type: AssetType.CLOUD_ACCOUNT,
          value: assetValue,
          name: account.name,
          description: `Cuenta Cloud ${account.provider} (${account.accountOrSubscriptionId}) conectada para evaluación CSPM`,
          criticality: AssetCriticality.HIGH,
          tags: ['cloud', account.provider.toLowerCase(), 'cspm'],
          authorizationConfirmed: true,
          authorizedAt: now,
          createdById: options?.actorId ?? null,
          lastScannedAt: now,
          verifiedAt: now,
          verificationMethod: VerificationMethod.PRE_AUTHORIZED,
        },
      });
      assetId = asset.id;
    }

    const activeNativeIds = new Set(
      executionResult.findings.map((f) => f.nativeId),
    );

    const txOutcome = await this.prisma.$transaction(async (tx) => {
      // 1. Upsert de recursos descubiertos en `cloud_resources`
      const resourceIdByNativeId = new Map<string, string>();
      const discoveredNativeIds: string[] = [];

      for (const res of executionResult.resources) {
        discoveredNativeIds.push(res.nativeId);
        const hasActiveFindings = activeNativeIds.has(res.nativeId);

        const upserted = await tx.cloudResource.upsert({
          where: {
            cloudAccountId_nativeId: {
              cloudAccountId: account.id,
              nativeId: res.nativeId,
            },
          },
          update: {
            name: res.name.slice(0, 255),
            resourceType: res.resourceType,
            region: res.region ? res.region.slice(0, 50) : null,
            configuration: (res.configuration ?? {}) as Prisma.InputJsonValue,
            tags: (res.tags ?? Prisma.JsonNull) as Prisma.InputJsonValue,
            hasActiveFindings,
          },
          create: {
            organizationId,
            cloudAccountId: account.id,
            provider: account.provider,
            resourceType: res.resourceType,
            nativeId: res.nativeId.slice(0, 500),
            name: res.name.slice(0, 255),
            region: res.region ? res.region.slice(0, 50) : null,
            configuration: (res.configuration ?? {}) as Prisma.InputJsonValue,
            tags: (res.tags ?? Prisma.JsonNull) as Prisma.InputJsonValue,
            hasActiveFindings,
          },
          select: { id: true },
        });

        resourceIdByNativeId.set(res.nativeId, upserted.id);
      }

      // Limpiar recursos antiguos que ya no existen en la cuenta auditada
      if (discoveredNativeIds.length > 0) {
        await tx.cloudResource.deleteMany({
          where: {
            cloudAccountId: account.id,
            nativeId: { notIn: discoveredNativeIds },
          },
        });
      } else {
        await tx.cloudResource.deleteMany({
          where: { cloudAccountId: account.id },
        });
      }

      // 2. Sincronización de hallazgos en `findings` con deduplicación y SLAs
      let findingsCreated = 0;
      let findingsUpdated = 0;
      let findingsReopened = 0;
      const bySeverity = emptySeverityCounts();
      const byCategory: Partial<Record<FindingCategory, number>> = {};
      const seenFingerprints = new Set<string>();

      for (const draft of executionResult.findings) {
        const rule = CSPM_RULES_MAP.get(draft.ruleId);
        if (!rule) {
          this.logger.warn(`Regla CSPM no encontrada en catálogo: ${draft.ruleId}`);
          continue;
        }

        const location = draft.nativeId.slice(0, 500);
        const fingerprint = fingerprintOf(rule.ruleId, location);
        if (seenFingerprints.has(fingerprint)) continue;
        seenFingerprints.add(fingerprint);

        const cloudResourceId = resourceIdByNativeId.get(draft.nativeId) ?? null;
        const defaultDueDate = computeDefaultCspmDueDate(rule.severity, now);

        const enrichedEvidence: Record<string, unknown> = {
          ...draft.evidence,
          provider: account.provider,
          cloudAccountName: account.name,
          accountOrSubscriptionId: account.accountOrSubscriptionId,
          resourceName: draft.resourceName,
          resourceType: draft.resourceType,
          region: draft.region,
          remediationCli: rule.remediationCli,
          remediationIac: rule.remediationIac,
          complianceControlIds: rule.complianceControlIds,
        };

        const existing = await tx.finding.findUnique({
          where: {
            assetId_fingerprint: {
              assetId,
              fingerprint,
            },
          },
          select: { id: true, status: true, dueDate: true },
        });

        const baseData = {
          category: rule.category,
          ruleId: rule.ruleId,
          severity: rule.severity,
          cvssScore: new Prisma.Decimal(rule.cvssScore),
          title: rule.title.slice(0, 200),
          description: draft.descriptionOverride ?? rule.description,
          recommendation: rule.recommendation,
          location,
          evidence: enrichedEvidence as Prisma.InputJsonValue,
          lastSeenAt: now,
          cloudAccountId: account.id,
          cloudResourceId,
        };

        if (!existing) {
          await tx.finding.create({
            data: {
              ...baseData,
              organizationId,
              assetId,
              fingerprint,
              status: FindingStatus.OPEN,
              firstSeenAt: now,
              dueDate: defaultDueDate,
            },
          });
          findingsCreated += 1;
          bySeverity[rule.severity] += 1;
          byCategory[rule.category] = (byCategory[rule.category] ?? 0) + 1;
        } else if (existing.status === FindingStatus.RESOLVED) {
          await tx.finding.update({
            where: { id: existing.id },
            data: {
              ...baseData,
              status: FindingStatus.OPEN,
              resolvedAt: null,
              dueDate: existing.dueDate ?? defaultDueDate,
            },
          });
          findingsReopened += 1;
          bySeverity[rule.severity] += 1;
          byCategory[rule.category] = (byCategory[rule.category] ?? 0) + 1;
        } else {
          await tx.finding.update({
            where: { id: existing.id },
            data: {
              ...baseData,
              dueDate: existing.dueDate ?? defaultDueDate,
            },
          });
          findingsUpdated += 1;
          if (
            existing.status === FindingStatus.OPEN ||
            existing.status === FindingStatus.IN_PROGRESS ||
            existing.status === FindingStatus.VERIFYING
          ) {
            bySeverity[rule.severity] += 1;
            byCategory[rule.category] = (byCategory[rule.category] ?? 0) + 1;
          }
        }
      }

      // 3. Auto-resolución: cerrar hallazgos abiertos de esta cuenta que ya no se reproducen
      const resolvedUpdate = await tx.finding.updateMany({
        where: {
          assetId,
          cloudAccountId: account.id,
          status: {
            in: [
              FindingStatus.OPEN,
              FindingStatus.IN_PROGRESS,
              FindingStatus.VERIFYING,
            ],
          },
          ...(seenFingerprints.size > 0
            ? { fingerprint: { notIn: [...seenFingerprints] } }
            : {}),
        },
        data: {
          status: FindingStatus.RESOLVED,
          resolvedAt: now,
        },
      });
      const findingsResolved = resolvedUpdate.count;

      const activeFindings =
        bySeverity.CRITICAL +
        bySeverity.HIGH +
        bySeverity.MEDIUM +
        bySeverity.LOW +
        bySeverity.INFO;

      // 4. Actualizar fechas de escaneo en Asset y CloudAccount
      await tx.asset.update({
        where: { id: assetId },
        data: {
          lastScannedAt: now,
          verifiedAt: now,
          verificationMethod: VerificationMethod.PRE_AUTHORIZED,
        },
      });

      const updatedAccount = await tx.cloudAccount.update({
        where: { id: account.id },
        data: {
          assetId,
          status: CloudAccountStatus.CONNECTED,
          lastAuditedAt: now,
          lastAuditError: null,
          resourceCount: executionResult.resources.length,
          failingFindingCount: activeFindings,
        },
      });

      // 5. Registrar instantánea de Security Score del activo y de la organización
      const scoreSnapshot = await this.riskScores.snapshot(tx, {
        organizationId,
        assetId,
        trigger: RiskScoreTrigger.SCAN_COMPLETED,
      });

      return {
        updatedAccount,
        stats: {
          resourcesDiscovered: executionResult.resources.length,
          findingsCreated,
          findingsUpdated,
          findingsReopened,
          findingsResolved,
          activeFindings,
          bySeverity,
          byCategory,
          score: scoreSnapshot.asset.score,
          grade: scoreSnapshot.asset.grade,
        } satisfies CloudAuditStats,
      };
    });

    return {
      account: this.cloudAccounts.sanitizeAccount(txOutcome.updatedAccount),
      simulated: executionResult.simulated,
      evaluatedRulesCount: executionResult.evaluatedRulesCount,
      evaluatedAt: now.toISOString(),
      durationMs: Date.now() - startTime,
      warnings: executionResult.warnings,
      stats: txOutcome.stats,
    };
  }

  /**
   * Lista el inventario de recursos cloud descubiertos en la organización,
   * permitiendo filtrar por proveedor, cuenta, tipo de recurso, estado de hallazgos y búsqueda libre.
   */
  async listResources(organizationId: string, filter: ListCloudResourcesFilter) {
    const where: Prisma.CloudResourceWhereInput = {
      organizationId,
      ...(filter.provider ? { provider: filter.provider } : {}),
      ...(filter.cloudAccountId ? { cloudAccountId: filter.cloudAccountId } : {}),
      ...(filter.resourceType ? { resourceType: filter.resourceType } : {}),
      ...(filter.hasActiveFindings !== undefined
        ? { hasActiveFindings: filter.hasActiveFindings }
        : {}),
      ...(filter.search?.trim()
        ? {
            OR: [
              { name: { contains: filter.search.trim(), mode: 'insensitive' } },
              { nativeId: { contains: filter.search.trim(), mode: 'insensitive' } },
              { region: { contains: filter.search.trim(), mode: 'insensitive' } },
            ],
          }
        : {}),
    };

    const items = await this.prisma.cloudResource.findMany({
      where,
      include: {
        cloudAccount: {
          select: {
            id: true,
            name: true,
            provider: true,
            accountOrSubscriptionId: true,
          },
        },
        findings: {
          where: {
            status: {
              in: [
                FindingStatus.OPEN,
                FindingStatus.IN_PROGRESS,
                FindingStatus.VERIFYING,
              ],
            },
          },
          select: {
            id: true,
            ruleId: true,
            title: true,
            severity: true,
            category: true,
            status: true,
          },
          orderBy: { cvssScore: 'desc' },
        },
      },
      orderBy: [{ hasActiveFindings: 'desc' }, { updatedAt: 'desc' }],
      take: 250,
    });

    return items;
  }

  /**
   * Obtiene el resumen consolidado de postura CSPM (cuentas, inventario de recursos y hallazgos cloud).
   */
  async getCloudPostureSummary(organizationId: string) {
    const [accounts, resources, findings] = await Promise.all([
      this.prisma.cloudAccount.findMany({
        where: { organizationId },
        select: {
          id: true,
          provider: true,
          status: true,
          resourceCount: true,
          failingFindingCount: true,
          lastAuditedAt: true,
        },
      }),
      this.prisma.cloudResource.findMany({
        where: { organizationId },
        select: {
          provider: true,
          resourceType: true,
          hasActiveFindings: true,
        },
      }),
      this.prisma.finding.findMany({
        where: {
          organizationId,
          cloudAccountId: { not: null },
          status: {
            in: [
              FindingStatus.OPEN,
              FindingStatus.IN_PROGRESS,
              FindingStatus.VERIFYING,
            ],
          },
        },
        select: {
          severity: true,
          category: true,
        },
      }),
    ]);

    const accountsByProvider = {
      AWS: accounts.filter((a) => a.provider === CloudProvider.AWS).length,
      AZURE: accounts.filter((a) => a.provider === CloudProvider.AZURE).length,
    };

    const resourcesByProvider = {
      AWS: resources.filter((r) => r.provider === CloudProvider.AWS).length,
      AZURE: resources.filter((r) => r.provider === CloudProvider.AZURE).length,
    };

    const resourcesByType: Record<string, number> = {};
    let resourcesWithFindings = 0;
    for (const r of resources) {
      resourcesByType[r.resourceType] = (resourcesByType[r.resourceType] ?? 0) + 1;
      if (r.hasActiveFindings) resourcesWithFindings += 1;
    }

    const findingsBySeverity = emptySeverityCounts();
    const findingsByCategory: Record<string, number> = {};
    for (const f of findings) {
      findingsBySeverity[f.severity] += 1;
      findingsByCategory[f.category] = (findingsByCategory[f.category] ?? 0) + 1;
    }

    return {
      accounts: {
        total: accounts.length,
        connected: accounts.filter((a) => a.status === CloudAccountStatus.CONNECTED)
          .length,
        error: accounts.filter((a) => a.status === CloudAccountStatus.ERROR).length,
        pending: accounts.filter((a) => a.status === CloudAccountStatus.PENDING)
          .length,
        byProvider: accountsByProvider,
      },
      resources: {
        total: resources.length,
        withFindings: resourcesWithFindings,
        clean: resources.length - resourcesWithFindings,
        byProvider: resourcesByProvider,
        byType: resourcesByType,
      },
      findings: {
        totalOpen: findings.length,
        bySeverity: findingsBySeverity,
        byCategory: findingsByCategory,
      },
    };
  }
}
