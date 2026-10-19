import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { FindingSeverity, FindingStatus } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import {
  COMPLIANCE_CONTROLS,
  ComplianceControlDefinition,
  ComplianceFramework,
  FRAMEWORKS_METADATA,
  FrameworkMetadata,
} from './compliance.catalog';

export interface ControlFindingSummary {
  id: string;
  ruleId: string;
  title: string;
  severity: FindingSeverity;
  cvssScore: number | null;
  location: string;
  assetId: string;
  assetValue: string;
  assetName: string | null;
}

export interface ControlEvaluationResult {
  control: ComplianceControlDefinition;
  status: 'COMPLIANT' | 'NON_COMPLIANT';
  affectedAssetsCount: number;
  failingFindingsCount: number;
  worstSeverity: FindingSeverity | null;
  failingFindings: ControlFindingSummary[];
}

export interface FrameworkSummary {
  metadata: FrameworkMetadata;
  totalControls: number;
  passedControls: number;
  failedControls: number;
  compliancePercentage: number;
  failingFindingsCount: number;
  worstSeverity: FindingSeverity | null;
}

export interface ComplianceOverview {
  globalCompliancePercentage: number;
  totalFrameworks: number;
  totalEvaluatedControls: number;
  frameworks: FrameworkSummary[];
  topFailingControls: Array<{
    framework: ComplianceFramework;
    code: string;
    title: string;
    domain: string;
    worstSeverity: FindingSeverity;
    failingFindingsCount: number;
    affectedAssetsCount: number;
  }>;
}

const SEVERITY_WEIGHT: Record<FindingSeverity, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

@Injectable()
export class ComplianceService {
  constructor(private readonly prisma: PrismaService) {}

  /**
   * Obtiene la vista general de cumplimiento normativo para una organización.
   */
  async getOverview(organizationId: string): Promise<ComplianceOverview> {
    const activeFindings = await this.prisma.finding.findMany({
      where: {
        organizationId,
        status: { in: [FindingStatus.OPEN, FindingStatus.IN_PROGRESS] },
        asset: { isActive: true },
      },
      select: {
        id: true,
        ruleId: true,
        title: true,
        severity: true,
        cvssScore: true,
        location: true,
        assetId: true,
        asset: {
          select: {
            id: true,
            value: true,
            name: true,
          },
        },
      },
    });

    const activeRulesMap = new Map<string, ControlFindingSummary[]>();
    for (const f of activeFindings) {
      const list = activeRulesMap.get(f.ruleId) ?? [];
      list.push({
        id: f.id,
        ruleId: f.ruleId,
        title: f.title,
        severity: f.severity,
        cvssScore: f.cvssScore ? Number(f.cvssScore) : null,
        location: f.location,
        assetId: f.assetId,
        assetValue: f.asset.value,
        assetName: f.asset.name,
      });
      activeRulesMap.set(f.ruleId, list);
    }

    const frameworkSummaries: FrameworkSummary[] = [];
    const allFailingControls: Array<{
      framework: ComplianceFramework;
      code: string;
      title: string;
      domain: string;
      worstSeverity: FindingSeverity;
      failingFindingsCount: number;
      affectedAssetsCount: number;
    }> = [];

    let totalSumPercentage = 0;

    for (const frameworkKey of Object.values(ComplianceFramework)) {
      const metadata = FRAMEWORKS_METADATA[frameworkKey];
      const controls = COMPLIANCE_CONTROLS.filter((c) => c.framework === frameworkKey);

      let passedControls = 0;
      let failedControls = 0;
      let frameworkFailingFindingsCount = 0;
      let frameworkWorstSeverity: FindingSeverity | null = null;

      for (const ctrl of controls) {
        const matchingFindings: ControlFindingSummary[] = [];
        for (const ruleId of ctrl.ruleIds) {
          const findings = activeRulesMap.get(ruleId);
          if (findings) {
            matchingFindings.push(...findings);
          }
        }

        if (matchingFindings.length === 0) {
          passedControls += 1;
        } else {
          failedControls += 1;
          frameworkFailingFindingsCount += matchingFindings.length;

          let controlWorstSeverity: FindingSeverity = FindingSeverity.INFO;
          const distinctAssets = new Set<string>();

          for (const mf of matchingFindings) {
            distinctAssets.add(mf.assetId);
            if (SEVERITY_WEIGHT[mf.severity] > SEVERITY_WEIGHT[controlWorstSeverity]) {
              controlWorstSeverity = mf.severity;
            }
          }

          if (
            !frameworkWorstSeverity ||
            SEVERITY_WEIGHT[controlWorstSeverity] > SEVERITY_WEIGHT[frameworkWorstSeverity]
          ) {
            frameworkWorstSeverity = controlWorstSeverity;
          }

          allFailingControls.push({
            framework: frameworkKey,
            code: ctrl.code,
            title: ctrl.title,
            domain: ctrl.domain,
            worstSeverity: controlWorstSeverity,
            failingFindingsCount: matchingFindings.length,
            affectedAssetsCount: distinctAssets.size,
          });
        }
      }

      const totalControls = controls.length;
      const compliancePercentage = totalControls > 0 ? Math.round((passedControls / totalControls) * 100) : 100;
      totalSumPercentage += compliancePercentage;

      frameworkSummaries.push({
        metadata,
        totalControls,
        passedControls,
        failedControls,
        compliancePercentage,
        failingFindingsCount: frameworkFailingFindingsCount,
        worstSeverity: frameworkWorstSeverity,
      });
    }

    allFailingControls.sort((a, b) => {
      const weightDiff = SEVERITY_WEIGHT[b.worstSeverity] - SEVERITY_WEIGHT[a.worstSeverity];
      if (weightDiff !== 0) return weightDiff;
      return b.failingFindingsCount - a.failingFindingsCount;
    });

    const globalPercentage =
      frameworkSummaries.length > 0 ? Math.round(totalSumPercentage / frameworkSummaries.length) : 100;

    return {
      globalCompliancePercentage: globalPercentage,
      totalFrameworks: frameworkSummaries.length,
      totalEvaluatedControls: COMPLIANCE_CONTROLS.length,
      frameworks: frameworkSummaries,
      topFailingControls: allFailingControls.slice(0, 5),
    };
  }

  /**
   * Obtiene la matriz detallada de controles para un marco regulatorio específico.
   */
  async getFrameworkDetails(
    organizationId: string,
    framework: ComplianceFramework,
  ): Promise<{
    metadata: FrameworkMetadata;
    summary: FrameworkSummary;
    controls: ControlEvaluationResult[];
  }> {
    const metadata = FRAMEWORKS_METADATA[framework];
    if (!metadata) {
      throw new NotFoundException(`Marco regulatorio no reconocido: ${framework}`);
    }

    const controls = COMPLIANCE_CONTROLS.filter((c) => c.framework === framework);

    const activeFindings = await this.prisma.finding.findMany({
      where: {
        organizationId,
        status: { in: [FindingStatus.OPEN, FindingStatus.IN_PROGRESS] },
        asset: { isActive: true },
      },
      select: {
        id: true,
        ruleId: true,
        title: true,
        severity: true,
        cvssScore: true,
        location: true,
        assetId: true,
        asset: {
          select: {
            id: true,
            value: true,
            name: true,
          },
        },
      },
    });

    const activeRulesMap = new Map<string, ControlFindingSummary[]>();
    for (const f of activeFindings) {
      const list = activeRulesMap.get(f.ruleId) ?? [];
      list.push({
        id: f.id,
        ruleId: f.ruleId,
        title: f.title,
        severity: f.severity,
        cvssScore: f.cvssScore ? Number(f.cvssScore) : null,
        location: f.location,
        assetId: f.assetId,
        assetValue: f.asset.value,
        assetName: f.asset.name,
      });
      activeRulesMap.set(f.ruleId, list);
    }

    const results: ControlEvaluationResult[] = [];
    let passedControls = 0;
    let failedControls = 0;
    let totalFailingFindings = 0;
    let worstFrameworkSeverity: FindingSeverity | null = null;

    for (const ctrl of controls) {
      const matchingFindings: ControlFindingSummary[] = [];
      for (const ruleId of ctrl.ruleIds) {
        const found = activeRulesMap.get(ruleId);
        if (found) {
          matchingFindings.push(...found);
        }
      }

      if (matchingFindings.length === 0) {
        passedControls += 1;
        results.push({
          control: ctrl,
          status: 'COMPLIANT',
          affectedAssetsCount: 0,
          failingFindingsCount: 0,
          worstSeverity: null,
          failingFindings: [],
        });
      } else {
        failedControls += 1;
        totalFailingFindings += matchingFindings.length;

        let controlWorstSeverity: FindingSeverity = FindingSeverity.INFO;
        const distinctAssets = new Set<string>();

        for (const mf of matchingFindings) {
          distinctAssets.add(mf.assetId);
          if (SEVERITY_WEIGHT[mf.severity] > SEVERITY_WEIGHT[controlWorstSeverity]) {
            controlWorstSeverity = mf.severity;
          }
        }

        if (
          !worstFrameworkSeverity ||
          SEVERITY_WEIGHT[controlWorstSeverity] > SEVERITY_WEIGHT[worstFrameworkSeverity]
        ) {
          worstFrameworkSeverity = controlWorstSeverity;
        }

        results.push({
          control: ctrl,
          status: 'NON_COMPLIANT',
          affectedAssetsCount: distinctAssets.size,
          failingFindingsCount: matchingFindings.length,
          worstSeverity: controlWorstSeverity,
          failingFindings: matchingFindings,
        });
      }
    }

    const totalControls = controls.length;
    const compliancePercentage = totalControls > 0 ? Math.round((passedControls / totalControls) * 100) : 100;

    return {
      metadata,
      summary: {
        metadata,
        totalControls,
        passedControls,
        failedControls,
        compliancePercentage,
        failingFindingsCount: totalFailingFindings,
        worstSeverity: worstFrameworkSeverity,
      },
      controls: results,
    };
  }

  /**
   * Exporta la matriz de cumplimiento en formato CSV para auditores.
   */
  async exportCsv(organizationId: string, framework: ComplianceFramework): Promise<string> {
    const data = await this.getFrameworkDetails(organizationId, framework);

    const headers = [
      'Marco Regulatorio',
      'Código de Control',
      'Título del Control',
      'Dominio',
      'Estado',
      'Nivel de Riesgo',
      'Hallazgos Activos',
      'Activos Afectados',
      'Descripción del Requisito',
    ];

    const rows = data.controls.map((item) => [
      `"${data.metadata.name}"`,
      `"${item.control.code}"`,
      `"${item.control.title.replace(/"/g, '""')}"`,
      `"${item.control.domain}"`,
      `"${item.status === 'COMPLIANT' ? 'CUMPLIDO' : 'INCUMPLIDO'}"`,
      `"${item.worstSeverity ?? 'NINGUNO'}"`,
      item.failingFindingsCount,
      item.affectedAssetsCount,
      `"${item.control.description.replace(/"/g, '""')}"`,
    ]);

    return [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
  }
}
