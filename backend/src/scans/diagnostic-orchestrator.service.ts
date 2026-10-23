import {
  BadRequestException,
  ConflictException,
  Injectable,
  Logger,
  NotFoundException,
  OnModuleInit,
} from '@nestjs/common';
import {
  AssetType,
  DiagnosticBatchStatus,
  DiagnosticProfile,
  FindingStatus,
  Prisma,
  ScanSource,
  ScanStatus,
  ScanType,
} from '@prisma/client';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { PrismaService } from '../prisma/prisma.service';
import { ScansService } from './scans.service';
import { ScanWorkerService } from './scan-worker.service';

export interface StageDefinition {
  stage: number;
  name: string;
  description: string;
  types: ScanType[];
}

export interface PostureFindingSummary {
  id: string;
  fingerprint: string;
  ruleId: string;
  title: string;
  severity: string;
  status: string;
  location: string;
}

export interface PostureSurfaceSummary {
  openPorts: number[];
  subdomainsCount: number;
  technologies: string[];
  waf: string;
  externalScriptsCount: number;
}

export interface PostureDiffResult {
  assetId: string;
  fromBatchId: string | null;
  toBatchId: string;
  fromFinishedAt: Date | null;
  toFinishedAt: Date;
  score: {
    previous: number | null;
    current: number;
    delta: number;
    gradeChange: 'IMPROVED' | 'DEGRADED' | 'UNCHANGED';
  };
  findings: {
    newCount: number;
    remediatedCount: number;
    persistentCount: number;
    newFindings: PostureFindingSummary[];
    remediatedFindings: PostureFindingSummary[];
    persistentFindings: PostureFindingSummary[];
  };
  surface: {
    newPorts: number[];
    closedPorts: number[];
    wafChanged: boolean;
    wafBefore: string | null;
    wafAfter: string;
    subdomainsDelta: number;
  };
  assessment: string;
}

@Injectable()
export class DiagnosticOrchestratorService implements OnModuleInit {
  private readonly logger = new Logger(DiagnosticOrchestratorService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly scansService: ScansService,
    private readonly worker: ScanWorkerService,
  ) {}

  onModuleInit() {
    this.worker.registerCompletionHook(async (scanId, batchId) => {
      if (batchId) {
        await this.onScanFinished(scanId, batchId);
      }
    });
  }

  /**
   * Configuración de etapas según el perfil de auditoría y tipo de activo.
   */
  getStagesForProfile(profile: DiagnosticProfile, assetType: AssetType): StageDefinition[] {
    const isDomain = assetType === AssetType.DOMAIN;

    if (profile === DiagnosticProfile.PERIMETER_FAST) {
      return [
        {
          stage: 1,
          name: 'Red y Puertos Abiertos',
          description: 'Identificación rápida de puertos y servicios expuestos.',
          types: [ScanType.PORT_SCAN],
        },
        {
          stage: 2,
          name: 'Seguridad Web y Certificados',
          description: 'Cabeceras de protección HTTP y vigencia TLS.',
          types: [ScanType.WEB_HEADERS, ScanType.SSL_CERT],
        },
      ];
    }

    if (profile === DiagnosticProfile.FULL_AUDIT) {
      const stages: StageDefinition[] = [];
      let stageNumber = 1;

      if (isDomain) {
        stages.push({
          stage: stageNumber++,
          name: 'Descubrimiento de Superficie Pasiva',
          description: 'Mapeo de subdominios en Certificate Transparency.',
          types: [ScanType.SUBDOMAIN_DISCOVERY],
        });
      }

      stages.push({
        stage: stageNumber++,
        name: 'Perímetro, Puertos y Correo',
        description: 'Escaneo de puertos, servicios y registros de correo (SPF, DMARC, DKIM).',
        types: isDomain ? [ScanType.PORT_SCAN, ScanType.EMAIL_SECURITY] : [ScanType.PORT_SCAN],
      });

      stages.push({
        stage: stageNumber++,
        name: 'Auditoría Web Profunda y Rutas Sensibles',
        description: 'Análisis de cabeceras, rutas expuestas y certificados.',
        types: [ScanType.WEB_HEADERS, ScanType.SENSITIVE_PATHS, ScanType.SSL_CERT],
      });

      return stages;
    }

    // Default: COMMERCE_360 (Auditoría Profunda de Comercio Electrónico)
    const stages: StageDefinition[] = [];
    let stageNumber = 1;

    if (isDomain) {
      stages.push({
        stage: stageNumber++,
        name: 'Descubrimiento de Superficie Comercial',
        description: 'Mapeo de subdominios, tiendas activas y Subdomain Takeover.',
        types: [ScanType.SUBDOMAIN_DISCOVERY],
      });
    }

    stages.push({
      stage: stageNumber++,
      name: 'Perímetro, Red y Autenticación de Correo',
      description: 'Detección de puertos abiertos, servicios expuestos y protección contra spoofing/phishing.',
      types: isDomain ? [ScanType.PORT_SCAN, ScanType.EMAIL_SECURITY] : [ScanType.PORT_SCAN],
    });

    stages.push({
      stage: stageNumber++,
      name: 'Web Profunda, E-Commerce, Magecart y Secretos',
      description: 'Mini-crawler comercial, Anti-Skimming SRI, JS secret hunter, CMS y CORS.',
      types: [ScanType.WEB_HEADERS, ScanType.SENSITIVE_PATHS, ScanType.SSL_CERT],
    });

    return stages;
  }

  /**
   * Inicia un Diagnóstico Integral 360° encadenado.
   */
  async start(
    actor: AuthUser,
    assetId: string,
    profile: DiagnosticProfile = DiagnosticProfile.COMMERCE_360,
  ) {
    const asset = await this.prisma.asset.findFirst({
      where: { id: assetId, organizationId: actor.organizationId },
    });

    if (!asset) {
      throw new NotFoundException('Activo no encontrado');
    }
    if (!asset.isActive) {
      throw new BadRequestException('El activo está inactivo; reactívelo antes de auditarlo.');
    }
    if (!asset.authorizationConfirmed) {
      throw new BadRequestException('El activo no tiene autorización de escaneo confirmada.');
    }

    // Verificar si ya hay un diagnóstico 360° en progreso para este activo
    const activeBatch = await this.prisma.diagnosticBatch.findFirst({
      where: {
        assetId,
        organizationId: actor.organizationId,
        status: { in: [DiagnosticBatchStatus.PENDING, DiagnosticBatchStatus.IN_PROGRESS] },
      },
      include: { scans: true },
    });

    if (activeBatch) {
      throw new ConflictException(
        `Ya existe un Diagnóstico Integral 360° en progreso para este activo (Batch ID: ${activeBatch.id})`,
      );
    }

    const stages = this.getStagesForProfile(profile, asset.type);
    if (stages.length === 0) {
      throw new BadRequestException('No hay etapas de escaneo aplicables para este tipo de activo.');
    }

    const firstStage = stages[0];

    // Crear el lote en base de datos
    const batch = await this.prisma.diagnosticBatch.create({
      data: {
        organizationId: actor.organizationId,
        assetId,
        requestedById: actor.id,
        profile,
        status: DiagnosticBatchStatus.IN_PROGRESS,
        currentStage: 1,
        totalStages: stages.length,
        startedAt: new Date(),
      },
    });

    // Encolar los escaneos de la primera etapa
    for (const type of firstStage.types) {
      try {
        await this.scansService.enqueue({
          organizationId: actor.organizationId,
          assetId,
          type,
          requestedById: actor.id,
          source: ScanSource.MANUAL,
          batchId: batch.id,
          stage: 1,
        });
      } catch (err) {
        this.logger.warn(`No se pudo encolar escaneo ${type} para lote ${batch.id}: ${err}`);
      }
    }

    this.worker.kick();
    return this.getBatch(actor.organizationId, batch.id);
  }

  /**
   * Hook reactivo llamado por ScanWorkerService cuando un escaneo finaliza o falla.
   */
  async onScanFinished(scanId: string, batchId: string) {
    try {
      await this.advancePipeline(batchId);
    } catch (err) {
      this.logger.error(`Error al avanzar pipeline para lote ${batchId}: ${err}`);
    }
  }

  /**
   * Avanza el pipeline hacia la siguiente etapa si la etapa actual se ha completado.
   */
  async advancePipeline(batchId: string) {
    const batch = await this.prisma.diagnosticBatch.findUnique({
      where: { id: batchId },
      include: {
        asset: true,
        scans: true,
      },
    });

    if (!batch || batch.status !== DiagnosticBatchStatus.IN_PROGRESS) {
      return;
    }

    const stages = this.getStagesForProfile(batch.profile, batch.asset.type);
    const currentStageScans = batch.scans.filter((s) => s.stage === batch.currentStage);

    // Si algún escaneo de la etapa actual sigue pendiente o en ejecución, no se avanza
    const pendingScans = currentStageScans.filter((s) =>
      s.status === ScanStatus.PENDING || s.status === ScanStatus.RUNNING,
    );

    if (pendingScans.length > 0) {
      return;
    }

    // La etapa actual terminó. ¿Hay más etapas?
    if (batch.currentStage < batch.totalStages) {
      const nextStageIndex = batch.currentStage; // 0-indexed para la siguiente etapa
      const nextStage = stages[nextStageIndex];

      if (nextStage) {
        this.logger.log(
          `Lote 360° ${batch.id}: avanzando de Etapa ${batch.currentStage} a Etapa ${nextStage.stage} (${nextStage.name})`,
        );

        // Actualizar el estado de la etapa en el lote
        await this.prisma.diagnosticBatch.update({
          where: { id: batch.id },
          data: { currentStage: nextStage.stage },
        });

        // Encolar los escaneos de la nueva etapa
        for (const type of nextStage.types) {
          try {
            await this.scansService.enqueue({
              organizationId: batch.organizationId,
              assetId: batch.assetId,
              type,
              requestedById: batch.requestedById,
              source: ScanSource.MANUAL,
              batchId: batch.id,
              stage: nextStage.stage,
            });
          } catch (err) {
            this.logger.warn(`No se pudo encolar escaneo ${type} en etapa ${nextStage.stage}: ${err}`);
          }
        }

        this.worker.kick();
        return;
      }
    }

    // Todas las etapas han finalizado: completar el Diagnóstico 360°
    this.logger.log(`Lote 360° ${batch.id}: todas las etapas completadas. Generando consolidación.`);
    await this.completeBatch(batch.id);
  }

  /**
   * Consolida resultados, calcula snapshot de postura y guarda el resumen del Diagnóstico 360°.
   */
  private async completeBatch(batchId: string) {
    const batch = await this.prisma.diagnosticBatch.findUnique({
      where: { id: batchId },
      include: {
        asset: true,
        scans: {
          include: {
            ports: true,
          },
        },
      },
    });

    if (!batch) return;

    // Obtener score actual
    const currentScore = await this.prisma.riskScore.findFirst({
      where: { assetId: batch.assetId, scope: 'ASSET' },
      orderBy: { computedAt: 'desc' },
    });

    // Obtener hallazgos activos del activo
    const openFindings = await this.prisma.finding.findMany({
      where: {
        assetId: batch.assetId,
        status: { in: [FindingStatus.OPEN, FindingStatus.IN_PROGRESS, FindingStatus.VERIFYING] },
      },
      select: {
        id: true,
        fingerprint: true,
        ruleId: true,
        title: true,
        severity: true,
        status: true,
        location: true,
      },
    });

    // Superficie expuesta
    const allPorts = new Set<number>();
    for (const s of batch.scans) {
      for (const p of s.ports) {
        if (p.state === 'open') allPorts.add(p.port);
      }
    }

    const subdomainsCount = await this.prisma.discoveredHost.count({
      where: { assetId: batch.assetId },
    });

    // Extraer WAF y tecnologías del resumen de WEB_HEADERS
    const webHeadersScan = batch.scans.find((s) => s.type === ScanType.WEB_HEADERS);
    const webSummary = (webHeadersScan?.summary ?? {}) as Record<string, unknown>;
    const waf = (webSummary.waf as string) ?? 'Ninguno detectado';
    const techList = ((webSummary.technologies as Array<{ name: string }>) ?? []).map((t) => t.name);

    const surfaceSummary: PostureSurfaceSummary = {
      openPorts: Array.from(allPorts).sort((a, b) => a - b),
      subdomainsCount,
      technologies: techList,
      waf,
      externalScriptsCount: (webSummary.scriptsInspected as number) ?? 0,
    };

    const counts = {
      total: openFindings.length,
      critical: openFindings.filter((f) => f.severity === 'CRITICAL').length,
      high: openFindings.filter((f) => f.severity === 'HIGH').length,
      medium: openFindings.filter((f) => f.severity === 'MEDIUM').length,
      low: openFindings.filter((f) => f.severity === 'LOW').length,
    };

    const summaryPayload = {
      score: {
        score: currentScore?.score ? Number(currentScore.score) : 100,
        grade: currentScore?.grade ?? 'A',
      },
      findingsCount: counts,
      findingSnapshots: openFindings,
      surface: surfaceSummary,
    };

    await this.prisma.diagnosticBatch.update({
      where: { id: batch.id },
      data: {
        status: DiagnosticBatchStatus.COMPLETED,
        finishedAt: new Date(),
        summary: summaryPayload as unknown as Prisma.InputJsonValue,
      },
    });
  }

  /**
   * Obtiene el detalle de un Diagnóstico 360°, auto-avanzando el pipeline si está listo.
   */
  async getBatch(organizationId: string, batchId: string) {
    await this.advancePipeline(batchId);

    const batch = await this.prisma.diagnosticBatch.findFirst({
      where: { id: batchId, organizationId },
      include: {
        asset: { select: { id: true, value: true, type: true } },
        requestedBy: { select: { id: true, fullName: true, email: true } },
        scans: {
          orderBy: [{ stage: 'asc' }, { createdAt: 'asc' }],
          select: {
            id: true,
            type: true,
            status: true,
            stage: true,
            startedAt: true,
            finishedAt: true,
            summary: true,
            errorMessage: true,
          },
        },
      },
    });

    if (!batch) {
      throw new NotFoundException('Lote de diagnóstico 360° no encontrado');
    }

    const stages = this.getStagesForProfile(batch.profile, batch.asset.type);

    // Calcular progreso
    const totalExpectedScans = stages.reduce((acc, s) => acc + s.types.length, 0);
    const completedScans = batch.scans.filter(
      (s) => s.status === ScanStatus.COMPLETED || s.status === ScanStatus.FAILED,
    ).length;

    let progressPercentage = 0;
    if (batch.status === DiagnosticBatchStatus.COMPLETED) {
      progressPercentage = 100;
    } else if (totalExpectedScans > 0) {
      progressPercentage = Math.min(95, Math.round((completedScans / totalExpectedScans) * 100));
    }

    const stagesProgress = stages.map((stg) => {
      const scansInStage = batch.scans.filter((s) => s.stage === stg.stage);
      let stageStatus: 'PENDING' | 'IN_PROGRESS' | 'COMPLETED' = 'PENDING';

      if (batch.currentStage > stg.stage || batch.status === DiagnosticBatchStatus.COMPLETED) {
        stageStatus = 'COMPLETED';
      } else if (batch.currentStage === stg.stage) {
        stageStatus = 'IN_PROGRESS';
      }

      return {
        stage: stg.stage,
        name: stg.name,
        description: stg.description,
        status: stageStatus,
        scans: scansInStage,
      };
    });

    return {
      ...batch,
      progressPercentage,
      stages: stagesProgress,
    };
  }

  /**
   * Obtiene el diagnóstico más reciente de un activo.
   */
  async getLatestBatchForAsset(organizationId: string, assetId: string) {
    const latest = await this.prisma.diagnosticBatch.findFirst({
      where: { assetId, organizationId },
      orderBy: { createdAt: 'desc' },
      select: { id: true },
    });

    if (!latest) {
      return null;
    }

    return this.getBatch(organizationId, latest.id);
  }

  /**
   * Calcula el Diff de Postura Comercial entre dos diagnósticos temporales.
   */
  async getPostureDiff(
    organizationId: string,
    assetId: string,
    fromBatchId?: string,
    toBatchId?: string,
  ): Promise<PostureDiffResult> {
    let toBatch: Awaited<ReturnType<typeof this.getBatch>> | null = null;
    let fromBatch: Awaited<ReturnType<typeof this.getBatch>> | null = null;

    if (toBatchId) {
      toBatch = await this.getBatch(organizationId, toBatchId);
    } else {
      // Tomar el más reciente completado
      const latest = await this.prisma.diagnosticBatch.findFirst({
        where: { assetId, organizationId, status: DiagnosticBatchStatus.COMPLETED },
        orderBy: { finishedAt: 'desc' },
      });
      if (!latest) {
        throw new NotFoundException('No existen diagnósticos completados para generar el Diff de Postura.');
      }
      toBatch = await this.getBatch(organizationId, latest.id);
    }

    if (fromBatchId) {
      fromBatch = await this.getBatch(organizationId, fromBatchId);
    } else {
      // Tomar el anterior completado al toBatch
      const previous = await this.prisma.diagnosticBatch.findFirst({
        where: {
          assetId,
          organizationId,
          status: DiagnosticBatchStatus.COMPLETED,
          finishedAt: { lt: toBatch.finishedAt ?? toBatch.createdAt },
        },
        orderBy: { finishedAt: 'desc' },
      });
      if (previous) {
        fromBatch = await this.getBatch(organizationId, previous.id);
      }
    }

    const toSummary = (toBatch.summary ?? {}) as Record<string, unknown>;
    const toScoreObj = (toSummary.score as { score: number; grade: string }) ?? { score: 100, grade: 'A' };
    const toFindings = (toSummary.findingSnapshots as PostureFindingSummary[]) ?? [];
    const toSurface = (toSummary.surface as PostureSurfaceSummary) ?? {
      openPorts: [],
      subdomainsCount: 0,
      technologies: [],
      waf: 'Ninguno detectado',
      externalScriptsCount: 0,
    };

    const fromSummary = fromBatch ? ((fromBatch.summary ?? {}) as Record<string, unknown>) : null;
    const fromScoreObj = fromSummary ? (fromSummary.score as { score: number; grade: string }) : null;
    const fromFindings = fromSummary ? ((fromSummary.findingSnapshots as PostureFindingSummary[]) ?? []) : [];
    const fromSurface = fromSummary
      ? (fromSummary.surface as PostureSurfaceSummary)
      : {
          openPorts: [],
          subdomainsCount: 0,
          technologies: [],
          waf: 'Ninguno detectado',
          externalScriptsCount: 0,
        };

    // Calcular comparación de score
    const currentScore = toScoreObj.score;
    const previousScore = fromScoreObj ? fromScoreObj.score : null;
    const delta = previousScore !== null ? currentScore - previousScore : 0;
    let gradeChange: 'IMPROVED' | 'DEGRADED' | 'UNCHANGED' = 'UNCHANGED';
    if (delta > 0) gradeChange = 'IMPROVED';
    else if (delta < 0) gradeChange = 'DEGRADED';

    // Comparación de hallazgos
    const fromFingerprintMap = new Map(fromFindings.map((f) => [f.fingerprint, f]));
    const toFingerprintMap = new Map(toFindings.map((f) => [f.fingerprint, f]));

    const newFindings: PostureFindingSummary[] = [];
    const persistentFindings: PostureFindingSummary[] = [];
    const remediatedFindings: PostureFindingSummary[] = [];

    for (const tf of toFindings) {
      if (!fromFingerprintMap.has(tf.fingerprint)) {
        newFindings.push(tf);
      } else {
        persistentFindings.push(tf);
      }
    }

    for (const ff of fromFindings) {
      if (!toFingerprintMap.has(ff.fingerprint)) {
        remediatedFindings.push({ ...ff, status: 'RESOLVED' });
      }
    }

    // Comparación de superficie
    const fromPortsSet = new Set(fromSurface.openPorts ?? []);
    const toPortsSet = new Set(toSurface.openPorts ?? []);
    const newPorts = (toSurface.openPorts ?? []).filter((p) => !fromPortsSet.has(p));
    const closedPorts = (fromSurface.openPorts ?? []).filter((p) => !toPortsSet.has(p));

    const wafBefore = fromSurface.waf ?? null;
    const wafAfter = toSurface.waf ?? 'Ninguno detectado';
    const wafChanged = Boolean(wafBefore && wafBefore !== wafAfter);
    const subdomainsDelta = (toSurface.subdomainsCount ?? 0) - (fromSurface.subdomainsCount ?? 0);

    // Redacción de conclusión ejecutiva
    let assessment = '';
    if (fromBatch === null) {
      assessment = `Línea base inicial establecida con Security Score de ${currentScore}/100 (Grado ${toScoreObj.grade}) y ${toFindings.length} hallazgos activos detectados.`;
    } else if (delta > 0) {
      assessment = `La postura de seguridad mejoró +${delta} puntos (Score: ${currentScore}/100, Grado ${toScoreObj.grade}). Se remediaron ${remediatedFindings.length} vulnerabilidad(es) y se registraron ${newFindings.length} nueva(s).`;
    } else if (delta < 0) {
      assessment = `Alerta de regresión: la postura se degradó ${delta} puntos (Score: ${currentScore}/100, Grado ${toScoreObj.grade}). Se introdujeron ${newFindings.length} nueva(s) vulnerabilidad(es).`;
    } else {
      assessment = `La postura se mantiene estable en ${currentScore}/100 (Grado ${toScoreObj.grade}) con ${persistentFindings.length} hallazgo(s) persistente(s).`;
    }

    return {
      assetId,
      fromBatchId: fromBatch?.id ?? null,
      toBatchId: toBatch.id,
      fromFinishedAt: fromBatch?.finishedAt ?? null,
      toFinishedAt: toBatch.finishedAt ?? toBatch.createdAt,
      score: {
        previous: previousScore,
        current: currentScore,
        delta,
        gradeChange,
      },
      findings: {
        newCount: newFindings.length,
        remediatedCount: remediatedFindings.length,
        persistentCount: persistentFindings.length,
        newFindings,
        remediatedFindings,
        persistentFindings,
      },
      surface: {
        newPorts,
        closedPorts,
        wafChanged,
        wafBefore,
        wafAfter,
        subdomainsDelta,
      },
      assessment,
    };
  }

  /**
   * Cancela un lote de diagnóstico 360° en progreso.
   */
  async cancelBatch(organizationId: string, batchId: string) {
    const batch = await this.prisma.diagnosticBatch.findFirst({
      where: { id: batchId, organizationId },
      include: { scans: true },
    });

    if (!batch) {
      throw new NotFoundException('Lote de diagnóstico no encontrado');
    }

    // Cancelar cada escaneo activo
    for (const scan of batch.scans) {
      if (scan.status === ScanStatus.PENDING || scan.status === ScanStatus.RUNNING) {
        try {
          await this.scansService.cancel(organizationId, scan.id);
        } catch {
          // Ignorar fallo de cancelación individual
        }
      }
    }

    await this.prisma.diagnosticBatch.update({
      where: { id: batch.id },
      data: {
        status: DiagnosticBatchStatus.CANCELLED,
        finishedAt: new Date(),
      },
    });

    return { message: 'Diagnóstico Integral 360° cancelado exitosamente', batchId: batch.id };
  }
}
