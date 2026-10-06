import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AssetCriticality, Prisma, RiskScoreTrigger } from '@prisma/client';
import { Readable } from 'node:stream';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { validateAssetValue } from '../common/utils/network.util';
import { UTF8_BOM, formatCsvRow } from '../common/utils/csv';
import { AuditService } from '../audit/audit.service';
import { PrismaService } from '../prisma/prisma.service';
import { RiskScoresService } from '../risk/risk-scores.service';
import { gradeFor } from '../risk/scoring';
import { CreateAssetDto } from './dto/create-asset.dto';
import { ExportAssetsQuery } from './dto/export-assets.query';
import { ListAssetsQuery } from './dto/list-assets.query';
import { UpdateAssetDto } from './dto/update-asset.dto';
import { AssetVerificationService } from './verification/asset-verification.service';

const assetInclude = {
  createdBy: { select: { id: true, fullName: true, email: true } },
  _count: { select: { scans: true } },
} satisfies Prisma.AssetInclude;

/**
 * RF-01: inventario de activos externos.
 * Todas las operaciones reciben el `organizationId` del usuario autenticado y lo
 * usan como filtro obligatorio: un tenant nunca puede leer o modificar activos de otro.
 */
@Injectable()
export class AssetsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
    private readonly riskScores: RiskScoresService,
    private readonly verification: AssetVerificationService,
    private readonly audit: AuditService,
  ) {}

  async create(actor: AuthUser, dto: CreateAssetDto) {
    const validation = validateAssetValue(dto.value, dto.type, {
      allowPrivate: this.config.get<boolean>('ALLOW_PRIVATE_TARGETS') === true,
    });
    if (!validation.ok) {
      throw new BadRequestException(validation.reason);
    }

    // Un subdominio de un dominio ya verificado por DNS hereda la verificación.
    const inherited = await this.verification.inheritedVerification(
      this.prisma,
      actor.organizationId,
      validation.type,
      validation.value,
    );

    // La unicidad (organization_id, value) la garantiza la BD; un duplicado
    // produce P2002 que el filtro global traduce a 409 Conflict.
    const created = await this.prisma.asset.create({
      data: {
        organizationId: actor.organizationId,
        createdById: actor.id,
        type: validation.type,
        value: validation.value,
        name: dto.name,
        description: dto.description,
        criticality: dto.criticality ?? AssetCriticality.MEDIUM,
        tags: dto.tags ?? [],
        authorizationConfirmed: true,
        authorizedAt: new Date(),
        ...(inherited ?? {}),
      },
      include: assetInclude,
    });
    this.audit.record({
      organizationId: actor.organizationId,
      action: 'asset.create',
      actor,
      target: { type: 'asset', id: created.id, label: created.value },
      detail: { type: created.type, ...(created.verificationMethod ? { verificationMethod: created.verificationMethod } : {}) },
    });
    return created;
  }

  async findAll(organizationId: string, query: ListAssetsQuery) {
    const where: Prisma.AssetWhereInput = {
      organizationId,
      type: query.type,
      criticality: query.criticality,
      ...(query.tag ? { tags: { has: query.tag } } : {}),
      isActive: query.isActive,
      ...(query.search
        ? {
            OR: [
              { value: { contains: query.search.toLowerCase() } },
              { name: { contains: query.search, mode: 'insensitive' } },
            ],
          }
        : {}),
    };

    const [items, total] = await this.prisma.$transaction([
      this.prisma.asset.findMany({
        where,
        include: assetInclude,
        orderBy: { createdAt: 'desc' },
        skip: (query.page - 1) * query.pageSize,
        take: query.pageSize,
      }),
      this.prisma.asset.count({ where }),
    ]);

    return {
      items,
      meta: {
        total,
        page: query.page,
        pageSize: query.pageSize,
        totalPages: Math.max(1, Math.ceil(total / query.pageSize)),
      },
    };
  }

  async findOne(organizationId: string, id: string) {
    const asset = await this.prisma.asset.findFirst({
      where: { id, organizationId },
      include: assetInclude,
    });
    if (!asset) {
      // 404 (no 403) para no revelar la existencia de activos de otros tenants.
      throw new NotFoundException('Activo no encontrado');
    }
    return asset;
  }

  async update(actor: AuthUser, id: string, dto: UpdateAssetDto) {
    const organizationId = actor.organizationId;
    const existing = await this.findOne(organizationId, id);
    const updated = await this.prisma.$transaction(async (tx) => {
      const updated = await tx.asset.update({
        where: { id },
        data: {
          name: dto.name,
          description: dto.description,
          isActive: dto.isActive,
          criticality: dto.criticality,
          tags: dto.tags,
        },
        include: assetInclude,
      });
      // Excluir o incluir un activo en el monitoreo o cambiar su criticidad cambia el score de la organización.
      if (
        (dto.isActive !== undefined && dto.isActive !== existing.isActive) ||
        (dto.criticality !== undefined && dto.criticality !== existing.criticality)
      ) {
        await this.riskScores.snapshotOrganization(tx, organizationId, RiskScoreTrigger.ASSET_CHANGED);
      }
      return updated;
    });

    this.audit.record({
      organizationId,
      action: 'asset.update',
      actor,
      target: { type: 'asset', id: updated.id, label: updated.value },
      detail: {
        ...(dto.name !== undefined ? { name: dto.name } : {}),
        ...(dto.description !== undefined ? { description: true } : {}),
        ...(dto.isActive !== undefined ? { isActive: dto.isActive } : {}),
      },
    });
    return updated;
  }

  async remove(actor: AuthUser, id: string): Promise<void> {
    const organizationId = actor.organizationId;
    const existing = await this.findOne(organizationId, id);
    await this.prisma.$transaction(async (tx) => {
      await tx.asset.delete({ where: { id } });
      await this.riskScores.snapshotOrganization(tx, organizationId, RiskScoreTrigger.ASSET_CHANGED);
    });
    this.audit.record({
      organizationId,
      action: 'asset.delete',
      actor,
      target: { type: 'asset', id: existing.id, label: existing.value },
    });
  }

  /**
   * Genera un stream legible (Readable) en formato CSV con el inventario de activos,
   * cálculo de Security Score y calificación por letra (grade) en streaming.
   */
  exportStream(organizationId: string, query: ExportAssetsQuery): Readable {
    const where: Prisma.AssetWhereInput = {
      organizationId,
      type: query.type,
      criticality: query.criticality,
      ...(query.tag ? { tags: { has: query.tag } } : {}),
      isActive: query.isActive,
      ...(query.search
        ? {
            OR: [
              { value: { contains: query.search.toLowerCase() } },
              { name: { contains: query.search, mode: 'insensitive' } },
            ],
          }
        : {}),
    };

    const prisma = this.prisma;
    const riskScores = this.riskScores;
    const batchSize = 500;

    async function* generateRows() {
      yield UTF8_BOM;
      yield formatCsvRow([
        'id',
        'name',
        'value',
        'type',
        'criticality',
        'tags',
        'is_active',
        'verified',
        'verification_method',
        'score',
        'grade',
        'last_scanned_at',
        'created_at',
      ]);

      const states = await riskScores.computeAllAssets(prisma, organizationId);
      const byAsset = new Map(states.map((s) => [s.assetId, s]));

      let skip = 0;
      while (true) {
        const batch = await prisma.asset.findMany({
          where,
          select: {
            id: true,
            name: true,
            value: true,
            type: true,
            criticality: true,
            tags: true,
            isActive: true,
            verifiedAt: true,
            verificationMethod: true,
            lastScannedAt: true,
            createdAt: true,
          },
          orderBy: [{ createdAt: 'desc' }, { id: 'asc' }],
          skip,
          take: batchSize,
        });

        if (batch.length === 0) break;

        for (const asset of batch) {
          const state = byAsset.get(asset.id);
          const scored = state?.scored ?? asset.lastScannedAt !== null;
          const score = scored ? (state?.result.score ?? null) : null;
          const grade = score !== null ? gradeFor(score).grade : '';

          yield formatCsvRow([
            asset.id,
            asset.name ?? '',
            asset.value,
            asset.type,
            asset.criticality,
            asset.tags,
            asset.isActive,
            asset.verifiedAt !== null,
            asset.verificationMethod ?? '',
            score !== null ? score : '',
            grade,
            asset.lastScannedAt,
            asset.createdAt,
          ]);
        }

        skip += batch.length;
        if (batch.length < batchSize) break;
      }
    }

    return Readable.from(generateRows());
  }
}
