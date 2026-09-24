import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { AuthenticatedUser } from '../common/interfaces/authenticated-user.interface';
import type { EnvConfig } from '../config/env.validation';
import { Prisma } from '../generated/prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { InvalidTargetError, normalizeTarget } from './asset-target.util';
import { CreateAssetDto } from './dto/create-asset.dto';
import { ListAssetsQuery } from './dto/list-assets.query';

const assetSelect = {
  id: true,
  organizationId: true,
  type: true,
  value: true,
  label: true,
  description: true,
  authorizationConfirmed: true,
  isActive: true,
  lastScannedAt: true,
  createdAt: true,
  updatedAt: true,
  createdBy: { select: { id: true, fullName: true, email: true } },
} satisfies Prisma.AssetSelect;

/**
 * Inventario de activos. Todas las operaciones reciben al usuario autenticado y
 * filtran por su `organizationId`: un tenant nunca puede ver ni crear activos de otro.
 */
@Injectable()
export class AssetsService {
  private readonly allowPrivateTargets: boolean;

  constructor(
    private readonly prisma: PrismaService,
    config: ConfigService<EnvConfig, true>,
  ) {
    this.allowPrivateTargets = config.get('ALLOW_PRIVATE_TARGETS', { infer: true });
  }

  async create(user: AuthenticatedUser, dto: CreateAssetDto) {
    let target;
    try {
      target = normalizeTarget(dto.value, { allowPrivate: this.allowPrivateTargets });
    } catch (error) {
      if (error instanceof InvalidTargetError) {
        throw new BadRequestException(error.message);
      }
      throw error;
    }

    if (dto.type && dto.type !== target.type) {
      throw new BadRequestException(
        `El valor "${target.value}" corresponde a un activo de tipo ${target.type}, no ${dto.type}`,
      );
    }

    const duplicate = await this.prisma.asset.findUnique({
      where: { organizationId_value: { organizationId: user.organizationId, value: target.value } },
      select: { id: true },
    });
    if (duplicate) {
      throw new ConflictException(
        `El activo "${target.value}" ya está registrado en tu organización`,
      );
    }

    return this.prisma.asset.create({
      data: {
        organizationId: user.organizationId,
        createdById: user.id,
        type: target.type,
        value: target.value,
        label: dto.label,
        description: dto.description,
        authorizationConfirmed: dto.authorizationConfirmed,
      },
      select: assetSelect,
    });
  }

  async findAll(organizationId: string, query: ListAssetsQuery) {
    const where: Prisma.AssetWhereInput = {
      organizationId,
      ...(query.type && { type: query.type }),
      ...(query.search && {
        OR: [
          { value: { contains: query.search.toLowerCase() } },
          { label: { contains: query.search, mode: 'insensitive' } },
        ],
      }),
    };

    const [items, total] = await this.prisma.$transaction([
      this.prisma.asset.findMany({
        where,
        select: assetSelect,
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
    // Se filtra por organización además de por id: un id válido de otro tenant devuelve 404.
    const asset = await this.prisma.asset.findFirst({
      where: { id, organizationId },
      select: assetSelect,
    });
    if (!asset) {
      throw new NotFoundException('Activo no encontrado');
    }
    return asset;
  }
}
