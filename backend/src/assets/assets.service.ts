import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { validateAssetValue } from '../common/utils/network.util';
import { PrismaService } from '../prisma/prisma.service';
import { CreateAssetDto } from './dto/create-asset.dto';
import { ListAssetsQuery } from './dto/list-assets.query';
import { UpdateAssetDto } from './dto/update-asset.dto';

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
  constructor(private readonly prisma: PrismaService) {}

  async create(actor: AuthUser, dto: CreateAssetDto) {
    const validation = validateAssetValue(dto.value, dto.type);
    if (!validation.ok) {
      throw new BadRequestException(validation.reason);
    }

    // La unicidad (organization_id, value) la garantiza la BD; un duplicado
    // produce P2002 que el filtro global traduce a 409 Conflict.
    return this.prisma.asset.create({
      data: {
        organizationId: actor.organizationId,
        createdById: actor.id,
        type: validation.type,
        value: validation.value,
        name: dto.name,
        description: dto.description,
        authorizationConfirmed: true,
        authorizedAt: new Date(),
      },
      include: assetInclude,
    });
  }

  async findAll(organizationId: string, query: ListAssetsQuery) {
    const where: Prisma.AssetWhereInput = {
      organizationId,
      type: query.type,
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

  async update(organizationId: string, id: string, dto: UpdateAssetDto) {
    await this.findOne(organizationId, id);
    return this.prisma.asset.update({
      where: { id },
      data: { name: dto.name, description: dto.description, isActive: dto.isActive },
      include: assetInclude,
    });
  }

  async remove(organizationId: string, id: string): Promise<void> {
    await this.findOne(organizationId, id);
    await this.prisma.asset.delete({ where: { id } });
  }
}
