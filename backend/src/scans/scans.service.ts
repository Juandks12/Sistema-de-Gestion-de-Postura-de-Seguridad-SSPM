import {
  BadRequestException,
  ConflictException,
  HttpException,
  HttpStatus,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Prisma, ScanSource, ScanStatus, ScanType } from '@prisma/client';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { PrismaService } from '../prisma/prisma.service';
import { CreateScanDto } from './dto/create-scan.dto';
import { ListScansQuery } from './dto/list-scans.query';
import { ScanCancellationService } from './scan-cancellation.service';
import { ScanWorkerService } from './scan-worker.service';

const scanListSelect = {
  id: true,
  organizationId: true,
  assetId: true,
  type: true,
  status: true,
  source: true,
  targetAddress: true,
  summary: true,
  errorMessage: true,
  startedAt: true,
  finishedAt: true,
  createdAt: true,
  updatedAt: true,
  asset: { select: { id: true, type: true, value: true, name: true } },
  requestedBy: { select: { id: true, fullName: true, email: true } },
} satisfies Prisma.ScanSelect;

export interface EnqueueScanInput {
  organizationId: string;
  assetId: string;
  type: ScanType;
  /** Nulo para los escaneos del monitoreo continuo. */
  requestedById: string | null;
  source: ScanSource;
}

@Injectable()
export class ScansService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly worker: ScanWorkerService,
    private readonly cancellation: ScanCancellationService,
    private readonly config: ConfigService,
  ) {}

  private get verificationRequired(): boolean {
    return this.config.get<boolean>('ASSET_VERIFICATION_REQUIRED') !== false;
  }

  /** Encola un escaneo (puertos, cabeceras, TLS o rutas sensibles) solicitado por un usuario. */
  request(actor: AuthUser, assetId: string, dto: CreateScanDto) {
    return this.enqueue({
      organizationId: actor.organizationId,
      assetId,
      type: dto.type ?? ScanType.PORT_SCAN,
      requestedById: actor.id,
      source: ScanSource.MANUAL,
    });
  }

  /** Auditoría completa solicitada por un usuario. */
  requestAll(actor: AuthUser, assetId: string) {
    return this.enqueueAll({
      organizationId: actor.organizationId,
      assetId,
      requestedById: actor.id,
      source: ScanSource.MANUAL,
    });
  }

  /**
   * Encola un escaneo. El límite por hora protege contra abuso de usuarios
   * (sección 11.3); los escaneos del monitoreo continuo no lo consumen porque
   * su volumen ya está acotado por la frecuencia y el número de activos.
   */
  async enqueue(input: EnqueueScanInput) {
    const { organizationId, assetId, type, requestedById, source } = input;
    if (!this.worker.supportedTypes.includes(type)) {
      throw new BadRequestException(`El tipo de escaneo ${type} no está disponible`);
    }

    const scan = await this.prisma.$transaction(async (tx) => {
      // Serializa las solicitudes sobre el mismo activo para evitar duplicados concurrentes.
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${assetId}))`;

      const asset = await tx.asset.findFirst({
        where: { id: assetId, organizationId },
      });
      if (!asset) {
        throw new NotFoundException('Activo no encontrado');
      }
      if (!asset.isActive) {
        throw new BadRequestException('El activo está inactivo; reactívalo antes de escanearlo');
      }
      if (!asset.authorizationConfirmed) {
        throw new BadRequestException('El activo no tiene autorización de escaneo confirmada');
      }
      if (this.verificationRequired && !asset.verifiedAt) {
        throw new BadRequestException(
          'Verifica que el activo es de tu organización (registro DNS o archivo de verificación) antes de escanearlo',
        );
      }

      const inProgress = await tx.scan.findFirst({
        where: {
          assetId,
          type,
          status: { in: [ScanStatus.PENDING, ScanStatus.RUNNING] },
        },
        select: { id: true, status: true },
      });
      if (inProgress) {
        throw new ConflictException(
          `Ya hay un escaneo ${inProgress.status} para este activo (id ${inProgress.id})`,
        );
      }

      if (source === ScanSource.MANUAL) {
        const maxPerHour = this.config.get<number>('SCAN_MAX_PER_HOUR_PER_ORG') ?? 30;
        const lastHour = await tx.scan.count({
          where: {
            organizationId,
            source: ScanSource.MANUAL,
            createdAt: { gte: new Date(Date.now() - 60 * 60 * 1000) },
          },
        });
        if (lastHour >= maxPerHour) {
          throw new HttpException(
            `Límite de ${maxPerHour} escaneos por hora alcanzado para la organización`,
            HttpStatus.TOO_MANY_REQUESTS,
          );
        }
      }

      return tx.scan.create({
        data: {
          organizationId,
          assetId,
          type,
          status: ScanStatus.PENDING,
          source,
          requestedById,
        },
        select: scanListSelect,
      });
    });

    this.worker.kick();
    return scan;
  }

  /** Encola todos los tipos de escaneo disponibles para un activo (auditoría completa). */
  async enqueueAll(input: Omit<EnqueueScanInput, 'type'>) {
    const queued: Awaited<ReturnType<ScansService['enqueue']>>[] = [];
    const skipped: Array<{ type: ScanType; reason: string }> = [];
    for (const type of this.worker.supportedTypes) {
      try {
        queued.push(await this.enqueue({ ...input, type }));
      } catch (err) {
        if (err instanceof NotFoundException || err instanceof BadRequestException) throw err;
        if (err instanceof HttpException) {
          skipped.push({ type, reason: err.message });
          continue;
        }
        throw err;
      }
    }
    return { queued, skipped };
  }

  async findAll(organizationId: string, query: ListScansQuery) {
    const where: Prisma.ScanWhereInput = {
      organizationId,
      assetId: query.assetId,
      status: query.status,
      type: query.type,
    };
    const [items, total] = await this.prisma.$transaction([
      this.prisma.scan.findMany({
        where,
        select: scanListSelect,
        orderBy: { createdAt: 'desc' },
        skip: (query.page - 1) * query.pageSize,
        take: query.pageSize,
      }),
      this.prisma.scan.count({ where }),
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

  async findOne(organizationId: string, id: string, includeRaw = false) {
    const scan = await this.prisma.scan.findFirst({
      where: { id, organizationId },
      select: {
        ...scanListSelect,
        parameters: true,
        rawResult: includeRaw,
        _count: { select: { findings: true } },
        ports: {
          orderBy: [{ protocol: 'asc' }, { port: 'asc' }],
          select: {
            port: true,
            protocol: true,
            state: true,
            reason: true,
            serviceName: true,
            product: true,
            version: true,
            extraInfo: true,
            tunnel: true,
            cpe: true,
            confidence: true,
          },
        },
      },
    });
    if (!scan) {
      throw new NotFoundException('Escaneo no encontrado');
    }
    return scan;
  }

  async cancel(organizationId: string, id: string) {
    const scan = await this.prisma.scan.findFirst({
      where: { id, organizationId },
      select: { id: true, status: true },
    });
    if (!scan) {
      throw new NotFoundException('Escaneo no encontrado');
    }
    if (scan.status !== ScanStatus.PENDING && scan.status !== ScanStatus.RUNNING) {
      throw new ConflictException(`No se puede cancelar un escaneo en estado ${scan.status}`);
    }

    const { count } = await this.prisma.scan.updateMany({
      where: { id, status: scan.status },
      data: { status: ScanStatus.CANCELLED, finishedAt: new Date() },
    });
    if (count === 0) {
      throw new ConflictException('El escaneo cambió de estado; vuelve a consultarlo');
    }
    if (scan.status === ScanStatus.RUNNING) {
      this.cancellation.abort(id, 'cancelled');
    }
    return this.findOne(organizationId, id);
  }

  /**
   * Superficie expuesta actual de un activo: puertos abiertos según el último
   * escaneo de puertos completado.
   */
  async exposure(organizationId: string, assetId: string) {
    const asset = await this.prisma.asset.findFirst({
      where: { id: assetId, organizationId },
      select: { id: true, type: true, value: true, name: true, lastScannedAt: true },
    });
    if (!asset) {
      throw new NotFoundException('Activo no encontrado');
    }

    const lastScan = await this.prisma.scan.findFirst({
      where: { assetId, organizationId, type: ScanType.PORT_SCAN, status: ScanStatus.COMPLETED },
      orderBy: { finishedAt: 'desc' },
      select: {
        id: true,
        finishedAt: true,
        targetAddress: true,
        ports: {
          where: { state: 'open' },
          orderBy: [{ protocol: 'asc' }, { port: 'asc' }],
          select: {
            port: true,
            protocol: true,
            serviceName: true,
            product: true,
            version: true,
            extraInfo: true,
            tunnel: true,
            cpe: true,
          },
        },
      },
    });

    return {
      asset,
      scan: lastScan
        ? { id: lastScan.id, finishedAt: lastScan.finishedAt, targetAddress: lastScan.targetAddress }
        : null,
      openPorts: lastScan?.ports ?? [],
    };
  }
}
