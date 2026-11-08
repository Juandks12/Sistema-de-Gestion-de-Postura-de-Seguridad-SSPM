import { Controller, Get, Optional, ServiceUnavailableException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { DiagnosticBatchStatus, ScanStatus } from '@prisma/client';
import { Public } from '../common/decorators/public.decorator';
import { PrismaService } from '../prisma/prisma.service';

@ApiTags('health')
@Controller('health')
export class HealthController {
  constructor(
    private readonly prisma: PrismaService,
    @Optional() private readonly config?: ConfigService,
  ) {}

  @Public()
  @Get()
  @ApiOperation({ summary: 'Estado operativo del servicio, subsistemas, colas y conexión a base de datos' })
  async check() {
    try {
      await this.prisma.$queryRaw`SELECT 1`;
    } catch {
      throw new ServiceUnavailableException('Base de datos no disponible');
    }

    let pendingScans = 0;
    let runningScans = 0;
    let activeDiagnosticBatches = 0;

    try {
      const [pending, running, batches] = await Promise.all([
        this.prisma.scan ? this.prisma.scan.count({ where: { status: ScanStatus.PENDING } }) : Promise.resolve(0),
        this.prisma.scan ? this.prisma.scan.count({ where: { status: ScanStatus.RUNNING } }) : Promise.resolve(0),
        this.prisma.diagnosticBatch
          ? this.prisma.diagnosticBatch.count({
              where: { status: { in: [DiagnosticBatchStatus.PENDING, DiagnosticBatchStatus.IN_PROGRESS] } },
            })
          : Promise.resolve(0),
      ]);
      pendingScans = pending;
      runningScans = running;
      activeDiagnosticBatches = batches;
    } catch {
      // Si alguna tabla opcional no está disponible en un mock parcial, mantenemos 0
    }

    return {
      status: 'ok',
      database: 'up',
      version: '3.0.0',
      subsystems: {
        schedulerEnabled: this.config ? this.config.get<boolean>('SCHEDULER_ENABLED') !== false : true,
        retentionEnabled: this.config ? this.config.get<boolean>('RETENTION_ENABLED') !== false : true,
        threatLab: 'ready',
        grcCompliance: 'ready',
      },
      queue: {
        pendingScans,
        runningScans,
        activeDiagnosticBatches,
      },
      timestamp: new Date().toISOString(),
    };
  }
}
