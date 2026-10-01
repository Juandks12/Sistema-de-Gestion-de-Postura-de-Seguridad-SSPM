import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { hours, minutes, ThrottlerModule } from '@nestjs/throttler';
import { APP_GUARD } from '@nestjs/core';
import { validateEnv } from './config/env.validation';
import { AuditModule } from './audit/audit.module';
import { RequestContextMiddleware } from './common/context/request-context';
import { MailerModule } from './common/mail/mailer.module';
import { PrismaModule } from './prisma/prisma.module';
import { AuthModule } from './auth/auth.module';
import { JwtAuthGuard } from './common/guards/jwt-auth.guard';
import { RolesGuard } from './common/guards/roles.guard';
import { OrganizationsModule } from './organizations/organizations.module';
import { UsersModule } from './users/users.module';
import { AssetsModule } from './assets/assets.module';
import { HealthModule } from './health/health.module';
import { ScansModule } from './scans/scans.module';
import { FindingsModule } from './findings/findings.module';
import { RiskModule } from './risk/risk.module';
import { DashboardModule } from './dashboard/dashboard.module';
import { AlertsModule } from './alerts/alerts.module';
import { MonitoringModule } from './monitoring/monitoring.module';
import { ReportsModule } from './reports/reports.module';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true, validate: validateEnv }),
    // Límites por IP solo para las rutas que usan ThrottlerGuard (login y registro).
    ThrottlerModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        errorMessage: 'Demasiadas solicitudes desde tu red. Espera un momento e inténtalo de nuevo.',
        throttlers: [
          { name: 'login', ttl: minutes(1), limit: config.get<number>('AUTH_LOGIN_RATE_PER_MINUTE') ?? 20 },
          { name: 'register', ttl: hours(1), limit: config.get<number>('AUTH_REGISTER_RATE_PER_HOUR') ?? 5 },
          { name: 'forgot', ttl: hours(1), limit: config.get<number>('AUTH_FORGOT_RATE_PER_HOUR') ?? 10 },
        ],
      }),
    }),
    PrismaModule,
    MailerModule,
    AuditModule,
    HealthModule,
    AuthModule,
    OrganizationsModule,
    UsersModule,
    AssetsModule,
    ScansModule,
    FindingsModule,
    RiskModule,
    DashboardModule,
    AlertsModule,
    MonitoringModule,
    ReportsModule,
  ],
  providers: [
    // Orden importante: primero autenticación (JWT), después autorización (roles).
    { provide: APP_GUARD, useClass: JwtAuthGuard },
    { provide: APP_GUARD, useClass: RolesGuard },
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer): void {
    // Contexto por petición (IP del cliente) para el registro de auditoría.
    consumer.apply(RequestContextMiddleware).forRoutes('{*path}');
  }
}
