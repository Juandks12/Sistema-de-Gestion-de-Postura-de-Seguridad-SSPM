import { Logger, ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NestFactory } from '@nestjs/core';
import { NestExpressApplication } from '@nestjs/platform-express';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import helmet from 'helmet';
import { AppModule } from './app.module';
import { PrismaClientExceptionFilter } from './common/filters/prisma-exception.filter';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule, { bufferLogs: true });
  const config = app.get(ConfigService);
  const logger = new Logger('Bootstrap');

  // Detrás de un proxy (el Nginx de la imagen web) la IP real llega en
  // X-Forwarded-For; sin esto todos los clientes compartirían la IP del proxy
  // en los límites de peticiones del login.
  const trustProxy = parseTrustProxy(config.get<string>('TRUST_PROXY') ?? '');
  if (trustProxy !== undefined) app.set('trust proxy', trustProxy);

  app.use(helmet());
  app.setGlobalPrefix('api/v1');

  const corsOrigins = (config.get<string>('CORS_ORIGINS') ?? '')
    .split(',')
    .map((o) => o.trim())
    .filter(Boolean);
  if (corsOrigins.length > 0) {
    app.enableCors({ origin: corsOrigins, credentials: true });
  }

  // Validación global: rechaza propiedades desconocidas y transforma tipos.
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      transformOptions: { enableImplicitConversion: true },
    }),
  );
  app.useGlobalFilters(new PrismaClientExceptionFilter());

  const swaggerConfig = new DocumentBuilder()
    .setTitle('SSPM - SaaS Lite API')
    .setDescription(
      'API del Sistema de Gestión de Postura de Seguridad. ' +
        'Autentícate con /auth/login y usa el token como Bearer en el botón "Authorize".',
    )
    .setVersion('0.1.0')
    .addBearerAuth()
    .build();
  const document = SwaggerModule.createDocument(app, swaggerConfig);
  SwaggerModule.setup('api/docs', app, document);

  app.enableShutdownHooks();

  const port = config.get<number>('PORT') ?? 3000;
  await app.listen(port);
  logger.log(`API escuchando en http://localhost:${port}/api/v1`);
  logger.log(`Documentación Swagger en http://localhost:${port}/api/docs`);
}

function parseTrustProxy(raw: string): boolean | number | string | undefined {
  const value = raw.trim();
  if (!value) return undefined;
  if (value === 'true') return true;
  if (value === 'false') return false;
  if (/^\d+$/.test(value)) return Number(value);
  return value;
}

void bootstrap();
