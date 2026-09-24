import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { AppModule } from '../src/app.module';
import { PrismaClientExceptionFilter } from '../src/common/filters/prisma-exception.filter';
import { PrismaService } from '../src/prisma/prisma.service';

/**
 * Prueba de integración del flujo RF-01 con aislamiento multi-tenant.
 * Requiere una base de datos PostgreSQL accesible vía DATABASE_URL con las
 * migraciones aplicadas. Los datos creados se eliminan al finalizar.
 */
describe('Assets (e2e) - RF-01 y aislamiento multi-tenant', () => {
  let app: INestApplication;
  let prisma: PrismaService;
  const suffix = Date.now();
  const orgIds: string[] = [];

  let tokenAdminA: string;
  let tokenViewerA: string;
  let tokenAdminB: string;
  let assetIdA: string;

  const register = async (orgName: string, email: string) => {
    const res = await request(app.getHttpServer())
      .post('/api/v1/auth/register')
      .send({ organizationName: orgName, fullName: 'Test User', email, password: 'Password123' })
      .expect(201);
    orgIds.push(res.body.user.organizationId);
    return res.body as { accessToken: string; user: { id: string; organizationId: string } };
  };

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] }).compile();
    app = moduleRef.createNestApplication();
    app.setGlobalPrefix('api/v1');
    app.useGlobalPipes(
      new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }),
    );
    app.useGlobalFilters(new PrismaClientExceptionFilter());
    await app.init();
    prisma = app.get(PrismaService);

    const a = await register(`Org A ${suffix}`, `admin-a-${suffix}@test.local`);
    tokenAdminA = a.accessToken;
    const b = await register(`Org B ${suffix}`, `admin-b-${suffix}@test.local`);
    tokenAdminB = b.accessToken;

    // Usuario VIEWER dentro de la organización A
    await request(app.getHttpServer())
      .post('/api/v1/users')
      .set('Authorization', `Bearer ${tokenAdminA}`)
      .send({
        fullName: 'Viewer A',
        email: `viewer-a-${suffix}@test.local`,
        password: 'Password123',
        role: 'VIEWER',
      })
      .expect(201);
    const login = await request(app.getHttpServer())
      .post('/api/v1/auth/login')
      .send({ email: `viewer-a-${suffix}@test.local`, password: 'Password123' })
      .expect(200);
    tokenViewerA = login.body.accessToken;
  });

  afterAll(async () => {
    await prisma.organization.deleteMany({ where: { id: { in: orgIds } } });
    await app.close();
  });

  it('rechaza peticiones sin token', async () => {
    await request(app.getHttpServer()).get('/api/v1/assets').expect(401);
  });

  it('ADMIN registra un dominio y el valor se normaliza', async () => {
    const res = await request(app.getHttpServer())
      .post('/api/v1/assets')
      .set('Authorization', `Bearer ${tokenAdminA}`)
      .send({ value: 'HTTPS://Www.Example.ORG/path', name: 'Web', authorizationConfirmed: true })
      .expect(201);
    expect(res.body.type).toBe('DOMAIN');
    expect(res.body.value).toBe('www.example.org');
    expect(res.body.authorizationConfirmed).toBe(true);
    assetIdA = res.body.id;
  });

  it('registra una IP pública detectando el tipo automáticamente', async () => {
    const res = await request(app.getHttpServer())
      .post('/api/v1/assets')
      .set('Authorization', `Bearer ${tokenAdminA}`)
      .send({ value: '45.33.32.156', authorizationConfirmed: true })
      .expect(201);
    expect(res.body.type).toBe('IP');
  });

  it('rechaza duplicados dentro de la misma organización (409)', async () => {
    await request(app.getHttpServer())
      .post('/api/v1/assets')
      .set('Authorization', `Bearer ${tokenAdminA}`)
      .send({ value: 'www.example.org', authorizationConfirmed: true })
      .expect(409);
  });

  it('permite el mismo valor en otra organización', async () => {
    await request(app.getHttpServer())
      .post('/api/v1/assets')
      .set('Authorization', `Bearer ${tokenAdminB}`)
      .send({ value: 'www.example.org', authorizationConfirmed: true })
      .expect(201);
  });

  it('rechaza IPs privadas, hosts no públicos y valores inválidos (400)', async () => {
    for (const value of ['10.0.0.5', 'localhost', 'servidor.local', 'no es un host']) {
      await request(app.getHttpServer())
        .post('/api/v1/assets')
        .set('Authorization', `Bearer ${tokenAdminA}`)
        .send({ value, authorizationConfirmed: true })
        .expect(400);
    }
  });

  it('exige la confirmación de autorización (400)', async () => {
    await request(app.getHttpServer())
      .post('/api/v1/assets')
      .set('Authorization', `Bearer ${tokenAdminA}`)
      .send({ value: 'example.net', authorizationConfirmed: false })
      .expect(400);
  });

  it('ignora el organizationId enviado en el cuerpo (400 por propiedad no permitida)', async () => {
    await request(app.getHttpServer())
      .post('/api/v1/assets')
      .set('Authorization', `Bearer ${tokenAdminA}`)
      .send({ value: 'example.net', authorizationConfirmed: true, organizationId: orgIds[1] })
      .expect(400);
  });

  it('VIEWER no puede registrar activos (403) pero sí listarlos', async () => {
    await request(app.getHttpServer())
      .post('/api/v1/assets')
      .set('Authorization', `Bearer ${tokenViewerA}`)
      .send({ value: 'example.net', authorizationConfirmed: true })
      .expect(403);

    const res = await request(app.getHttpServer())
      .get('/api/v1/assets')
      .set('Authorization', `Bearer ${tokenViewerA}`)
      .expect(200);
    expect(res.body.meta.total).toBe(2);
  });

  it('una organización no ve ni modifica los activos de otra', async () => {
    const list = await request(app.getHttpServer())
      .get('/api/v1/assets')
      .set('Authorization', `Bearer ${tokenAdminB}`)
      .expect(200);
    expect(list.body.meta.total).toBe(1);
    expect(list.body.items.every((a: { organizationId: string }) => a.organizationId === orgIds[1])).toBe(true);

    await request(app.getHttpServer())
      .get(`/api/v1/assets/${assetIdA}`)
      .set('Authorization', `Bearer ${tokenAdminB}`)
      .expect(404);
    await request(app.getHttpServer())
      .patch(`/api/v1/assets/${assetIdA}`)
      .set('Authorization', `Bearer ${tokenAdminB}`)
      .send({ name: 'hackeado' })
      .expect(404);
    await request(app.getHttpServer())
      .delete(`/api/v1/assets/${assetIdA}`)
      .set('Authorization', `Bearer ${tokenAdminB}`)
      .expect(404);
  });

  it('solo ADMIN elimina activos', async () => {
    await request(app.getHttpServer())
      .delete(`/api/v1/assets/${assetIdA}`)
      .set('Authorization', `Bearer ${tokenViewerA}`)
      .expect(403);
    await request(app.getHttpServer())
      .delete(`/api/v1/assets/${assetIdA}`)
      .set('Authorization', `Bearer ${tokenAdminA}`)
      .expect(204);
    await request(app.getHttpServer())
      .get(`/api/v1/assets/${assetIdA}`)
      .set('Authorization', `Bearer ${tokenAdminA}`)
      .expect(404);
  });
});
