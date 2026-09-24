/**
 * Pruebas end-to-end del Sprint 1 contra una base de datos PostgreSQL real
 * (usa DATABASE_URL del entorno / .env). Cubre:
 *  - registro y login (JWT)
 *  - RF-01: registro de activos con validación
 *  - RBAC: VIEWER no puede crear activos
 *  - aislamiento multi-tenant: una organización no ve los activos de otra
 */
import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { AppModule } from '../src/app.module';
import { PrismaClientExceptionFilter } from '../src/common/filters/prisma-client-exception.filter';
import { PrismaService } from '../src/prisma/prisma.service';

const unique = Date.now().toString(36);

describe('SSPM API (e2e)', () => {
  let app: INestApplication;
  let prisma: PrismaService;
  let tokenOrgA: string;
  let tokenOrgB: string;
  let tokenViewerA: string;
  let assetIdA: string;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] }).compile();
    app = moduleRef.createNestApplication();
    app.setGlobalPrefix('api/v1', { exclude: ['health'] });
    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
        transformOptions: { enableImplicitConversion: true },
      }),
    );
    app.useGlobalFilters(new PrismaClientExceptionFilter());
    await app.init();
    prisma = app.get(PrismaService);
  });

  afterAll(async () => {
    await prisma.organization.deleteMany({ where: { slug: { startsWith: `e2e-${unique}` } } });
    await app.close();
  });

  const api = () => request(app.getHttpServer());

  it('GET /health responde sin autenticación', async () => {
    const res = await api().get('/health').expect(200);
    expect(res.body).toMatchObject({ status: 'ok', database: 'up' });
  });

  it('POST /auth/register crea organización y usuario ADMIN', async () => {
    const res = await api()
      .post('/api/v1/auth/register')
      .send({
        organizationName: `E2E ${unique} Org A`,
        fullName: 'Admin A',
        email: `admin-a-${unique}@test.local`,
        password: 'Password123',
      })
      .expect(201);
    expect(res.body.user.role).toBe('ADMIN');
    expect(res.body.user.organization.slug).toBe(`e2e-${unique}-org-a`);
    tokenOrgA = res.body.accessToken;

    const resB = await api()
      .post('/api/v1/auth/register')
      .send({
        organizationName: `E2E ${unique} Org B`,
        fullName: 'Admin B',
        email: `admin-b-${unique}@test.local`,
        password: 'Password123',
      })
      .expect(201);
    tokenOrgB = resB.body.accessToken;
  });

  it('POST /auth/register rechaza un correo duplicado', async () => {
    await api()
      .post('/api/v1/auth/register')
      .send({
        organizationName: 'Otra Org',
        fullName: 'Otro Admin',
        email: `admin-a-${unique}@test.local`,
        password: 'Password123',
      })
      .expect(409);
  });

  it('POST /auth/login devuelve un JWT y rechaza credenciales inválidas', async () => {
    const res = await api()
      .post('/api/v1/auth/login')
      .send({ email: `admin-a-${unique}@test.local`, password: 'Password123' })
      .expect(200);
    expect(res.body.accessToken).toBeDefined();

    await api()
      .post('/api/v1/auth/login')
      .send({ email: `admin-a-${unique}@test.local`, password: 'incorrecta' })
      .expect(401);
  });

  it('endpoints protegidos exigen JWT', async () => {
    await api().get('/api/v1/assets').expect(401);
    await api().get('/api/v1/auth/me').set('Authorization', 'Bearer invalido').expect(401);
  });

  it('POST /organizations/me/members permite al ADMIN crear un VIEWER', async () => {
    await api()
      .post('/api/v1/organizations/me/members')
      .set('Authorization', `Bearer ${tokenOrgA}`)
      .send({
        fullName: 'Viewer A',
        email: `viewer-a-${unique}@test.local`,
        password: 'Password123',
        role: 'VIEWER',
      })
      .expect(201);

    const login = await api()
      .post('/api/v1/auth/login')
      .send({ email: `viewer-a-${unique}@test.local`, password: 'Password123' })
      .expect(200);
    tokenViewerA = login.body.accessToken;

    // El VIEWER no puede administrar usuarios.
    await api()
      .get('/api/v1/organizations/me/members')
      .set('Authorization', `Bearer ${tokenViewerA}`)
      .expect(403);
  });

  it('RF-01: POST /assets registra un dominio y detecta el tipo', async () => {
    const res = await api()
      .post('/api/v1/assets')
      .set('Authorization', `Bearer ${tokenOrgA}`)
      .send({ value: ' WWW.Ejemplo-A.com ', label: 'Web A', authorizationConfirmed: true })
      .expect(201);
    expect(res.body).toMatchObject({ type: 'DOMAIN', value: 'www.ejemplo-a.com', label: 'Web A' });
    expect(res.body.createdBy.email).toBe(`admin-a-${unique}@test.local`);
    assetIdA = res.body.id;
  });

  it('RF-01: POST /assets registra una IP pública', async () => {
    const res = await api()
      .post('/api/v1/assets')
      .set('Authorization', `Bearer ${tokenOrgA}`)
      .send({ value: '45.33.32.156', type: 'IP', authorizationConfirmed: true })
      .expect(201);
    expect(res.body.type).toBe('IP');
  });

  it('RF-01: POST /assets valida la entrada', async () => {
    const auth = { Authorization: `Bearer ${tokenOrgA}` };
    // URL completa
    await api()
      .post('/api/v1/assets')
      .set(auth)
      .send({ value: 'https://acme.com', authorizationConfirmed: true })
      .expect(400);
    // IP privada (ALLOW_PRIVATE_TARGETS=false por defecto)
    await api()
      .post('/api/v1/assets')
      .set(auth)
      .send({ value: '192.168.0.1', authorizationConfirmed: true })
      .expect(400);
    // Sin confirmar autorización
    await api()
      .post('/api/v1/assets')
      .set(auth)
      .send({ value: 'acme.com', authorizationConfirmed: false })
      .expect(400);
    // Tipo inconsistente con el valor
    await api()
      .post('/api/v1/assets')
      .set(auth)
      .send({ value: 'acme.com', type: 'IP', authorizationConfirmed: true })
      .expect(400);
    // Propiedad desconocida
    await api()
      .post('/api/v1/assets')
      .set(auth)
      .send({ value: 'acme.com', authorizationConfirmed: true, organizationId: 'x' })
      .expect(400);
    // Duplicado en la misma organización
    await api()
      .post('/api/v1/assets')
      .set(auth)
      .send({ value: 'www.ejemplo-a.com', authorizationConfirmed: true })
      .expect(409);
  });

  it('RBAC: el rol VIEWER no puede registrar activos pero sí listarlos', async () => {
    await api()
      .post('/api/v1/assets')
      .set('Authorization', `Bearer ${tokenViewerA}`)
      .send({ value: 'viewer.ejemplo.com', authorizationConfirmed: true })
      .expect(403);

    const res = await api()
      .get('/api/v1/assets')
      .set('Authorization', `Bearer ${tokenViewerA}`)
      .expect(200);
    expect(res.body.meta.total).toBe(2);
  });

  it('Multi-tenant: la organización B no ve los activos de A', async () => {
    const list = await api()
      .get('/api/v1/assets')
      .set('Authorization', `Bearer ${tokenOrgB}`)
      .expect(200);
    expect(list.body.items).toHaveLength(0);

    await api()
      .get(`/api/v1/assets/${assetIdA}`)
      .set('Authorization', `Bearer ${tokenOrgB}`)
      .expect(404);

    // El mismo valor puede registrarse en otra organización (unicidad por tenant).
    await api()
      .post('/api/v1/assets')
      .set('Authorization', `Bearer ${tokenOrgB}`)
      .send({ value: 'www.ejemplo-a.com', authorizationConfirmed: true })
      .expect(201);

    const listA = await api()
      .get('/api/v1/assets')
      .set('Authorization', `Bearer ${tokenOrgA}`)
      .expect(200);
    expect(listA.body.meta.total).toBe(2);
  });
});
