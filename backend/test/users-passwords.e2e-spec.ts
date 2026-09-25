import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { AppModule } from '../src/app.module';
import { PrismaClientExceptionFilter } from '../src/common/filters/prisma-exception.filter';
import { PrismaService } from '../src/prisma/prisma.service';

/** Gestión de usuarios y contraseñas: cambio propio, restablecimiento por ADMIN y cierre de sesiones. */
describe('Usuarios y contraseñas (e2e)', () => {
  let app: INestApplication;
  let prisma: PrismaService;
  const suffix = Date.now();
  const orgIds: string[] = [];
  const adminEmail = `pw-admin-${suffix}@test.local`;
  const analystEmail = `pw-analyst-${suffix}@test.local`;
  let adminToken: string;
  let adminId: string;
  let analystId: string;

  const http = () => request(app.getHttpServer());
  const auth = (t: string) => ({ Authorization: `Bearer ${t}` });
  const login = (email: string, password: string) => http().post('/api/v1/auth/login').send({ email, password });

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] }).compile();
    app = moduleRef.createNestApplication();
    app.setGlobalPrefix('api/v1');
    app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }));
    app.useGlobalFilters(new PrismaClientExceptionFilter());
    await app.init();
    prisma = app.get(PrismaService);

    const reg = await http()
      .post('/api/v1/auth/register')
      .send({ organizationName: `Pw Org ${suffix}`, fullName: 'Admin', email: adminEmail, password: 'Password123' })
      .expect(201);
    orgIds.push(reg.body.user.organizationId);
    adminToken = reg.body.accessToken;
    adminId = reg.body.user.id;

    const created = await http()
      .post('/api/v1/users')
      .set(auth(adminToken))
      .send({ fullName: 'Analista', email: analystEmail, password: 'Password123', role: 'ANALYST' })
      .expect(201);
    analystId = created.body.id;
  });

  afterAll(async () => {
    await prisma.organization.deleteMany({ where: { id: { in: orgIds } } });
    await app.close();
  });

  it('el listado de usuarios incluye la fecha del último cambio de contraseña y nunca el hash', async () => {
    const res = await http().get('/api/v1/users').set(auth(adminToken)).expect(200);
    expect(res.body).toHaveLength(2);
    expect(res.body[0]).toHaveProperty('passwordChangedAt', null);
    expect(JSON.stringify(res.body)).not.toContain('passwordHash');
  });

  it('cambiar mi contraseña exige la actual y responde 400 (no 401) si es incorrecta', async () => {
    const t = (await login(analystEmail, 'Password123').expect(200)).body.accessToken;
    await http().patch('/api/v1/auth/me/password').set(auth(t)).send({ currentPassword: 'Incorrecta1', newPassword: 'NuevaClave2026' }).expect(400);
    await http().patch('/api/v1/auth/me/password').set(auth(t)).send({ currentPassword: 'Password123', newPassword: 'Password123' }).expect(400);
    await http().patch('/api/v1/auth/me/password').set(auth(t)).send({ currentPassword: 'Password123', newPassword: 'corta' }).expect(400);
    // La sesión sigue siendo válida tras los intentos fallidos.
    await http().get('/api/v1/auth/me').set(auth(t)).expect(200);
  });

  it('al cambiar mi contraseña se cierran las demás sesiones y la actual recibe un token nuevo', async () => {
    const other = (await login(analystEmail, 'Password123').expect(200)).body.accessToken;
    const current = (await login(analystEmail, 'Password123').expect(200)).body.accessToken;

    const res = await http()
      .patch('/api/v1/auth/me/password')
      .set(auth(current))
      .send({ currentPassword: 'Password123', newPassword: 'NuevaClave2026' })
      .expect(200);
    expect(res.body.accessToken).toBeTruthy();
    expect(res.body.user.email).toBe(analystEmail);

    await http().get('/api/v1/auth/me').set(auth(other)).expect(401);
    await http().get('/api/v1/auth/me').set(auth(current)).expect(401);
    await http().get('/api/v1/auth/me').set(auth(res.body.accessToken)).expect(200);

    await login(analystEmail, 'Password123').expect(401);
    await login(analystEmail, 'NuevaClave2026').expect(200);

    const list = await http().get('/api/v1/users').set(auth(adminToken)).expect(200);
    expect(list.body.find((u: { id: string }) => u.id === analystId).passwordChangedAt).toBeTruthy();
  });

  it('un ADMIN restablece la contraseña de otro usuario y cierra sus sesiones', async () => {
    const analystSession = (await login(analystEmail, 'NuevaClave2026').expect(200)).body.accessToken;

    // Un analista no puede restablecer contraseñas.
    await http().post(`/api/v1/users/${adminId}/reset-password`).set(auth(analystSession)).send({ newPassword: 'Temporal2026' }).expect(403);
    // El ADMIN no puede usarlo sobre su propia cuenta.
    await http().post(`/api/v1/users/${adminId}/reset-password`).set(auth(adminToken)).send({ newPassword: 'Temporal2026' }).expect(400);
    // La política de contraseñas se aplica.
    await http().post(`/api/v1/users/${analystId}/reset-password`).set(auth(adminToken)).send({ newPassword: 'debil' }).expect(400);

    const res = await http().post(`/api/v1/users/${analystId}/reset-password`).set(auth(adminToken)).send({ newPassword: 'Temporal2026' }).expect(200);
    expect(res.body).toMatchObject({ id: analystId, email: analystEmail });
    expect(res.body).not.toHaveProperty('passwordHash');

    await http().get('/api/v1/auth/me').set(auth(analystSession)).expect(401);
    await login(analystEmail, 'NuevaClave2026').expect(401);
    await login(analystEmail, 'Temporal2026').expect(200);
    // La sesión del ADMIN no se ve afectada.
    await http().get('/api/v1/auth/me').set(auth(adminToken)).expect(200);
  });

  it('un ADMIN no puede restablecer contraseñas de otra organización', async () => {
    const other = await http()
      .post('/api/v1/auth/register')
      .send({ organizationName: `Pw Org B ${suffix}`, fullName: 'Beto', email: `pw-b-${suffix}@test.local`, password: 'Password123' })
      .expect(201);
    orgIds.push(other.body.user.organizationId);
    await http().post(`/api/v1/users/${analystId}/reset-password`).set(auth(other.body.accessToken)).send({ newPassword: 'Temporal2026' }).expect(404);
    await login(analystEmail, 'Temporal2026').expect(200);
  });

  it('desactivar un usuario corta su sesión de inmediato y cambiar su rol se aplica al instante', async () => {
    const t = (await login(analystEmail, 'Temporal2026').expect(200)).body.accessToken;
    await http().patch(`/api/v1/users/${analystId}`).set(auth(adminToken)).send({ role: 'VIEWER' }).expect(200);
    await http().post('/api/v1/assets').set(auth(t)).send({ value: 'example.org', authorizationConfirmed: true }).expect(403);

    await http().patch(`/api/v1/users/${analystId}`).set(auth(adminToken)).send({ isActive: false }).expect(200);
    await http().get('/api/v1/auth/me').set(auth(t)).expect(401);
    await login(analystEmail, 'Temporal2026').expect(401);
  });
});
