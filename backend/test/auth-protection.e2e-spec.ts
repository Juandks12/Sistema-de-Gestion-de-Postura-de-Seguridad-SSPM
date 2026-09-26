import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { loginAttemptKey } from '../src/auth/login-protection.service';
import { PrismaClientExceptionFilter } from '../src/common/filters/prisma-exception.filter';
import { PrismaService } from '../src/prisma/prisma.service';

/**
 * Sección 11.1: protección contra fuerza bruta en el inicio de sesión y
 * contra el registro masivo de organizaciones.
 */
describe('Protección del inicio de sesión y del registro (e2e)', () => {
  let app: INestApplication;
  let prisma: PrismaService;
  const suffix = Date.now();
  const orgIds: string[] = [];
  const emails: string[] = [];
  let adminToken: string;
  const userEmail = `lock-user-${suffix}@test.local`;
  let userId: string;

  const http_ = () => request(app.getHttpServer());
  const login = (email: string, password: string) => http_().post('/api/v1/auth/login').send({ email, password });

  beforeAll(async () => {
    process.env.AUTH_MAX_FAILED_LOGINS = '3';
    process.env.AUTH_LOCKOUT_MINUTES = '15';
    process.env.AUTH_LOGIN_RATE_PER_MINUTE = '25';
    process.env.AUTH_REGISTER_RATE_PER_HOUR = '3';

    const { AppModule } = await import('../src/app.module');
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] }).compile();
    app = moduleRef.createNestApplication();
    app.setGlobalPrefix('api/v1');
    app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }));
    app.useGlobalFilters(new PrismaClientExceptionFilter());
    await app.init();
    prisma = app.get(PrismaService);

    const reg = await http_()
      .post('/api/v1/auth/register')
      .send({ organizationName: `Lock Org ${suffix}`, fullName: 'Admin', email: `lock-admin-${suffix}@test.local`, password: 'Password123' })
      .expect(201);
    orgIds.push(reg.body.user.organizationId);
    adminToken = reg.body.accessToken;
    userId = (
      await http_()
        .post('/api/v1/users')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ fullName: 'Usuario', email: userEmail, password: 'Password123', role: 'ANALYST' })
        .expect(201)
    ).body.id;
    emails.push(userEmail, `lock-admin-${suffix}@test.local`);
  });

  afterAll(async () => {
    await prisma.loginAttempt.deleteMany({ where: { key: { in: emails.map(loginAttemptKey) } } });
    await prisma.organization.deleteMany({ where: { id: { in: orgIds } } });
    await app.close();
  });

  it('un acierto reinicia el contador de fallos', async () => {
    await login(userEmail, 'Incorrecta1').expect(401);
    await login(userEmail, 'Incorrecta1').expect(401);
    await login(userEmail, 'Password123').expect(200);
    await login(userEmail, 'Incorrecta1').expect(401);
    await login(userEmail, 'Incorrecta1').expect(401);
    await login(userEmail, 'Password123').expect(200);
  });

  it('bloquea la cuenta tras varios fallos, incluso con la contraseña correcta', async () => {
    for (let i = 0; i < 3; i += 1) await login(userEmail, 'Incorrecta1').expect(401);
    const res = await login(userEmail, 'Password123').expect(429);
    expect(res.body.message).toContain('bloqueada temporalmente');
    expect(res.body.retryAfterSeconds).toBeGreaterThan(800);
  });

  it('se comporta igual con correos que no existen (no revela qué cuentas hay)', async () => {
    const ghost = `no-existe-${suffix}@test.local`;
    emails.push(ghost);
    for (let i = 0; i < 3; i += 1) {
      const r = await login(ghost, 'Incorrecta1').expect(401);
      expect(r.body.message).toBe('Credenciales inválidas');
    }
    const res = await login(ghost, 'Incorrecta1').expect(429);
    expect(res.body.message).toContain('bloqueada temporalmente');
  });

  it('una contraseña nueva asignada por el administrador desbloquea la cuenta', async () => {
    await http_()
      .post(`/api/v1/users/${userId}/reset-password`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ newPassword: 'NuevaClave123' })
      .expect(200);
    await login(userEmail, 'NuevaClave123').expect(200);
  });

  it('limita los registros de organizaciones por IP', async () => {
    const statuses: number[] = [];
    for (let i = 0; i < 3; i += 1) {
      const email = `lock-reg-${i}-${suffix}@test.local`;
      const res = await http_()
        .post('/api/v1/auth/register')
        .send({ organizationName: `Lock Reg ${i} ${suffix}`, fullName: 'Registro', email, password: 'Password123' });
      statuses.push(res.status);
      if (res.status === 201) orgIds.push(res.body.user.organizationId);
    }
    // El registro del beforeAll ya consumió uno de los 3 permitidos por hora.
    expect(statuses).toEqual([201, 201, 429]);
  });

  it('limita los intentos de inicio de sesión por IP', async () => {
    const statuses: number[] = [];
    for (let i = 0; i < 25; i += 1) {
      const email = `rate-${i}-${suffix}@test.local`;
      emails.push(email);
      const res = await login(email, 'Incorrecta1');
      statuses.push(res.status);
      if (res.status === 429) {
        expect(res.body.message).toContain('Demasiadas solicitudes');
        break;
      }
    }
    expect(statuses).toContain(429);
  });
});
