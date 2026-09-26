import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { AuditService } from '../src/audit/audit.service';
import { totpCode } from '../src/auth/totp';
import { PrismaClientExceptionFilter } from '../src/common/filters/prisma-exception.filter';
import { MailerService, OutgoingMail } from '../src/common/mail/mailer.service';
import { PrismaService } from '../src/prisma/prisma.service';

/** Buzón simulado: captura los correos de cuenta (restablecer, invitaciones). */
class FakeMailer {
  readonly sent: OutgoingMail[] = [];
  enabled = true;
  async send(mail: OutgoingMail) {
    this.sent.push(mail);
    return { ok: true, status: 'SENT' as const, detail: 'capturado' };
  }
  /** Último correo enviado a un destinatario. */
  lastTo(email: string): OutgoingMail | undefined {
    return [...this.sent].reverse().find((m) => (Array.isArray(m.to) ? m.to.includes(email) : m.to === email));
  }
  token(email: string): string {
    const mail = this.lastTo(email);
    const match = /token=([a-f0-9]{64})/.exec(mail?.text ?? '');
    if (!match) throw new Error(`No hay token en el correo a ${email}`);
    return match[1];
  }
}

/**
 * Bloque 3: registro de auditoría (RNF-06), recuperación de contraseña por
 * correo, invitaciones y verificación en dos pasos (TOTP).
 */
describe('Cuentas y auditoría (e2e)', () => {
  let app: INestApplication;
  let prisma: PrismaService;
  let audit: AuditService;
  const mailer = new FakeMailer();
  const suffix = Date.now();
  const orgIds: string[] = [];
  const adminEmail = `acc-admin-${suffix}@test.local`;
  const analystEmail = `acc-analyst-${suffix}@test.local`;
  let adminToken: string;
  let analystToken: string;
  let analystId: string;

  const http_ = () => request(app.getHttpServer());
  const auth = (t: string) => ({ Authorization: `Bearer ${t}` });
  const login = (email: string, password: string) => http_().post('/api/v1/auth/login').send({ email, password });

  const auditRows = async (params: Record<string, string> = {}) => {
    await audit.flush();
    const res = await http_().get('/api/v1/audit-log').query({ pageSize: 100, ...params }).set(auth(adminToken)).expect(200);
    return res.body.items as Array<{ action: string; actorEmail: string | null; targetLabel: string | null; ip: string | null; detail: Record<string, unknown> | null }>;
  };

  beforeAll(async () => {
    process.env.AUTH_FORGOT_RATE_PER_HOUR = '1000';
    const { AppModule } = await import('../src/app.module');
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(MailerService)
      .useValue(mailer)
      .compile();
    app = moduleRef.createNestApplication();
    app.setGlobalPrefix('api/v1');
    app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }));
    app.useGlobalFilters(new PrismaClientExceptionFilter());
    await app.init();
    prisma = app.get(PrismaService);
    audit = app.get(AuditService);

    const reg = await http_()
      .post('/api/v1/auth/register')
      .send({ organizationName: `Acc Org ${suffix}`, fullName: 'Ana Admin', email: adminEmail, password: 'Password123' })
      .expect(201);
    adminToken = reg.body.accessToken;
    orgIds.push(reg.body.user.organizationId);
    analystId = (
      await http_()
        .post('/api/v1/users')
        .set(auth(adminToken))
        .send({ fullName: 'Aldo Analista', email: analystEmail, password: 'Password123', role: 'ANALYST' })
        .expect(201)
    ).body.id;
    analystToken = (await login(analystEmail, 'Password123').expect(200)).body.accessToken;
  });

  afterAll(async () => {
    await audit.flush();
    await prisma.organization.deleteMany({ where: { id: { in: orgIds } } });
    await app.close();
  });

  describe('Registro de auditoría (RNF-06)', () => {
    it('registra las acciones con actor, objetivo e IP, y solo lo ve el ADMIN', async () => {
      await http_()
        .post('/api/v1/assets')
        .set(auth(analystToken))
        .send({ value: `activo-${suffix}.example.com`, authorizationConfirmed: true })
        .expect(201);

      const rows = await auditRows();
      const actions = rows.map((r) => r.action);
      expect(actions).toEqual(expect.arrayContaining(['auth.register', 'auth.login', 'user.create', 'asset.create']));
      const assetRow = rows.find((r) => r.action === 'asset.create')!;
      expect(assetRow.actorEmail).toBe(analystEmail);
      expect(assetRow.targetLabel).toBe(`activo-${suffix}.example.com`);
      expect(assetRow.ip).toBeTruthy();

      await http_().get('/api/v1/audit-log').set(auth(analystToken)).expect(403);
    });

    it('filtra por acción y por actor, y expone el catálogo', async () => {
      const byAction = await auditRows({ action: 'user.create' });
      expect(byAction.length).toBeGreaterThan(0);
      expect(byAction.every((r) => r.action === 'user.create')).toBe(true);

      const catalog = await http_().get('/api/v1/audit-log/actions').set(auth(adminToken)).expect(200);
      expect(catalog.body.actions['asset.create']).toBeDefined();
      expect(catalog.body.actions['auth.login']).toBeTruthy();

      await http_().get('/api/v1/audit-log').query({ action: 'no.existe' }).set(auth(adminToken)).expect(400);
    });
  });

  describe('Recuperación de contraseña por correo', () => {
    it('responde igual exista o no la cuenta y solo envía correo a las registradas', async () => {
      const before = mailer.sent.length;
      const unknown = await http_().post('/api/v1/auth/forgot-password').send({ email: `nadie-${suffix}@test.local` }).expect(202);
      const known = await http_().post('/api/v1/auth/forgot-password').send({ email: analystEmail }).expect(202);
      expect(unknown.body.message).toBe(known.body.message);
      expect(mailer.sent.length).toBe(before + 1);
      expect(mailer.lastTo(analystEmail)!.subject).toContain('Restablecer');
    });

    it('el token restablece la contraseña una sola vez y cierra las demás sesiones', async () => {
      const token = mailer.token(analystEmail);
      const res = await http_()
        .post('/api/v1/auth/reset-password')
        .send({ token, newPassword: 'ClaveNueva123' })
        .expect(200);
      expect(res.body.accessToken).toBeTruthy();

      // La sesión anterior queda revocada y la contraseña nueva funciona.
      await http_().get('/api/v1/auth/me').set(auth(analystToken)).expect(401);
      analystToken = (await login(analystEmail, 'ClaveNueva123').expect(200)).body.accessToken;
      await login(analystEmail, 'Password123').expect(401);

      // El mismo token no vale dos veces.
      await http_().post('/api/v1/auth/reset-password').send({ token, newPassword: 'OtraClave123' }).expect(400);
      const rows = await auditRows({ action: 'auth.password_reset' });
      expect(rows[0].actorEmail).toBe(analystEmail);
    });

    it('emitir un enlace nuevo caduca el anterior y valida la política de contraseñas', async () => {
      await http_().post('/api/v1/auth/forgot-password').send({ email: analystEmail }).expect(202);
      const first = mailer.token(analystEmail);
      await http_().post('/api/v1/auth/forgot-password').send({ email: analystEmail }).expect(202);
      const second = mailer.token(analystEmail);
      expect(second).not.toBe(first);
      await http_().post('/api/v1/auth/reset-password').send({ token: first, newPassword: 'ClaveNueva123' }).expect(400);
      await http_().post('/api/v1/auth/reset-password').send({ token: second, newPassword: 'corta' }).expect(400);
      await http_().post('/api/v1/auth/reset-password').send({ token: 'zz', newPassword: 'ClaveNueva123' }).expect(400);
      // Se canjea para no dejar tokens vivos al terminar la suite.
      await http_().post('/api/v1/auth/reset-password').send({ token: second, newPassword: 'ClaveNueva123' }).expect(200);
      analystToken = (await login(analystEmail, 'ClaveNueva123').expect(200)).body.accessToken;
    });
  });

  describe('Invitaciones', () => {
    const invited = `acc-invitada-${suffix}@test.local`;

    it('el ADMIN invita por correo y la invitación aparece como pendiente', async () => {
      const res = await http_().post('/api/v1/users/invitations').set(auth(adminToken)).send({ email: invited, role: 'VIEWER' }).expect(201);
      expect(res.body).toMatchObject({ email: invited, role: 'VIEWER', deliveryStatus: 'SENT' });
      expect(mailer.lastTo(invited)!.subject).toContain('te invita');

      const list = await http_().get('/api/v1/users/invitations').set(auth(adminToken)).expect(200);
      expect(list.body.items.map((i: { email: string }) => i.email)).toContain(invited);

      await http_().post('/api/v1/users/invitations').set(auth(analystToken)).send({ email: 'x@test.local', role: 'VIEWER' }).expect(403);
      await http_().post('/api/v1/users/invitations').set(auth(adminToken)).send({ email: analystEmail, role: 'VIEWER' }).expect(409);
    });

    it('reenviar genera un enlace nuevo y el anterior deja de valer', async () => {
      const oldToken = mailer.token(invited);
      const list = await http_().get('/api/v1/users/invitations').set(auth(adminToken)).expect(200);
      const id = list.body.items.find((i: { email: string }) => i.email === invited).id;
      await http_().post(`/api/v1/users/invitations/${id}/resend`).set(auth(adminToken)).expect(200);
      const fresh = mailer.token(invited);
      expect(fresh).not.toBe(oldToken);
      await http_().get('/api/v1/auth/invitations/info').query({ token: oldToken }).expect(404);
      const info = await http_().get('/api/v1/auth/invitations/info').query({ token: fresh }).expect(200);
      expect(info.body).toMatchObject({ email: invited, role: 'VIEWER', organizationName: `Acc Org ${suffix}` });
    });

    it('aceptar crea la cuenta con el rol invitado e inicia sesión; el token queda usado', async () => {
      const token = mailer.token(invited);
      const res = await http_()
        .post('/api/v1/auth/invitations/accept')
        .send({ token, fullName: 'Vera Viewer', password: 'Password123' })
        .expect(201);
      expect(res.body.user).toMatchObject({ email: invited, role: 'VIEWER' });
      await http_().get('/api/v1/auth/me').set(auth(res.body.accessToken)).expect(200);
      await http_().post('/api/v1/auth/invitations/accept').send({ token, fullName: 'Otra', password: 'Password123' }).expect(400);

      const pending = await http_().get('/api/v1/users/invitations').set(auth(adminToken)).expect(200);
      expect(pending.body.items.map((i: { email: string }) => i.email)).not.toContain(invited);
      const rows = await auditRows({ action: 'user.invite_accepted' });
      expect(rows[0].targetLabel).toBe(invited);
    });

    it('cancelar elimina la invitación pendiente', async () => {
      const other = `acc-cancelada-${suffix}@test.local`;
      const created = await http_().post('/api/v1/users/invitations').set(auth(adminToken)).send({ email: other, role: 'ANALYST' }).expect(201);
      await http_().delete(`/api/v1/users/invitations/${created.body.id}`).set(auth(adminToken)).expect(204);
      const token = mailer.token(other);
      await http_().get('/api/v1/auth/invitations/info').query({ token }).expect(404);
    });
  });

  describe('Verificación en dos pasos (TOTP)', () => {
    let secret: string;
    let recoveryCodes: string[];

    it('se activa confirmando el primer código y entrega códigos de recuperación', async () => {
      const setup = await http_().post('/api/v1/auth/me/mfa/setup').set(auth(analystToken)).expect(200);
      secret = setup.body.secret;
      expect(secret).toMatch(/^[A-Z2-7]{32}$/);
      expect(setup.body.otpauthUrl).toContain('otpauth://totp/SSPM');

      await http_().post('/api/v1/auth/me/mfa/enable').set(auth(analystToken)).send({ code: '000000' }).expect(400);
      const enabled = await http_()
        .post('/api/v1/auth/me/mfa/enable')
        .set(auth(analystToken))
        .send({ code: totpCode(secret) })
        .expect(200);
      recoveryCodes = enabled.body.recoveryCodes;
      expect(recoveryCodes).toHaveLength(10);
      expect((await http_().get('/api/v1/auth/me/mfa').set(auth(analystToken)).expect(200)).body).toMatchObject({
        enabled: true,
        recoveryCodesLeft: 10,
      });
    });

    it('el login pasa a dos pasos: contraseña y después el código', async () => {
      const first = await login(analystEmail, 'ClaveNueva123').expect(200);
      expect(first.body.mfaRequired).toBe(true);
      expect(first.body.accessToken).toBeUndefined();
      const mfaToken = first.body.mfaToken as string;

      // El token intermedio no vale como sesión.
      await http_().get('/api/v1/auth/me').set(auth(mfaToken)).expect(401);
      await http_().post('/api/v1/auth/login/mfa').send({ mfaToken, code: '123456' }).expect(401);
      const done = await http_().post('/api/v1/auth/login/mfa').send({ mfaToken, code: totpCode(secret) }).expect(200);
      analystToken = done.body.accessToken;
      await http_().get('/api/v1/auth/me').set(auth(analystToken)).expect(200);
    });

    it('los fallos del segundo paso cuentan para el bloqueo de la cuenta', async () => {
      const { mfaToken } = (await login(analystEmail, 'ClaveNueva123').expect(200)).body;
      for (let i = 0; i < 5; i += 1) {
        await http_().post('/api/v1/auth/login/mfa').send({ mfaToken, code: '999999' }).expect(401);
      }
      const locked = await http_().post('/api/v1/auth/login/mfa').send({ mfaToken, code: totpCode(secret) }).expect(429);
      expect(locked.body.message).toContain('bloqueada');
      await prisma.loginAttempt.deleteMany({});
    });

    it('un código de recuperación entra una sola vez', async () => {
      const { mfaToken } = (await login(analystEmail, 'ClaveNueva123').expect(200)).body;
      const code = recoveryCodes[0];
      const res = await http_().post('/api/v1/auth/login/mfa').send({ mfaToken, code }).expect(200);
      expect(res.body.accessToken).toBeTruthy();
      analystToken = res.body.accessToken;

      const again = (await login(analystEmail, 'ClaveNueva123').expect(200)).body;
      await http_().post('/api/v1/auth/login/mfa').send({ mfaToken: again.mfaToken, code }).expect(401);
      await prisma.loginAttempt.deleteMany({});
      expect((await http_().get('/api/v1/auth/me/mfa').set(auth(analystToken)).expect(200)).body.recoveryCodesLeft).toBe(9);
    });

    it('un ADMIN puede desactivar el MFA de otro usuario y queda auditado', async () => {
      await http_().post(`/api/v1/users/${analystId}/disable-mfa`).set(auth(analystToken)).expect(403);
      const res = await http_().post(`/api/v1/users/${analystId}/disable-mfa`).set(auth(adminToken)).expect(200);
      expect(res.body.mfaEnabled).toBe(false);
      const direct = await login(analystEmail, 'ClaveNueva123').expect(200);
      expect(direct.body.accessToken).toBeTruthy();
      analystToken = direct.body.accessToken;
      const rows = await auditRows({ action: 'user.mfa_disabled' });
      expect(rows[0]).toMatchObject({ actorEmail: adminEmail, targetLabel: analystEmail });
    });

    it('desactivar el propio MFA exige contraseña y código', async () => {
      const setup = await http_().post('/api/v1/auth/me/mfa/setup').set(auth(analystToken)).expect(200);
      await http_().post('/api/v1/auth/me/mfa/enable').set(auth(analystToken)).send({ code: totpCode(setup.body.secret) }).expect(200);
      await http_()
        .delete('/api/v1/auth/me/mfa')
        .set(auth(analystToken))
        .send({ password: 'Incorrecta1', code: totpCode(setup.body.secret) })
        .expect(400);
      await http_()
        .delete('/api/v1/auth/me/mfa')
        .set(auth(analystToken))
        .send({ password: 'ClaveNueva123', code: totpCode(setup.body.secret) })
        .expect(200);
      expect((await http_().get('/api/v1/auth/me/mfa').set(auth(analystToken)).expect(200)).body.enabled).toBe(false);
    });
  });
});
