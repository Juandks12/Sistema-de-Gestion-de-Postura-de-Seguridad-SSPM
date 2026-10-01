import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createHash } from 'node:crypto';
import { PrismaService } from '../prisma/prisma.service';

/** Clave del contador: hash del correo normalizado (no se guarda el correo en claro). */
export function loginAttemptKey(email: string): string {
  return createHash('sha256').update(email.trim().toLowerCase()).digest('hex');
}

export interface FailureState {
  failures: number;
  lockedUntil: Date | null;
}

/**
 * Siguiente estado tras un intento fallido. Función pura.
 * - Un bloqueo vencido o fallos antiguos (más viejos que la ventana) reinician la cuenta.
 * - Al llegar a `maxFailures` se bloquea durante `lockoutMs`.
 */
export function nextFailureState(
  previous: (FailureState & { updatedAt: Date }) | null,
  now: Date,
  maxFailures: number,
  lockoutMs: number,
): FailureState {
  const expiredLock = previous?.lockedUntil && previous.lockedUntil.getTime() <= now.getTime();
  const stale = previous && !previous.lockedUntil && now.getTime() - previous.updatedAt.getTime() > lockoutMs;
  const failures = !previous || expiredLock || stale ? 1 : previous.failures + 1;
  if (failures >= maxFailures) {
    return { failures, lockedUntil: new Date(now.getTime() + lockoutMs) };
  }
  return { failures, lockedUntil: null };
}

/**
 * Protección contra fuerza bruta por cuenta (sección 11.1). El estado vive en
 * PostgreSQL, así que funciona con varias instancias de la API, y se aplica
 * igual a correos que no existen para no revelar qué cuentas están registradas.
 */
@Injectable()
export class LoginProtectionService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
  ) {}

  private get maxFailures(): number {
    return this.config.get<number>('AUTH_MAX_FAILED_LOGINS') ?? 5;
  }

  private get lockoutMs(): number {
    return (this.config.get<number>('AUTH_LOCKOUT_MINUTES') ?? 15) * 60 * 1000;
  }

  /** Lanza 429 si la cuenta está bloqueada, antes de comprobar la contraseña. */
  async assertNotLocked(email: string): Promise<void> {
    const row = await this.prisma.loginAttempt.findUnique({ where: { key: loginAttemptKey(email) } });
    const now = Date.now();
    if (row?.lockedUntil && row.lockedUntil.getTime() > now) {
      const minutes = Math.max(1, Math.ceil((row.lockedUntil.getTime() - now) / 60000));
      throw new HttpException(
        {
          statusCode: HttpStatus.TOO_MANY_REQUESTS,
          error: 'Too Many Requests',
          message: `Demasiados intentos fallidos. Por seguridad la cuenta está bloqueada temporalmente; vuelve a intentarlo en ${minutes} minuto(s).`,
          retryAfterSeconds: Math.ceil((row.lockedUntil.getTime() - now) / 1000),
        },
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }
  }

  async recordFailure(email: string): Promise<FailureState> {
    const key = loginAttemptKey(email);
    const now = new Date();
    const previous = await this.prisma.loginAttempt.findUnique({ where: { key } });
    const next = nextFailureState(previous, now, this.maxFailures, this.lockoutMs);
    await this.prisma.loginAttempt.upsert({
      where: { key },
      create: { key, ...next },
      update: next,
    });
    return next;
  }

  async reset(email: string): Promise<void> {
    await this.prisma.loginAttempt.deleteMany({ where: { key: loginAttemptKey(email) } });
  }
}
