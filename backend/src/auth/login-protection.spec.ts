import { loginAttemptKey, nextFailureState } from './login-protection.service';

describe('protección del inicio de sesión', () => {
  const now = new Date('2026-09-26T12:00:00Z');
  const lockout = 15 * 60 * 1000;
  const at = (msAgo: number) => new Date(now.getTime() - msAgo);

  it('la clave no depende de mayúsculas ni espacios y no contiene el correo', () => {
    expect(loginAttemptKey(' Admin@Demo.Local ')).toBe(loginAttemptKey('admin@demo.local'));
    expect(loginAttemptKey('admin@demo.local')).toMatch(/^[0-9a-f]{64}$/);
  });

  it('cuenta los fallos y bloquea al llegar al máximo', () => {
    let state = nextFailureState(null, now, 3, lockout);
    expect(state).toEqual({ failures: 1, lockedUntil: null });
    state = nextFailureState({ ...state, updatedAt: at(1000) }, now, 3, lockout);
    expect(state).toEqual({ failures: 2, lockedUntil: null });
    state = nextFailureState({ ...state, updatedAt: at(1000) }, now, 3, lockout);
    expect(state.failures).toBe(3);
    expect(state.lockedUntil?.getTime()).toBe(now.getTime() + lockout);
  });

  it('un bloqueo vencido empieza de cero', () => {
    const state = nextFailureState({ failures: 5, lockedUntil: at(1), updatedAt: at(lockout) }, now, 5, lockout);
    expect(state).toEqual({ failures: 1, lockedUntil: null });
  });

  it('los fallos antiguos no se acumulan indefinidamente', () => {
    const state = nextFailureState({ failures: 4, lockedUntil: null, updatedAt: at(lockout + 1) }, now, 5, lockout);
    expect(state).toEqual({ failures: 1, lockedUntil: null });
  });
});
