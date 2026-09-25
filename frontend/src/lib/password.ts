/** Misma política que el backend (backend/src/common/validators/password.ts). */
export const PASSWORD_RULES = [
  { id: 'length', label: 'Al menos 8 caracteres', test: (v: string) => v.length >= 8 && v.length <= 72 },
  { id: 'lower', label: 'Una letra minúscula', test: (v: string) => /[a-z]/.test(v) },
  { id: 'upper', label: 'Una letra mayúscula', test: (v: string) => /[A-Z]/.test(v) },
  { id: 'digit', label: 'Un número', test: (v: string) => /\d/.test(v) },
] as const;

export function isStrongPassword(value: string): boolean {
  return PASSWORD_RULES.every((r) => r.test(value));
}

/** Genera una contraseña temporal que cumple la política, con el generador criptográfico del navegador. */
export function generatePassword(length = 14): string {
  const lower = 'abcdefghijkmnopqrstuvwxyz';
  const upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  const digits = '23456789';
  const all = lower + upper + digits;
  const pick = (set: string) => set[crypto.getRandomValues(new Uint32Array(1))[0] % set.length];
  const chars = [pick(lower), pick(upper), pick(digits)];
  while (chars.length < length) chars.push(pick(all));
  for (let i = chars.length - 1; i > 0; i -= 1) {
    const j = crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join('');
}
