import { base32Decode, base32Encode, generateRecoveryCode, generateTotpSecret, hotpCode, normalizeRecoveryCode, otpauthUrl, totpCode, verifyTotp } from './totp';

describe('base32', () => {
  it('codifica y decodifica (RFC 4648)', () => {
    expect(base32Encode(Buffer.from('foobar'))).toBe('MZXW6YTBOI');
    expect(base32Decode('MZXW6YTBOI').toString()).toBe('foobar');
    expect(base32Decode('mzxw6ytboi======').toString()).toBe('foobar');
    expect(() => base32Decode('ABC1')).toThrow(/base32/);
  });
});

describe('hotp / totp', () => {
  // RFC 4226, apéndice D: secreto "12345678901234567890".
  const secret = base32Encode(Buffer.from('12345678901234567890'));

  it('reproduce los vectores de prueba de HOTP (RFC 4226)', () => {
    const expected = ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'];
    expected.forEach((code, counter) => expect(hotpCode(secret, counter)).toBe(code));
  });

  it('reproduce los vectores de prueba de TOTP con SHA-1 (RFC 6238)', () => {
    // La tabla del RFC usa 8 dígitos; los 6 nuestros son el sufijo.
    const vectors: Array<[number, string]> = [
      [59, '94287082'],
      [1111111109, '07081804'],
      [1111111111, '14050471'],
      [1234567890, '89005924'],
      [2000000000, '69279037'],
      [20000000000, '65353130'],
    ];
    for (const [seconds, code8] of vectors) {
      expect(totpCode(secret, seconds * 1000, 30, 8)).toBe(code8);
      expect(totpCode(secret, seconds * 1000)).toBe(code8.slice(2));
    }
  });

  it('admite un desfase de un paso y rechaza códigos mal formados o lejanos', () => {
    const now = 1111111111 * 1000;
    expect(verifyTotp(secret, totpCode(secret, now), now)).toBe(true);
    expect(verifyTotp(secret, totpCode(secret, now - 30000), now)).toBe(true);
    expect(verifyTotp(secret, totpCode(secret, now + 30000), now)).toBe(true);
    expect(verifyTotp(secret, totpCode(secret, now - 90000), now)).toBe(false);
    expect(verifyTotp(secret, '12 34 56'.slice(0, 6), now)).toBe(false);
    expect(verifyTotp(secret, 'abcdef', now)).toBe(false);
    expect(verifyTotp(secret, '1234567', now)).toBe(false);
  });

  it('genera secretos base32 de 32 caracteres y URLs otpauth correctas', () => {
    const secret2 = generateTotpSecret();
    expect(secret2).toMatch(/^[A-Z2-7]{32}$/);
    const url = otpauthUrl('SSPM', 'ana@empresa.com', secret2);
    expect(url).toBe(
      `otpauth://totp/SSPM:ana%40empresa.com?secret=${secret2}&issuer=SSPM&algorithm=SHA1&digits=6&period=30`,
    );
  });

  it('genera códigos de recuperación legibles y los normaliza', () => {
    const code = generateRecoveryCode();
    expect(code).toMatch(/^[A-Z2-7]{5}-[A-Z2-7]{5}$/);
    expect(normalizeRecoveryCode(' k7q2m-9xh4d ')).toBe('K7Q2M9XH4D');
  });
});
