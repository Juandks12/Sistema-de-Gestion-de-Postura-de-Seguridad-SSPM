import { ConfigService } from '@nestjs/config';
import { CryptoVaultService } from './crypto-vault.service';

describe('CryptoVaultService', () => {
  let service: CryptoVaultService;
  let configMock: { get: jest.Mock };

  beforeEach(() => {
    configMock = {
      get: jest.fn((key: string) => {
        if (key === 'CLOUD_CREDENTIALS_ENCRYPTION_KEY') return 'super-secret-key-32-bytes-length!';
        return null;
      }),
    };
    service = new CryptoVaultService(configMock as any);
  });

  it('cifra y descifra correctamente un texto plano con AES-256-GCM', () => {
    const secret = 'mi-secreto-azure-client-secret-12345';
    const encrypted = service.encrypt(secret);

    expect(encrypted).not.toBe(secret);
    expect(encrypted.split(':')).toHaveLength(3);

    const decrypted = service.decrypt(encrypted);
    expect(decrypted).toBe(secret);
  });

  it('cifra y descifra objetos JSON preservando tipos y propiedades', () => {
    const creds = {
      clientId: '84b72619-3321-4f11-9a71-8c4d2919aa01',
      clientSecret: 'secret-xyz-token-abc',
      subscriptionId: '1234-5678-9012',
    };

    const encrypted = service.encryptJson(creds);
    const decrypted = service.decryptJson<typeof creds>(encrypted);

    expect(decrypted).toEqual(creds);
    expect(decrypted.clientId).toBe(creds.clientId);
    expect(decrypted.clientSecret).toBe(creds.clientSecret);
  });

  it('falla al descifrar si el payload o el auth tag ha sido alterado (integridad GCM)', () => {
    const encrypted = service.encrypt('texto-protegido');
    const [iv, authTag, cipher] = encrypted.split(':');

    // Alterar un byte del authTag
    const tamperedTag = 'ff' + authTag.slice(2);
    const tamperedPayload = `${iv}:${tamperedTag}:${cipher}`;

    expect(() => service.decrypt(tamperedPayload)).toThrow();
  });

  it('lanza error al intentar cifrar o descifrar cadenas vacías', () => {
    expect(() => service.encrypt('')).toThrow('No se puede cifrar una cadena vacía');
    expect(() => service.decrypt('')).toThrow('No se puede descifrar una cadena vacía');
  });

  it('lanza error con formato de payload inválido', () => {
    expect(() => service.decrypt('payload-sin-separadores')).toThrow('Formato de carga cifrada inválido');
  });
});
