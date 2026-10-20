import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // 96 bits recomendado para GCM
const AUTH_TAG_LENGTH = 16; // 128 bits
const SALT = 'sspm-cloud-crypto-vault-salt-v1';

@Injectable()
export class CryptoVaultService {
  private readonly logger = new Logger(CryptoVaultService.name);
  private readonly encryptionKey: Buffer;

  constructor(private readonly config: ConfigService) {
    const rawKey = this.config.get<string>('CLOUD_CREDENTIALS_ENCRYPTION_KEY')
      || this.config.get<string>('JWT_SECRET')
      || 'sspm-default-fallback-insecure-key-do-not-use-in-production';

    if (rawKey.includes('default-fallback')) {
      this.logger.warn(
        'CLOUD_CREDENTIALS_ENCRYPTION_KEY no está configurada en el entorno. ' +
        'Usando clave derivada de fallback (insegura para producción).',
      );
    }

    // Derivar clave de 256 bits (32 bytes) usando scrypt
    this.encryptionKey = scryptSync(rawKey, SALT, 32);
  }

  /**
   * Cifra un texto en claro usando AES-256-GCM.
   * Retorna una cadena con formato: ivHex:authTagHex:cipherHex
   */
  encrypt(plaintext: string): string {
    if (!plaintext) {
      throw new Error('No se puede cifrar una cadena vacía o nula.');
    }

    const iv = randomBytes(IV_LENGTH);
    const cipher = createCipheriv(ALGORITHM, this.encryptionKey, iv, {
      authTagLength: AUTH_TAG_LENGTH,
    });

    const encrypted = Buffer.concat([
      cipher.update(plaintext, 'utf8'),
      cipher.final(),
    ]);

    const authTag = cipher.getAuthTag();

    return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted.toString('hex')}`;
  }

  /**
   * Descifra una cadena previamente cifrada con format: ivHex:authTagHex:cipherHex.
   */
  decrypt(encryptedPayload: string): string {
    if (!encryptedPayload) {
      throw new Error('No se puede descifrar una cadena vacía o nula.');
    }

    const parts = encryptedPayload.split(':');
    if (parts.length !== 3) {
      throw new Error('Formato de carga cifrada inválido. Se esperaba iv:authTag:ciphertext');
    }

    const [ivHex, authTagHex, cipherHex] = parts;
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');
    const cipherBuffer = Buffer.from(cipherHex, 'hex');

    if (iv.length !== IV_LENGTH || authTag.length !== AUTH_TAG_LENGTH) {
      throw new Error('Longitud de IV o AuthTag no coincide con los parámetros requeridos por AES-256-GCM');
    }

    const decipher = createDecipheriv(ALGORITHM, this.encryptionKey, iv, {
      authTagLength: AUTH_TAG_LENGTH,
    });
    decipher.setAuthTag(authTag);

    const decrypted = Buffer.concat([
      decipher.update(cipherBuffer),
      decipher.final(),
    ]);

    return decrypted.toString('utf8');
  }

  /**
   * Cifra un objeto serializable en JSON.
   */
  encryptJson(data: unknown): string {
    const jsonStr = JSON.stringify(data);
    return this.encrypt(jsonStr);
  }

  /**
   * Descifra una cadena y parsea el objeto JSON resultante.
   */
  decryptJson<T = unknown>(encryptedPayload: string): T {
    const jsonStr = this.decrypt(encryptedPayload);
    return JSON.parse(jsonStr) as T;
  }
}
