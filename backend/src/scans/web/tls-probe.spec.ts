import { X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { AddressInfo } from 'node:net';
import { join } from 'node:path';
import * as tls from 'node:tls';
import { signatureAlgorithmFromDer, tcpPortOpen, tlsProbe } from './tls-probe';

const fixtures = join(__dirname, '..', '..', '..', 'test', 'fixtures', 'tls');
const key = readFileSync(join(fixtures, 'localhost-key.pem'));
const cert = readFileSync(join(fixtures, 'localhost-cert.pem'));

describe('tls-probe', () => {
  let server: tls.Server;
  let port: number;

  beforeAll(async () => {
    server = tls.createServer({ key, cert, minVersion: 'TLSv1.2' }, (socket) => socket.end());
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    port = (server.address() as AddressInfo).port;
  });

  afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

  it('extrae el algoritmo de firma del DER', () => {
    const x509 = new X509Certificate(cert);
    expect(signatureAlgorithmFromDer(x509.raw)).toBe('sha256WithRSAEncryption');
    expect(signatureAlgorithmFromDer(Buffer.from([0x01, 0x02]))).toBeNull();
  });

  it('describe el certificado, la cadena y la identidad del host', async () => {
    const outcome = await tlsProbe({
      address: '127.0.0.1',
      port,
      hostname: 'localhost',
      timeoutMs: 5000,
      signal: new AbortController().signal,
    });
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.info.protocol).toMatch(/^TLSv1\.[23]$/);
    expect(outcome.info.authorized).toBe(false);
    expect(outcome.info.authorizationError).toBe('DEPTH_ZERO_SELF_SIGNED_CERT');
    expect(outcome.info.hostnameError).toBeNull();
    expect(outcome.info.legacyProtocolSupported).toBe(false);
    expect(outcome.info.certificate).toMatchObject({
      keyType: 'rsa',
      keyBits: 2048,
      selfSigned: true,
      signatureAlgorithm: 'sha256WithRSAEncryption',
    });
    expect(outcome.info.certificate.subjectAltName).toContain('DNS:localhost');
  });

  it('detecta un nombre de host que no coincide con el certificado', async () => {
    const outcome = await tlsProbe({
      address: '127.0.0.1',
      port,
      hostname: 'otro.example.org',
      timeoutMs: 5000,
      signal: new AbortController().signal,
      checkLegacy: false,
    });
    expect(outcome.ok && outcome.info.hostnameError).toMatch(/does not match/);
  });

  it('informa de conexiones rechazadas', async () => {
    const closed = await tlsProbe({
      address: '127.0.0.1',
      port: 1,
      hostname: 'localhost',
      timeoutMs: 2000,
      signal: new AbortController().signal,
    });
    expect(closed.ok).toBe(false);
    expect(!closed.ok && closed.connectionRefused).toBe(true);
    await expect(tcpPortOpen('127.0.0.1', port, 2000)).resolves.toBe(true);
    await expect(tcpPortOpen('127.0.0.1', 1, 2000)).resolves.toBe(false);
  });
});
