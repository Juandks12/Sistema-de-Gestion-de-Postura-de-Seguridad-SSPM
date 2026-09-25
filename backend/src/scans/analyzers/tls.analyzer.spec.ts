import { analyzeTls, TlsProbeInfo } from './tls.analyzer';

const now = new Date('2026-09-24T12:00:00Z');
const days = (n: number) => new Date(now.getTime() + n * 86400000).toISOString();

const healthy: TlsProbeInfo = {
  hostname: 'example.org',
  port: 443,
  protocol: 'TLSv1.3',
  cipher: 'TLS_AES_256_GCM_SHA384',
  authorized: true,
  authorizationError: null,
  hostnameError: null,
  legacyProtocolSupported: false,
  legacyProtocolNegotiated: null,
  chainLength: 3,
  certificate: {
    subject: 'CN=example.org',
    issuer: "CN=R3, O=Let's Encrypt",
    subjectAltName: 'DNS:example.org',
    validFrom: days(-30),
    validTo: days(60),
    serialNumber: '01',
    fingerprint256: 'AA:BB',
    keyType: 'rsa',
    keyBits: 2048,
    curve: null,
    signatureAlgorithm: 'sha256WithRSAEncryption',
    selfSigned: false,
  },
};

const ids = (info: TlsProbeInfo) => analyzeTls(info, now).map((f) => f.ruleId);

describe('analyzeTls', () => {
  it('no reporta nada con un certificado sano', () => {
    expect(ids(healthy)).toEqual([]);
  });

  it('clasifica la expiración por proximidad', () => {
    const withValidTo = (v: string) => ({ ...healthy, certificate: { ...healthy.certificate, validTo: v } });
    expect(ids(withValidTo(days(-1)))).toContain('TLS-EXPIRED');
    expect(ids(withValidTo(days(3)))).toContain('TLS-EXPIRING-7D');
    expect(ids(withValidTo(days(20)))).toContain('TLS-EXPIRING-30D');
    expect(ids(withValidTo(days(40)))).toEqual([]);
  });

  it('detecta certificados aún no válidos', () => {
    expect(ids({ ...healthy, certificate: { ...healthy.certificate, validFrom: days(2) } })).toContain('TLS-NOT-YET-VALID');
  });

  it('detecta cadenas no confiables, nombre incorrecto y protocolos antiguos', () => {
    const result = ids({
      ...healthy,
      authorized: false,
      authorizationError: 'DEPTH_ZERO_SELF_SIGNED_CERT',
      hostnameError: "Hostname/IP does not match certificate's altnames",
      legacyProtocolSupported: true,
      legacyProtocolNegotiated: 'TLSv1',
    });
    expect(result).toEqual(expect.arrayContaining(['TLS-UNTRUSTED-CHAIN', 'TLS-HOSTNAME-MISMATCH', 'TLS-LEGACY-PROTOCOL']));
  });

  it('no confunde un certificado caducado con una cadena no confiable', () => {
    const result = ids({
      ...healthy,
      authorized: false,
      authorizationError: 'CERT_HAS_EXPIRED',
      certificate: { ...healthy.certificate, validTo: days(-5) },
    });
    expect(result).toContain('TLS-EXPIRED');
    expect(result).not.toContain('TLS-UNTRUSTED-CHAIN');
  });

  it('detecta claves y firmas débiles', () => {
    expect(ids({ ...healthy, certificate: { ...healthy.certificate, keyBits: 1024 } })).toContain('TLS-WEAK-KEY');
    expect(ids({ ...healthy, certificate: { ...healthy.certificate, keyType: 'ec', keyBits: 256, curve: 'prime256v1' } })).toEqual([]);
    expect(ids({ ...healthy, certificate: { ...healthy.certificate, signatureAlgorithm: 'sha1WithRSAEncryption' } })).toContain(
      'TLS-WEAK-SIGNATURE',
    );
  });
});
