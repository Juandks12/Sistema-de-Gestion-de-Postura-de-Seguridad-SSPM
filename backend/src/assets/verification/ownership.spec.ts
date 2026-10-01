import {
  dnsProofDomains,
  dnsRecordName,
  expectedProof,
  fileContentMatches,
  isCoveredBy,
  txtRecordsContain,
} from './ownership';

describe('verificación de propiedad', () => {
  const proof = expectedProof('abc123');

  it('construye el valor a publicar', () => {
    expect(proof).toBe('sspm-verification=abc123');
    expect(dnsRecordName('example.com')).toBe('_sspm-verification.example.com');
  });

  it('busca la prueba DNS del dominio más específico al más general, sin bajar de dos etiquetas', () => {
    expect(dnsProofDomains('a.tienda.example.com')).toEqual(['a.tienda.example.com', 'tienda.example.com', 'example.com']);
    expect(dnsProofDomains('Example.COM.')).toEqual(['example.com']);
    expect(dnsProofDomains('localhost')).toEqual([]);
  });

  it('une los fragmentos de un registro TXT y exige coincidencia exacta', () => {
    expect(txtRecordsContain([['v=spf1 -all'], ['sspm-verification=', 'abc123']], proof)).toBe(true);
    expect(txtRecordsContain([[' sspm-verification=abc123 ']], proof)).toBe(true);
    expect(txtRecordsContain([['sspm-verification=abc1234']], proof)).toBe(false);
    expect(txtRecordsContain([['otro sspm-verification=abc123']], proof)).toBe(false);
    expect(txtRecordsContain([], proof)).toBe(false);
  });

  it('el archivo debe contener solo la prueba', () => {
    expect(fileContentMatches('sspm-verification=abc123\n', proof)).toBe(true);
    expect(fileContentMatches('<html>sspm-verification=abc123</html>', proof)).toBe(false);
  });

  it('un dominio verificado cubre sus subdominios, no dominios parecidos', () => {
    expect(isCoveredBy('www.example.com', 'example.com')).toBe(true);
    expect(isCoveredBy('example.com', 'example.com')).toBe(true);
    expect(isCoveredBy('evil-example.com', 'example.com')).toBe(false);
    expect(isCoveredBy('example.com.evil.io', 'example.com')).toBe(false);
    expect(isCoveredBy('example.com', 'www.example.com')).toBe(false);
  });
});
