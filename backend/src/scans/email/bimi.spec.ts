import { DnsClient } from '../../common/dns/dns-client';
import { isBimiRecord, lookupBimi, parseBimiTags } from './bimi';

describe('bimi', () => {
  let dnsMock: { txt: jest.Mock };

  beforeEach(() => {
    dnsMock = { txt: jest.fn() };
  });

  it('reconoce registros BIMI válidos', () => {
    expect(isBimiRecord('v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/cert.pem')).toBe(true);
    expect(isBimiRecord('v=bimi1; l=https://example.com/logo.svg;')).toBe(true);
    expect(isBimiRecord('v=spf1 include:_spf.google.com ~all')).toBe(false);
  });

  it('parsea las etiquetas de un registro BIMI', () => {
    const tags = parseBimiTags('v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/cert.pem');
    expect(tags.v).toBe('BIMI1');
    expect(tags.l).toBe('https://example.com/logo.svg');
    expect(tags.a).toBe('https://example.com/cert.pem');
  });

  it('retorna missing si la consulta DNS falla o no hay registros TXT', async () => {
    dnsMock.txt.mockRejectedValueOnce(new Error('ENOTFOUND'));
    const res = await lookupBimi('example.com', dnsMock as unknown as DnsClient);
    expect(res.status).toBe('missing');
  });

  it('valida exitosamente un registro BIMI conforme a especificación', async () => {
    dnsMock.txt.mockResolvedValueOnce([
      'v=BIMI1; l=https://cdn.example.com/branding/logo.svg; a=https://cdn.example.com/certs/vmc.pem',
    ]);
    const res = await lookupBimi('example.com', dnsMock as unknown as DnsClient);
    expect(res.status).toBe('valid');
    if (res.status === 'valid') {
      expect(res.record.location).toBe('https://cdn.example.com/branding/logo.svg');
      expect(res.record.authority).toBe('https://cdn.example.com/certs/vmc.pem');
    }
  });

  it('detecta error si l= no utiliza HTTPS seguro', async () => {
    dnsMock.txt.mockResolvedValueOnce([
      'v=BIMI1; l=http://insecure.example.com/logo.svg;',
    ]);
    const res = await lookupBimi('example.com', dnsMock as unknown as DnsClient);
    expect(res.status).toBe('invalid');
  });

  it('detecta error si hay múltiples registros BIMI en el mismo selector', async () => {
    dnsMock.txt.mockResolvedValueOnce([
      'v=BIMI1; l=https://example.com/logo1.svg;',
      'v=BIMI1; l=https://example.com/logo2.svg;',
    ]);
    const res = await lookupBimi('example.com', dnsMock as unknown as DnsClient);
    expect(res.status).toBe('invalid');
  });
});
