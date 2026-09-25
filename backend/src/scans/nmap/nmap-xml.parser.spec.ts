import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { NmapParseError, parseNmapXml } from './nmap-xml.parser';

describe('parseNmapXml', () => {
  const xml = readFileSync(join(__dirname, '__fixtures__', 'localhost-scan.xml'), 'utf8');

  it('extrae metadatos de la ejecución', () => {
    const result = parseNmapXml(xml);
    expect(result.scanner).toBe('nmap');
    expect(result.version).toBe('7.94SVN');
    expect(result.args).toContain('-sV');
    expect(result.hostsUp).toBe(1);
    expect(result.exit).toBe('success');
    expect(result.elapsedSeconds).toBeGreaterThan(0);
    expect(result.startedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it('extrae puertos ordenados con estado, servicio, producto, versión y CPE', () => {
    const [host] = parseNmapXml(xml).hosts;
    expect(host.status).toBe('up');
    expect(host.addresses).toContainEqual({ addr: '127.0.0.1', type: 'ipv4' });
    expect(host.ports.map((p) => p.port)).toEqual([22, 5432, 8089, 9999]);

    const pg = host.ports.find((p) => p.port === 5432)!;
    expect(pg).toMatchObject({ protocol: 'tcp', state: 'open', reason: 'syn-ack' });
    expect(pg.service).toMatchObject({
      name: 'postgresql',
      product: 'PostgreSQL DB',
      version: '9.6.0 or later',
      method: 'probed',
      confidence: 10,
      cpe: ['cpe:/a:postgresql:postgresql'],
    });

    const http = host.ports.find((p) => p.port === 8089)!;
    expect(http.service).toMatchObject({ name: 'http', extraInfo: 'Python 3.11.15' });

    const ssh = host.ports.find((p) => p.port === 22)!;
    expect(ssh.state).toBe('closed');
    expect(ssh.service?.cpe).toEqual([]);
  });

  it('no conserva la huella de servicio (servicefp)', () => {
    expect(JSON.stringify(parseNmapXml(xml))).not.toContain('SF-Port');
  });

  it('maneja un host sin puertos y agrupaciones extraports', () => {
    const minimal = `<?xml version="1.0"?>
      <nmaprun scanner="nmap" version="7.94" start="1700000000">
        <host><status state="up" reason="user-set"/><address addr="203.0.113.10" addrtype="ipv4"/>
          <ports><extraports state="filtered" count="1000"/></ports></host>
        <runstats><finished time="1700000010" elapsed="10.00" exit="success"/><hosts up="1" down="0" total="1"/></runstats>
      </nmaprun>`;
    const [host] = parseNmapXml(minimal).hosts;
    expect(host.ports).toEqual([]);
    expect(host.extraPorts).toEqual([{ state: 'filtered', count: 1000 }]);
  });

  it('rechaza salidas que no son XML de Nmap', () => {
    expect(() => parseNmapXml('')).toThrow(NmapParseError);
    expect(() => parseNmapXml('Starting Nmap...')).toThrow(NmapParseError);
  });
});
