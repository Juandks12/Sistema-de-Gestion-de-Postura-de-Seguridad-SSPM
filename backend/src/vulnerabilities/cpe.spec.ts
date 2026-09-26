import { NmapPort } from '../scans/nmap/nmap.types';
import { detectSoftware, parseCpe } from './cpe';

const port = (service: NmapPort['service'], state = 'open'): NmapPort => ({ protocol: 'tcp', port: 22, state, service });

describe('cpe', () => {
  it('lee CPE 2.2 de Nmap y CPE 2.3', () => {
    expect(parseCpe('cpe:/a:openbsd:openssh:7.4p1')).toEqual({ part: 'a', vendor: 'openbsd', product: 'openssh', version: '7.4p1' });
    expect(parseCpe('cpe:2.3:a:apache:http_server:2.4.29:*:*:*:*:*:*:*')).toMatchObject({ product: 'http_server', version: '2.4.29' });
    expect(parseCpe('cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*')).toMatchObject({ version: null });
    expect(parseCpe('no es un cpe')).toBeNull();
  });

  it('identifica el software con versión de un puerto abierto', () => {
    const sw = detectSoftware(port({ name: 'ssh', product: 'OpenSSH', version: '7.4', cpe: ['cpe:/a:openbsd:openssh:7.4'] }));
    expect(sw).toMatchObject({
      key: 'openbsd:openssh',
      version: '7.4',
      label: 'OpenSSH',
      cpe: 'cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*',
      distroPackage: false,
    });
  });

  it('toma la versión del banner si el CPE no la trae', () => {
    const sw = detectSoftware(port({ name: 'http', product: 'nginx', version: '1.14.0', cpe: ['cpe:/a:igor_sysoev:nginx'] }));
    expect(sw).toMatchObject({ key: 'igor_sysoev:nginx', version: '1.14.0' });
  });

  it('marca los paquetes de distribución (backports)', () => {
    const sw = detectSoftware(
      port({ name: 'ssh', product: 'OpenSSH', version: '8.2p1 Ubuntu 4ubuntu0.5', extraInfo: 'Ubuntu Linux; protocol 2.0', cpe: ['cpe:/a:openbsd:openssh:8.2p1'] }),
    );
    expect(sw).toMatchObject({ version: '8.2p1', distroPackage: true });
  });

  it('ignora puertos cerrados, CPE de sistema operativo y servicios sin versión', () => {
    expect(detectSoftware(port({ name: 'ssh', cpe: ['cpe:/a:openbsd:openssh:7.4'] }, 'closed'))).toBeNull();
    expect(detectSoftware(port({ name: 'ssh', cpe: ['cpe:/o:linux:linux_kernel:4.15'] }))).toBeNull();
    expect(detectSoftware(port({ name: 'http', product: 'nginx', cpe: ['cpe:/a:igor_sysoev:nginx'] }))).toBeNull();
    expect(detectSoftware(port({ name: 'http', cpe: [] }))).toBeNull();
  });

  it('no usa versiones imprecisas del banner', () => {
    expect(detectSoftware(port({ name: 'postgresql', version: '9.6.0 or later', cpe: ['cpe:/a:postgresql:postgresql'] }))).toBeNull();
    expect(detectSoftware(port({ name: 'http', version: '2.4.X', cpe: ['cpe:/a:apache:http_server'] }))).toBeNull();
  });
});
