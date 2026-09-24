import { buildNmapArgs } from './nmap-args';
import { NmapProfile } from './nmap.types';

const profile: NmapProfile = { topPorts: 1000, timing: 4, hostTimeoutSeconds: 585 };

describe('buildNmapArgs', () => {
  it('genera un escaneo TCP connect con detección de versiones y salida XML', () => {
    const args = buildNmapArgs('45.33.32.156', profile);
    expect(args).toEqual(
      expect.arrayContaining(['-sT', '-sV', '-Pn', '-n', '-T4', '--top-ports', '1000']),
    );
    expect(args.slice(-3)).toEqual(['-oX', '-', '45.33.32.156']);
    expect(args).toContain('585s');
  });

  it('usa la lista explícita de puertos cuando está definida', () => {
    const args = buildNmapArgs('45.33.32.156', { ...profile, ports: '22,80,443' });
    expect(args).toEqual(expect.arrayContaining(['-p', '22,80,443']));
    expect(args).not.toContain('--top-ports');
  });

  it('añade -6 para objetivos IPv6', () => {
    expect(buildNmapArgs('2606:4700:4700::1111', profile)).toContain('-6');
    expect(buildNmapArgs('1.1.1.1', profile)).not.toContain('-6');
  });

  it('rechaza objetivos que no son una IP literal (prevención de inyección)', () => {
    for (const target of ['example.com', '-oN /tmp/x', '1.1.1.1; rm -rf /', '']) {
      expect(() => buildNmapArgs(target, profile)).toThrow();
    }
  });
});
