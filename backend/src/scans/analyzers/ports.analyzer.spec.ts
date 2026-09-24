import { NmapPort } from '../nmap/nmap.types';
import { analyzePorts } from './ports.analyzer';

const port = (p: number, state = 'open', name?: string, product?: string, version?: string): NmapPort => ({
  protocol: 'tcp',
  port: p,
  state,
  service: { name, product, version, cpe: [] },
});

describe('analyzePorts', () => {
  it('ignora los puertos cerrados o filtrados', () => {
    expect(analyzePorts([port(22, 'closed', 'ssh'), port(80, 'filtered', 'http')])).toEqual([]);
  });

  it('clasifica los servicios por riesgo', () => {
    const findings = analyzePorts([
      port(23, 'open', 'telnet'),
      port(3306, 'open', 'mysql', 'MySQL', '5.7.33'),
      port(3389, 'open', 'ms-wbt-server'),
      port(2375, 'open', 'docker'),
      port(443, 'open', 'http', 'nginx'),
      port(9999, 'open', 'abyss'),
    ]);
    const byPort = Object.fromEntries(findings.map((f) => [f.location, f.ruleId]));
    expect(byPort).toEqual({
      'tcp/23': 'SVC-CLEARTEXT-REMOTE-ADMIN',
      'tcp/3306': 'SVC-DATABASE-EXPOSED',
      'tcp/3389': 'SVC-REMOTE-DESKTOP',
      'tcp/2375': 'SVC-ORCHESTRATION-EXPOSED',
      'tcp/443': 'SVC-OPEN-PORT',
      'tcp/9999': 'SVC-OPEN-PORT',
    });
  });

  it('clasifica por nombre de servicio aunque el puerto no sea el estándar', () => {
    expect(analyzePorts([port(15432, 'open', 'postgresql')])[0].ruleId).toBe('SVC-DATABASE-EXPOSED');
  });

  it('incluye producto y versión en el título y la evidencia', () => {
    const [finding] = analyzePorts([port(3306, 'open', 'mysql', 'MySQL', '5.7.33')]);
    expect(finding.title).toBe('mysql (MySQL 5.7.33) expuesto en el puerto 3306/tcp');
    expect(finding.evidence).toMatchObject({ port: 3306, product: 'MySQL', version: '5.7.33' });
  });
});
