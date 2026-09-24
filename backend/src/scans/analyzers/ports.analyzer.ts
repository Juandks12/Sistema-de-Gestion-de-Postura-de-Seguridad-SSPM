import { NmapPort } from '../nmap/nmap.types';
import { FindingDraft } from '../scanner.interface';

interface ServiceClass {
  ruleId: string;
  ports: number[];
  /** Nombres de servicio de Nmap que también activan la regla. */
  services?: string[];
}

/** Clasificación de servicios expuestos por nivel de riesgo (RF-08). */
const SERVICE_CLASSES: ServiceClass[] = [
  { ruleId: 'SVC-CLEARTEXT-REMOTE-ADMIN', ports: [23, 513, 514], services: ['telnet', 'rlogin', 'shell'] },
  { ruleId: 'SVC-CLEARTEXT-FILE-TRANSFER', ports: [21, 69], services: ['ftp', 'tftp'] },
  { ruleId: 'SVC-REMOTE-DESKTOP', ports: [3389, 5900, 5901, 5902, 5903], services: ['ms-wbt-server', 'vnc', 'rdp'] },
  { ruleId: 'SVC-FILE-SHARING', ports: [139, 445, 2049], services: ['microsoft-ds', 'netbios-ssn', 'nfs'] },
  {
    ruleId: 'SVC-DATABASE-EXPOSED',
    ports: [1433, 1521, 3306, 5432, 5984, 6379, 9042, 9200, 9300, 11211, 27017, 27018],
    services: ['ms-sql-s', 'oracle-tns', 'mysql', 'postgresql', 'couchdb', 'redis', 'cassandra', 'elasticsearch', 'memcache', 'memcached', 'mongodb'],
  },
  { ruleId: 'SVC-ORCHESTRATION-EXPOSED', ports: [2375, 2376, 2379, 2380, 10250, 10255], services: ['docker', 'etcd', 'kubelet'] },
  { ruleId: 'SVC-DIRECTORY-SERVICE', ports: [389], services: ['ldap'] },
  { ruleId: 'SVC-RPC-EXPOSED', ports: [111, 135, 593], services: ['rpcbind', 'msrpc'] },
  { ruleId: 'SVC-MAIL-CLEARTEXT', ports: [110, 143], services: ['pop3', 'imap'] },
];

function classify(port: NmapPort): string {
  const name = port.service?.name?.toLowerCase();
  const match = SERVICE_CLASSES.find(
    (c) => c.ports.includes(port.port) || (name !== undefined && c.services?.includes(name)),
  );
  return match?.ruleId ?? 'SVC-OPEN-PORT';
}

function describeService(port: NmapPort): string {
  const s = port.service;
  const parts = [s?.product, s?.version].filter(Boolean);
  const name = s?.name ?? 'desconocido';
  return parts.length > 0 ? `${name} (${parts.join(' ')})` : name;
}

/** Genera un hallazgo por cada puerto abierto, clasificado según el servicio. */
export function analyzePorts(ports: NmapPort[]): FindingDraft[] {
  return ports
    .filter((p) => p.state === 'open')
    .map((p) => ({
      ruleId: classify(p),
      location: `${p.protocol}/${p.port}`,
      title: `${describeService(p)} expuesto en el puerto ${p.port}/${p.protocol}`,
      evidence: {
        port: p.port,
        protocol: p.protocol,
        service: p.service?.name ?? null,
        product: p.service?.product ?? null,
        version: p.service?.version ?? null,
        extraInfo: p.service?.extraInfo ?? null,
        tunnel: p.service?.tunnel ?? null,
        cpe: p.service?.cpe ?? [],
      },
    }));
}
