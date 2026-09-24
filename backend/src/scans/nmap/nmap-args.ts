import { isIP } from 'node:net';
import { NmapProfile } from './nmap.types';

/**
 * Construye la lista de argumentos de Nmap para un escaneo de puertos y servicios.
 *
 * Seguridad (sección 11.2 - inyección de comandos):
 * - El objetivo SIEMPRE es una IP literal ya validada y resuelta; nunca texto del usuario.
 * - Los argumentos se pasan como arreglo a `spawn` sin shell, por lo que no hay
 *   interpretación de metacaracteres.
 *
 * Perfil:
 * -sT  escaneo TCP connect (no requiere privilegios de root)
 * -sV  detección de versiones de servicios (RF-03)
 * -Pn  no depende de ping (muchos hosts bloquean ICMP)
 * -n   sin resolución DNS inversa (el objetivo ya está resuelto)
 */
export function buildNmapArgs(target: string, profile: NmapProfile): string[] {
  const family = isIP(target);
  if (family === 0) {
    throw new Error(`Objetivo de Nmap inválido: se esperaba una IP literal y se recibió "${target}"`);
  }

  const args = [
    '-sT',
    '-sV',
    '-Pn',
    '-n',
    `-T${profile.timing}`,
    '--max-retries',
    '2',
    '--host-timeout',
    `${profile.hostTimeoutSeconds}s`,
  ];

  if (profile.ports) {
    args.push('-p', profile.ports);
  } else {
    args.push('--top-ports', String(profile.topPorts));
  }

  if (family === 6) {
    args.push('-6');
  }

  args.push('-oX', '-', target);
  return args;
}
