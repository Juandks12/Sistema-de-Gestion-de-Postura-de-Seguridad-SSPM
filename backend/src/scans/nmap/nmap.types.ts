/** Servicio identificado por Nmap en un puerto (-sV). */
export interface NmapService {
  name?: string;
  product?: string;
  version?: string;
  extraInfo?: string;
  /** "ssl" cuando el servicio va sobre TLS. */
  tunnel?: string;
  /** "probed" (sondeo activo) o "table" (deducido del número de puerto). */
  method?: string;
  /** Confianza de la detección (0-10). */
  confidence?: number;
  cpe: string[];
}

export interface NmapPort {
  protocol: string;
  port: number;
  state: string;
  reason?: string;
  service?: NmapService;
}

export interface NmapHost {
  status: string;
  reason?: string;
  addresses: Array<{ addr: string; type: string }>;
  hostnames: Array<{ name: string; type?: string }>;
  ports: NmapPort[];
  /** Puertos agregados por Nmap (p. ej. 995 closed). */
  extraPorts: Array<{ state: string; count: number }>;
}

/** Resultado normalizado de una ejecución de Nmap (-oX). */
export interface NmapScanResult {
  scanner: string;
  version?: string;
  args?: string;
  startedAt?: string;
  finishedAt?: string;
  elapsedSeconds?: number;
  exit?: string;
  errorMessage?: string;
  summary?: string;
  hostsUp: number;
  hostsDown: number;
  hosts: NmapHost[];
}

/** Perfil de escaneo configurable por entorno. */
export interface NmapProfile {
  /** Número de puertos más comunes (--top-ports). */
  topPorts: number;
  /** Lista explícita de puertos/rangos; si está definida tiene prioridad sobre topPorts. */
  ports?: string;
  /** Plantilla de temporización -T0..-T5. */
  timing: number;
  /** Límite de tiempo por host que se pasa a Nmap (--host-timeout). */
  hostTimeoutSeconds: number;
}

/** Salida del proceso de Nmap. */
export interface NmapRunOutput {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  timedOut: boolean;
  cancelled: boolean;
  durationMs: number;
}
