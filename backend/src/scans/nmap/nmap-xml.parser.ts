import { XMLParser } from 'fast-xml-parser';
import { NmapHost, NmapPort, NmapScanResult, NmapService } from './nmap.types';

/** Elementos que Nmap puede repetir y que siempre se tratan como arreglos. */
const ARRAY_TAGS = new Set(['host', 'port', 'address', 'hostname', 'cpe', 'extraports']);

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '',
  parseAttributeValue: false,
  parseTagValue: false,
  // Nmap no usa entidades externas; se desactiva el procesamiento de DOCTYPE.
  processEntities: true,
  isArray: (name) => ARRAY_TAGS.has(name),
});

type XmlNode = Record<string, unknown>;

export class NmapParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'NmapParseError';
  }
}

function asNode(value: unknown): XmlNode | undefined {
  return value && typeof value === 'object' ? (value as XmlNode) : undefined;
}

function asArray(value: unknown): XmlNode[] {
  return Array.isArray(value) ? (value.filter((v) => v && typeof v === 'object') as XmlNode[]) : [];
}

function str(value: unknown): string | undefined {
  if (value === undefined || value === null) return undefined;
  const s = String(value).trim();
  return s.length > 0 ? s : undefined;
}

function num(value: unknown): number | undefined {
  const n = Number(value);
  return Number.isFinite(n) ? n : undefined;
}

function epochToIso(value: unknown): string | undefined {
  const n = num(value);
  return n !== undefined ? new Date(n * 1000).toISOString() : undefined;
}

function parseService(node: XmlNode | undefined): NmapService | undefined {
  if (!node) return undefined;
  const cpe = Array.isArray(node.cpe)
    ? (node.cpe as unknown[]).map((c) => str(typeof c === 'object' ? (c as XmlNode)['#text'] : c)).filter((c): c is string => !!c)
    : [];
  return {
    name: str(node.name),
    product: str(node.product),
    version: str(node.version),
    extraInfo: str(node.extrainfo),
    tunnel: str(node.tunnel),
    method: str(node.method),
    confidence: num(node.conf),
    cpe,
  };
}

function parsePort(node: XmlNode): NmapPort | undefined {
  const port = num(node.portid);
  const protocol = str(node.protocol);
  const state = asNode(node.state);
  if (port === undefined || !protocol || !state) return undefined;
  return {
    protocol,
    port,
    state: str(state.state) ?? 'unknown',
    reason: str(state.reason),
    service: parseService(asNode(node.service)),
  };
}

function parseHost(node: XmlNode): NmapHost {
  const status = asNode(node.status);
  const ports = asNode(node.ports);
  const hostnames = asNode(node.hostnames);
  return {
    status: str(status?.state) ?? 'unknown',
    reason: str(status?.reason),
    addresses: asArray(node.address).map((a) => ({
      addr: str(a.addr) ?? '',
      type: str(a.addrtype) ?? 'unknown',
    })),
    hostnames: asArray(hostnames?.hostname).map((h) => ({ name: str(h.name) ?? '', type: str(h.type) })),
    ports: asArray(ports?.port)
      .map(parsePort)
      .filter((p): p is NmapPort => p !== undefined)
      .sort((a, b) => a.port - b.port),
    extraPorts: asArray(ports?.extraports).map((e) => ({
      state: str(e.state) ?? 'unknown',
      count: num(e.count) ?? 0,
    })),
  };
}

/**
 * Convierte la salida XML de Nmap (-oX) en una estructura tipada.
 * Descarta información voluminosa y poco útil para el análisis (servicefp).
 */
export function parseNmapXml(xml: string): NmapScanResult {
  if (!xml || !xml.includes('<nmaprun')) {
    throw new NmapParseError('La salida de Nmap no contiene un documento XML válido');
  }

  let doc: XmlNode;
  try {
    doc = parser.parse(xml) as XmlNode;
  } catch (err) {
    throw new NmapParseError(`XML de Nmap mal formado: ${(err as Error).message}`);
  }

  const run = asNode(doc.nmaprun);
  if (!run) {
    throw new NmapParseError('No se encontró el elemento <nmaprun>');
  }

  const runstats = asNode(run.runstats);
  const finished = asNode(runstats?.finished);
  const hostsStats = asNode(runstats?.hosts);

  return {
    scanner: str(run.scanner) ?? 'nmap',
    version: str(run.version),
    args: str(run.args),
    startedAt: epochToIso(run.start),
    finishedAt: epochToIso(finished?.time),
    elapsedSeconds: num(finished?.elapsed),
    exit: str(finished?.exit),
    errorMessage: str(finished?.errormsg),
    summary: str(finished?.summary),
    hostsUp: num(hostsStats?.up) ?? 0,
    hostsDown: num(hostsStats?.down) ?? 0,
    hosts: asArray(run.host).map(parseHost),
  };
}
