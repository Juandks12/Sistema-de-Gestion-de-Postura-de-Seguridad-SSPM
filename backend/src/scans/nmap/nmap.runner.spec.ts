import { ConfigService } from '@nestjs/config';
import { spawnSync } from 'node:child_process';
import { AddressInfo, createServer, Server } from 'node:net';
import { ScanExecutionError } from '../scan.errors';
import { parseNmapXml } from './nmap-xml.parser';
import { NmapRunner } from './nmap.runner';

const nmapAvailable = spawnSync('nmap', ['--version']).status === 0;
const describeIfNmap = nmapAvailable ? describe : describe.skip;

const config = (values: Record<string, unknown>) =>
  ({ get: (key: string) => values[key] }) as unknown as ConfigService;

describe('NmapRunner', () => {
  it('informa si el binario no existe', async () => {
    const runner = new NmapRunner(config({ NMAP_PATH: '/nonexistent/nmap' }));
    await expect(runner.run('scan-x', ['--version'], 5000)).rejects.toBeInstanceOf(
      ScanExecutionError,
    );
  });

  describeIfNmap('con Nmap instalado', () => {
    let server: Server;
    let port: number;

    beforeAll(async () => {
      // Nmap cierra las conexiones con RST; se ignoran esos errores del socket.
      server = createServer((socket) => {
        socket.on('error', () => undefined);
        socket.end();
      });
      await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
      port = (server.address() as AddressInfo).port;
    });

    afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

    it('ejecuta Nmap de forma asíncrona y devuelve XML parseable', async () => {
      const runner = new NmapRunner(config({ NMAP_PATH: 'nmap' }));
      const out = await runner.run(
        'scan-real',
        ['-sT', '-Pn', '-n', '-p', String(port), '-oX', '-', '127.0.0.1'],
        60000,
      );
      expect(out.exitCode).toBe(0);
      expect(out.timedOut).toBe(false);
      const [host] = parseNmapXml(out.stdout).hosts;
      expect(host.ports).toContainEqual(expect.objectContaining({ port, state: 'open' }));
    }, 60000);

    it('aborta el proceso cuando supera el tiempo máximo', async () => {
      const runner = new NmapRunner(config({ NMAP_PATH: 'nmap' }));
      const out = await runner.run(
        'scan-timeout',
        ['-sT', '-Pn', '-n', '-T0', '-p', '1-65535', '-oX', '-', '127.0.0.1'],
        1000,
      );
      expect(out.timedOut).toBe(true);
      expect(runner.runningCount).toBe(0);
    }, 30000);

    it('permite cancelar un escaneo en curso', async () => {
      const runner = new NmapRunner(config({ NMAP_PATH: 'nmap' }));
      const promise = runner.run(
        'scan-cancel',
        ['-sT', '-Pn', '-n', '-T0', '-p', '1-65535', '-oX', '-', '127.0.0.1'],
        30000,
      );
      await new Promise((r) => setTimeout(r, 300));
      expect(runner.cancel('scan-cancel')).toBe(true);
      const out = await promise;
      expect(out.cancelled).toBe(true);
    }, 30000);
  });
});
