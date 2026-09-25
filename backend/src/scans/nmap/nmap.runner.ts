import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ChildProcess, spawn } from 'node:child_process';
import { ScanExecutionError } from '../scan.errors';
import { NmapRunOutput } from './nmap.types';

/** Límite de salida capturada para no agotar memoria con respuestas anómalas. */
const MAX_STDOUT_BYTES = 20 * 1024 * 1024;
const MAX_STDERR_BYTES = 64 * 1024;
/** Margen entre SIGTERM y SIGKILL. */
const KILL_GRACE_MS = 5000;

interface RunningProcess {
  child: ChildProcess;
  cancelled: boolean;
}

/**
 * Ejecuta Nmap como proceso hijo de forma asíncrona (no bloquea el event loop).
 * Se usa `spawn` sin shell y con un entorno mínimo.
 */
@Injectable()
export class NmapRunner {
  private readonly logger = new Logger(NmapRunner.name);
  private readonly running = new Map<string, RunningProcess>();

  constructor(private readonly config: ConfigService) {}

  run(scanId: string, args: string[], timeoutMs: number): Promise<NmapRunOutput> {
    const binary = this.config.get<string>('NMAP_PATH') ?? 'nmap';
    const startedAt = Date.now();

    return new Promise<NmapRunOutput>((resolve, reject) => {
      let child: ChildProcess;
      try {
        child = spawn(binary, args, {
          shell: false,
          stdio: ['ignore', 'pipe', 'pipe'],
          env: { PATH: process.env.PATH ?? '/usr/local/bin:/usr/bin:/bin' },
        });
      } catch (err) {
        reject(new ScanExecutionError(`No se pudo iniciar Nmap: ${(err as Error).message}`));
        return;
      }

      const entry: RunningProcess = { child, cancelled: false };
      this.running.set(scanId, entry);

      const stdout: Buffer[] = [];
      const stderr: Buffer[] = [];
      let stdoutBytes = 0;
      let stderrBytes = 0;
      let timedOut = false;
      let overflow = false;
      let killTimer: NodeJS.Timeout | undefined;

      const terminate = () => {
        if (child.exitCode !== null || child.signalCode !== null) return;
        child.kill('SIGTERM');
        killTimer = setTimeout(() => child.kill('SIGKILL'), KILL_GRACE_MS);
        killTimer.unref();
      };

      const timeout = setTimeout(() => {
        timedOut = true;
        this.logger.warn(`Escaneo ${scanId}: tiempo máximo excedido, se aborta Nmap`);
        terminate();
      }, timeoutMs);

      child.stdout?.on('data', (chunk: Buffer) => {
        stdoutBytes += chunk.length;
        if (stdoutBytes > MAX_STDOUT_BYTES) {
          overflow = true;
          terminate();
          return;
        }
        stdout.push(chunk);
      });
      child.stderr?.on('data', (chunk: Buffer) => {
        if (stderrBytes < MAX_STDERR_BYTES) {
          stderr.push(chunk);
          stderrBytes += chunk.length;
        }
      });

      child.once('error', (err: NodeJS.ErrnoException) => {
        clearTimeout(timeout);
        if (killTimer) clearTimeout(killTimer);
        this.running.delete(scanId);
        if (err.code === 'ENOENT') {
          reject(new ScanExecutionError('Nmap no está instalado o NMAP_PATH es incorrecto'));
        } else {
          reject(new ScanExecutionError(`Error al ejecutar Nmap: ${err.message}`));
        }
      });

      child.once('close', (code) => {
        clearTimeout(timeout);
        if (killTimer) clearTimeout(killTimer);
        this.running.delete(scanId);
        if (overflow) {
          reject(new ScanExecutionError('La salida de Nmap excedió el tamaño máximo permitido'));
          return;
        }
        resolve({
          stdout: Buffer.concat(stdout).toString('utf8'),
          stderr: Buffer.concat(stderr).toString('utf8'),
          exitCode: code,
          timedOut,
          cancelled: entry.cancelled,
          durationMs: Date.now() - startedAt,
        });
      });
    });
  }

  /** Detiene el proceso de un escaneo en curso. Devuelve false si no estaba corriendo aquí. */
  cancel(scanId: string): boolean {
    const entry = this.running.get(scanId);
    if (!entry) return false;
    entry.cancelled = true;
    entry.child.kill('SIGTERM');
    const t = setTimeout(() => entry.child.kill('SIGKILL'), KILL_GRACE_MS);
    t.unref();
    return true;
  }

  /** Detiene todos los escaneos en curso (apagado de la aplicación). */
  cancelAll(): string[] {
    const ids = [...this.running.keys()];
    ids.forEach((id) => this.cancel(id));
    return ids;
  }

  get runningCount(): number {
    return this.running.size;
  }
}
