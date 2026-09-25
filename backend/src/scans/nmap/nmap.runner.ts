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

export interface NmapRunOptions {
  /** Tiempo máximo del proceso. */
  timeoutMs: number;
  /** Cancelación externa (usuario o apagado). */
  signal?: AbortSignal;
}

/**
 * Ejecuta Nmap como proceso hijo de forma asíncrona (no bloquea el event loop).
 * Se usa `spawn` sin shell y con un entorno mínimo.
 */
@Injectable()
export class NmapRunner {
  private readonly logger = new Logger(NmapRunner.name);
  private running = 0;

  constructor(private readonly config: ConfigService) {}

  run(args: string[], options: NmapRunOptions): Promise<NmapRunOutput> {
    const binary = this.config.get<string>('NMAP_PATH') ?? 'nmap';
    const startedAt = Date.now();
    const { signal } = options;

    if (signal?.aborted) {
      return Promise.resolve({ stdout: '', stderr: '', exitCode: null, timedOut: false, cancelled: true, durationMs: 0 });
    }

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
      this.running += 1;

      const stdout: Buffer[] = [];
      const stderr: Buffer[] = [];
      let stdoutBytes = 0;
      let stderrBytes = 0;
      let timedOut = false;
      let cancelled = false;
      let overflow = false;
      let killTimer: NodeJS.Timeout | undefined;

      const terminate = () => {
        if (child.exitCode !== null || child.signalCode !== null) return;
        child.kill('SIGTERM');
        killTimer = setTimeout(() => child.kill('SIGKILL'), KILL_GRACE_MS);
        killTimer.unref();
      };

      const onAbort = () => {
        cancelled = true;
        terminate();
      };
      signal?.addEventListener('abort', onAbort, { once: true });

      const timeout = setTimeout(() => {
        timedOut = true;
        this.logger.warn('Tiempo máximo de Nmap excedido, se aborta el proceso');
        terminate();
      }, options.timeoutMs);

      const cleanup = () => {
        clearTimeout(timeout);
        if (killTimer) clearTimeout(killTimer);
        signal?.removeEventListener('abort', onAbort);
        this.running -= 1;
      };

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
        cleanup();
        if (err.code === 'ENOENT') {
          reject(new ScanExecutionError('Nmap no está instalado o NMAP_PATH es incorrecto'));
        } else {
          reject(new ScanExecutionError(`Error al ejecutar Nmap: ${err.message}`));
        }
      });

      child.once('close', (code) => {
        cleanup();
        if (overflow) {
          reject(new ScanExecutionError('La salida de Nmap excedió el tamaño máximo permitido'));
          return;
        }
        resolve({
          stdout: Buffer.concat(stdout).toString('utf8'),
          stderr: Buffer.concat(stderr).toString('utf8'),
          exitCode: code,
          timedOut,
          cancelled,
          durationMs: Date.now() - startedAt,
        });
      });
    });
  }

  get runningCount(): number {
    return this.running;
  }
}
