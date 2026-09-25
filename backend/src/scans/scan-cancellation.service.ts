import { Injectable } from '@nestjs/common';
import { AbortReason } from './scanner.interface';

interface Entry {
  controller: AbortController;
  timer: NodeJS.Timeout;
}

/**
 * Registro de escaneos en ejecución en este proceso. Cada escaneo recibe un
 * AbortSignal que se dispara por cancelación del usuario, timeout o apagado.
 */
@Injectable()
export class ScanCancellationService {
  private readonly entries = new Map<string, Entry>();

  register(scanId: string, timeoutMs: number): AbortSignal {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort('timeout' satisfies AbortReason), timeoutMs);
    timer.unref();
    this.entries.set(scanId, { controller, timer });
    return controller.signal;
  }

  release(scanId: string): void {
    const entry = this.entries.get(scanId);
    if (!entry) return;
    clearTimeout(entry.timer);
    this.entries.delete(scanId);
  }

  /** Aborta un escaneo en curso. Devuelve false si no se ejecuta en este proceso. */
  abort(scanId: string, reason: AbortReason = 'cancelled'): boolean {
    const entry = this.entries.get(scanId);
    if (!entry) return false;
    entry.controller.abort(reason);
    return true;
  }

  abortAll(reason: AbortReason = 'shutdown'): string[] {
    const ids = [...this.entries.keys()];
    ids.forEach((id) => this.abort(id, reason));
    return ids;
  }

  get runningCount(): number {
    return this.entries.size;
  }
}
