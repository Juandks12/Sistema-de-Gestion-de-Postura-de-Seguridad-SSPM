import { Injectable, NestMiddleware } from '@nestjs/common';
import { AsyncLocalStorage } from 'node:async_hooks';
import type { NextFunction, Request, Response } from 'express';

/**
 * Contexto de la petición en curso, disponible en cualquier servicio sin
 * cambiar firmas (AsyncLocalStorage). Hoy solo lleva la IP del cliente, que
 * el registro de auditoría adjunta a cada acción.
 */
export interface RequestContext {
  ip?: string;
}

const storage = new AsyncLocalStorage<RequestContext>();

/** IP del cliente de la petición en curso (respeta `trust proxy`), o undefined fuera de una petición. */
export function clientIp(): string | undefined {
  return storage.getStore()?.ip;
}

/** Ejecuta `fn` con un contexto fijado; para pruebas. */
export function runWithRequestContext<T>(ctx: RequestContext, fn: () => T): T {
  return storage.run(ctx, fn);
}

@Injectable()
export class RequestContextMiddleware implements NestMiddleware {
  use(req: Request, _res: Response, next: NextFunction): void {
    storage.run({ ip: req.ip }, next);
  }
}
