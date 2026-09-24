import { ArgumentsHost, Catch, ExceptionFilter, HttpStatus, Logger } from '@nestjs/common';
import type { Response } from 'express';
import { Prisma } from '../../generated/prisma/client';

/**
 * Traduce errores conocidos de Prisma a respuestas HTTP coherentes
 * (p. ej. violación de unicidad -> 409 Conflict) sin filtrar detalles internos.
 */
@Catch(Prisma.PrismaClientKnownRequestError)
export class PrismaClientExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(PrismaClientExceptionFilter.name);

  catch(exception: Prisma.PrismaClientKnownRequestError, host: ArgumentsHost): void {
    const response = host.switchToHttp().getResponse<Response>();

    let status = HttpStatus.INTERNAL_SERVER_ERROR;
    let message = 'Error interno de base de datos';

    switch (exception.code) {
      case 'P2002': {
        status = HttpStatus.CONFLICT;
        const target = (exception.meta?.target as string[] | undefined)?.join(', ');
        message = target
          ? `Ya existe un registro con el mismo valor para: ${target}`
          : 'Ya existe un registro con esos datos';
        break;
      }
      case 'P2003':
        status = HttpStatus.BAD_REQUEST;
        message = 'Referencia inválida a otro registro';
        break;
      case 'P2025':
        status = HttpStatus.NOT_FOUND;
        message = 'El registro solicitado no existe';
        break;
      default:
        this.logger.error(`Prisma error ${exception.code}: ${exception.message}`);
    }

    response.status(status).json({ statusCode: status, message, error: HttpStatus[status] });
  }
}
