import type { UserRole } from '../../generated/prisma/client';

/** Payload firmado dentro del JWT. */
export interface JwtPayload {
  /** ID del usuario */
  sub: string;
  email: string;
  /** Tenant al que pertenece el usuario */
  organizationId: string;
  role: UserRole;
}

/** Usuario autenticado disponible en `request.user` tras pasar el JwtAuthGuard. */
export interface AuthenticatedUser {
  id: string;
  email: string;
  fullName: string;
  organizationId: string;
  role: UserRole;
}
