import { UserRole } from '@prisma/client';

/** Identidad mínima del usuario autenticado que viaja en cada request. */
export interface AuthUser {
  id: string;
  email: string;
  fullName: string;
  role: UserRole;
  /** Tenant al que pertenece el usuario. Toda consulta debe filtrarse por este valor. */
  organizationId: string;
}

/** Contenido firmado dentro del JWT. */
export interface JwtPayload {
  sub: string;
  email: string;
  role: UserRole;
  org: string;
  /** Versión de sesión del usuario; si no coincide con la de la BD el token está revocado. */
  ver?: number;
}
