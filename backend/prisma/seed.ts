/* eslint-disable no-console */
import { AssetType, PrismaClient, UserRole, VerificationMethod } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { randomBytes } from 'node:crypto';

const prisma = new PrismaClient();

const DEMO_PASSWORD = 'Password123!';

async function main() {
  const passwordHash = await bcrypt.hash(DEMO_PASSWORD, 10);

  const org = await prisma.organization.upsert({
    where: { slug: 'demo-pyme' },
    update: {},
    create: { name: 'Demo PyME S.A.S.', slug: 'demo-pyme', verificationToken: randomBytes(16).toString('hex') },
  });

  const users = [
    { email: 'admin@demo.local', fullName: 'Ana Admin', role: UserRole.ADMIN },
    { email: 'analista@demo.local', fullName: 'Andrés Analista', role: UserRole.ANALYST },
    { email: 'gerente@demo.local', fullName: 'Gloria Gerente', role: UserRole.VIEWER },
  ];

  for (const u of users) {
    await prisma.user.upsert({
      where: { email: u.email },
      update: {},
      create: { ...u, passwordHash, organizationId: org.id },
    });
  }

  const admin = await prisma.user.findUniqueOrThrow({ where: { email: 'admin@demo.local' } });

  const assets = [
    { type: AssetType.DOMAIN, value: 'scanme.nmap.org', name: 'Host de pruebas de Nmap' },
    { type: AssetType.IP, value: '45.33.32.156', name: 'IP de scanme.nmap.org' },
  ];

  // scanme.nmap.org es un host que el proyecto Nmap pone a disposición pública
  // para practicar escaneos, por eso se marca como pre-autorizado. Cualquier
  // activo real debe verificarse por DNS o con el archivo de verificación.
  const preAuthorized = {
    verifiedAt: new Date(),
    verificationMethod: VerificationMethod.PRE_AUTHORIZED,
  };
  for (const a of assets) {
    await prisma.asset.upsert({
      where: { organizationId_value: { organizationId: org.id, value: a.value } },
      update: { ...preAuthorized, verificationScope: a.value },
      create: {
        ...a,
        organizationId: org.id,
        createdById: admin.id,
        authorizationConfirmed: true,
        authorizedAt: new Date(),
        ...preAuthorized,
        verificationScope: a.value,
      },
    });
  }

  console.log(`Seed completado. Organización "${org.name}" con ${users.length} usuarios.`);
  console.log(`Contraseña de todos los usuarios demo: ${DEMO_PASSWORD}`);
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());
