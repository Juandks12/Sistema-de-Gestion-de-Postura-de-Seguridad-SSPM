/* eslint-disable no-console */
import { PrismaClient, UserRole, AssetType } from '@prisma/client';
import * as bcrypt from 'bcrypt';

const prisma = new PrismaClient();

const DEMO_PASSWORD = 'Password123!';

async function main() {
  const passwordHash = await bcrypt.hash(DEMO_PASSWORD, 10);

  const org = await prisma.organization.upsert({
    where: { slug: 'demo-pyme' },
    update: {},
    create: { name: 'Demo PyME S.A.S.', slug: 'demo-pyme' },
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

  for (const a of assets) {
    await prisma.asset.upsert({
      where: { organizationId_value: { organizationId: org.id, value: a.value } },
      update: {},
      create: {
        ...a,
        organizationId: org.id,
        createdById: admin.id,
        authorizationConfirmed: true,
        authorizedAt: new Date(),
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
