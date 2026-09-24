/**
 * Datos de ejemplo para desarrollo local. Crea una organización demo con un
 * usuario por cada rol y un par de activos. Ejecutar con `npm run db:seed`.
 */
import 'dotenv/config';
import { PrismaPg } from '@prisma/adapter-pg';
import { hashSync } from 'bcryptjs';
import { AssetType, PrismaClient, UserRole } from '../src/generated/prisma/client';

const prisma = new PrismaClient({
  adapter: new PrismaPg({ connectionString: process.env.DATABASE_URL }),
});

const DEMO_PASSWORD = 'Demo1234';

async function main(): Promise<void> {
  const organization = await prisma.organization.upsert({
    where: { slug: 'demo-pyme' },
    update: {},
    create: { name: 'Demo PyME', slug: 'demo-pyme' },
  });

  const users: Array<{ email: string; fullName: string; role: UserRole }> = [
    { email: 'admin@demo.local', fullName: 'Admin Demo', role: UserRole.ADMIN },
    { email: 'analyst@demo.local', fullName: 'Analista Demo', role: UserRole.ANALYST },
    { email: 'viewer@demo.local', fullName: 'Gerente Demo', role: UserRole.VIEWER },
  ];
  const passwordHash = hashSync(DEMO_PASSWORD, 10);

  for (const user of users) {
    await prisma.user.upsert({
      where: { email: user.email },
      update: { role: user.role, organizationId: organization.id },
      create: { ...user, passwordHash, organizationId: organization.id },
    });
  }

  const admin = await prisma.user.findUniqueOrThrow({ where: { email: 'admin@demo.local' } });

  const assets: Array<{ type: AssetType; value: string; label: string }> = [
    {
      type: AssetType.DOMAIN,
      value: 'scanme.nmap.org',
      label: 'Host de pruebas autorizado por Nmap',
    },
    { type: AssetType.IP, value: '45.33.32.156', label: 'IP de scanme.nmap.org' },
  ];
  for (const asset of assets) {
    await prisma.asset.upsert({
      where: { organizationId_value: { organizationId: organization.id, value: asset.value } },
      update: {},
      create: {
        ...asset,
        organizationId: organization.id,
        createdById: admin.id,
        authorizationConfirmed: true,
      },
    });
  }

  console.log(`Seed completado. Organización "${organization.name}" (${organization.slug}).`);
  console.log(`Usuarios (contraseña "${DEMO_PASSWORD}"): ${users.map((u) => u.email).join(', ')}`);
}

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(() => prisma.$disconnect());
