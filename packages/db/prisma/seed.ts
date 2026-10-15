import { PrismaClient } from '@prisma/client';
import argon2 from 'argon2';

const prisma = new PrismaClient();

async function main() {
  const email = process.env.SEED_ADMIN_EMAIL;
  const password = process.env.SEED_ADMIN_PASSWORD;
  const name = process.env.SEED_ADMIN_NAME ?? 'Platform Admin';
  if (!email || !password) {
    console.info('SEED_ADMIN_EMAIL and SEED_ADMIN_PASSWORD are not set. Skipping platform admin seed.');
    return;
  }
  const passwordHash = await argon2.hash(password, { type: argon2.argon2id });
  await prisma.user.upsert({
    where: { email: email.toLowerCase() },
    update: { name, isPlatformAdmin: true },
    create: { email: email.toLowerCase(), name, passwordHash, isPlatformAdmin: true },
  });
  console.info(`Platform admin ready for ${email.toLowerCase()}`);
}

main()
  .catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : 'Seed failed');
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
