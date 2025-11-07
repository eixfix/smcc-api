import { PrismaClient, Role, TaskMode } from '@prisma/client';
import * as bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

async function main() {
  const passwordHash = await bcrypt.hash('open1234', 10);

  const administrator = await prisma.user.upsert({
    where: { email: 'administrator@mail.com' },
    update: {},
    create: {
      email: 'administrator@mail.com',
      name: 'Administrator',
      passwordHash,
      role: Role.ADMINISTRATOR
    }
  });

  const redAntOrg = await prisma.organization.upsert({
    where: { slug: 'redant' },
    update: {},
    create: {
      name: 'RedAnt',
      slug: 'redant',
      credits: 200,
      ownerId: administrator.id
    }
  });

  await prisma.organizationMember.upsert({
    where: {
      organizationId_userId: {
        organizationId: redAntOrg.id,
        userId: administrator.id
      }
    },
    update: {
      role: Role.ADMINISTRATOR
    },
    create: {
      organizationId: redAntOrg.id,
      userId: administrator.id,
      role: Role.ADMINISTRATOR
    }
  });

  const project = await prisma.project.upsert({
    where: { id: 'seed-project-redant' },
    update: {},
    create: {
      id: 'seed-project-redant',
      name: 'RedAnt Load Testing',
      description: 'Baseline load testing scenarios for RedAnt platform.',
      organizationId: redAntOrg.id
    }
  });

  await prisma.task.upsert({
    where: { id: 'seed-task-redant-smoke' },
    update: {},
    create: {
      id: 'seed-task-redant-smoke',
      projectId: project.id,
      label: 'Smoke Test Homepage',
      targetUrl: 'https://example.com',
      mode: TaskMode.SMOKE
    }
  });

  console.log('Seed completed: Administrator + RedAnt organization with baseline project/task.');
}

main()
  .catch((error) => {
    console.error('Seeding failed', error);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
