import { BadRequestException } from '@nestjs/common';
import type { RoleName } from '@seap/db';
import { ROLE_PERMISSIONS } from '@seap/shared';
import { PrismaService } from '../../common/prisma.module';

export const SYSTEM_ROLES = ['SECURITY_ADMIN', 'SECURITY_ANALYST', 'ENGINEER', 'VIEWER'] as const;

const SYSTEM_ROLE_DESCRIPTIONS: Record<(typeof SYSTEM_ROLES)[number], string> = {
  SECURITY_ADMIN: 'Manages members, policies, and every workflow in the organization.',
  SECURITY_ANALYST: 'Triages findings, runs scans, and handles incidents and remediation.',
  ENGINEER: 'Reads exposure and updates remediation assigned to them.',
  VIEWER: 'Reads assets, findings, scans, incidents, and reports.',
};

export function isSystemRole(value: string): value is (typeof SYSTEM_ROLES)[number] {
  return (SYSTEM_ROLES as readonly string[]).includes(value);
}

export async function ensureSystemRoles(prisma: PrismaService, organizationId: string) {
  for (const name of SYSTEM_ROLES) {
    await prisma.db.organizationRole.upsert({
      where: { organizationId_name: { organizationId, name } },
      create: {
        organizationId,
        name,
        description: SYSTEM_ROLE_DESCRIPTIONS[name],
        permissions: [...ROLE_PERMISSIONS[name]],
        system: true,
      },
      update: {},
    });
  }
}

export async function resolveRoleAssignment(
  prisma: PrismaService,
  organizationId: string,
  role: string,
): Promise<{ role: RoleName; roleId: string | null; name: string }> {
  if (isSystemRole(role)) return { role, roleId: null, name: role };
  const custom = await prisma.db.organizationRole.findFirst({
    where: { organizationId, system: false, OR: [{ id: role }, { name: role }] },
  });
  if (!custom) throw new BadRequestException('Choose a role from this organization');
  return { role: 'VIEWER', roleId: custom.id, name: custom.name };
}
