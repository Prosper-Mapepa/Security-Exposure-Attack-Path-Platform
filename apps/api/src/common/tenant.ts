import { BadRequestException, ForbiddenException } from '@nestjs/common';
import type { PrismaClient } from '@seap/db';
import type { RequestUser } from './types';

export async function resolvePlatformOrganization(db: PrismaClient, requested?: string | null): Promise<string | null> {
  if (requested) return requested;
  const organizations = await db.organization.findMany({
    where: { deletedAt: null },
    select: { id: true },
    orderBy: { createdAt: 'asc' },
  });
  if (organizations.length === 0) return null;
  let selected = organizations[0];
  let selectedAssets = -1;
  for (const organization of organizations) {
    const assets = await db.asset.count({ where: { organizationId: organization.id, deletedAt: null } });
    if (assets > selectedAssets) {
      selected = organization;
      selectedAssets = assets;
    }
  }
  return selected.id;
}

export function requireOrganization(user: RequestUser, header?: string | string[]): string {
  const requested = Array.isArray(header) ? header[0] : header;
  if (user.isPlatformAdmin) {
    const organizationId = requested || user.organizationId;
    if (!organizationId) {
      throw new BadRequestException('X-Organization-Id is required for platform admin requests');
    }
    return organizationId;
  }
  if (!user.organizationId) {
    throw new ForbiddenException('Organization context is required');
  }
  if (requested && requested !== user.organizationId) {
    throw new ForbiddenException('Cross-tenant access denied');
  }
  return user.organizationId;
}
