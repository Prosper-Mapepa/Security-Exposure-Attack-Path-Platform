import { BadRequestException, ForbiddenException } from '@nestjs/common';
import type { RequestUser } from './types';

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
