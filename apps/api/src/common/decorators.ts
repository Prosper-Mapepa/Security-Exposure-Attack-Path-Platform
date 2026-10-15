import { SetMetadata } from '@nestjs/common';
import type { Permission } from '@seap/shared';

export const IS_PUBLIC = 'isPublic';
export const PERMISSIONS_KEY = 'permissions';

export const Public = () => SetMetadata(IS_PUBLIC, true);
export const RequirePermissions = (...permissions: Permission[]) =>
  SetMetadata(PERMISSIONS_KEY, permissions);
