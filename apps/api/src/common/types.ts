import type { Permission } from '@seap/shared';
import type { Request } from 'express';

export interface RequestUser {
  id: string;
  email: string;
  name: string;
  organizationId: string | null;
  role: string;
  isPlatformAdmin: boolean;
  permissions: Permission[];
}

export interface AppRequest extends Request {
  user?: RequestUser;
  requestId?: string;
}
