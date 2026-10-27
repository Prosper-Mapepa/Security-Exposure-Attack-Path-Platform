import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { PERMISSIONS, ROLE_PERMISSIONS, type Permission, type RoleName } from '@seap/shared';
import type { Request } from 'express';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { PrismaService } from '../../common/prisma.module';
import { resolvePlatformOrganization } from '../../common/tenant';
import type { RequestUser } from '../../common/types';

interface AccessPayload {
  sub: string;
  email: string;
  organizationId: string | null;
  role: string;
  isPlatformAdmin: boolean;
}

function tokenFromRequest(request: Request): string | null {
  const header = request.headers.authorization;
  if (header?.startsWith('Bearer ')) return header.slice(7);
  const cookies = (request as Request & { cookies?: Record<string, string> }).cookies;
  return cookies?.seap_access ?? null;
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private readonly prisma: PrismaService) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([tokenFromRequest]),
      ignoreExpiration: false,
      secretOrKey: process.env.JWT_ACCESS_SECRET ?? 'development-only-change-me',
      issuer: process.env.JWT_ISSUER ?? 'seap',
    });
  }

  async validate(payload: AccessPayload): Promise<RequestUser> {
    const user = await this.prisma.db.user.findFirst({
      where: { id: payload.sub, deletedAt: null },
    });
    if (!user) throw new UnauthorizedException('Authentication required');
    if (user.lockedUntil && user.lockedUntil > new Date()) {
      throw new UnauthorizedException('Account is temporarily locked');
    }
    if (user.isPlatformAdmin) {
      return {
        id: user.id,
        email: user.email,
        name: user.name,
        organizationId: await resolvePlatformOrganization(this.prisma.db, payload.organizationId),
        role: 'PLATFORM_ADMIN',
        isPlatformAdmin: true,
        permissions: [...ROLE_PERMISSIONS.PLATFORM_ADMIN],
      };
    }
    if (!payload.organizationId) throw new UnauthorizedException('Organization context is required');
    const membership = await this.prisma.db.membership.findUnique({
      where: {
        userId_organizationId: { userId: user.id, organizationId: payload.organizationId },
      },
    });
    if (!membership) throw new UnauthorizedException('Organization membership is no longer valid');
    const assigned = membership.roleId
      ? await this.prisma.db.organizationRole.findFirst({
          where: { id: membership.roleId, organizationId: membership.organizationId },
        })
      : await this.prisma.db.organizationRole.findUnique({
          where: { organizationId_name: { organizationId: membership.organizationId, name: membership.role } },
        });
    const role = assigned?.name ?? membership.role;
    return {
      id: user.id,
      email: user.email,
      name: user.name,
      organizationId: membership.organizationId,
      role,
      isPlatformAdmin: false,
      permissions: permissionsFor(membership.role, assigned),
    };
  }
}

function permissionsFor(
  fallback: RoleName,
  assigned: { system: boolean; permissions: string[] } | null,
): Permission[] {
  const known = new Set<string>(PERMISSIONS);
  const stored = (assigned?.permissions ?? []).filter((permission): permission is Permission => known.has(permission));
  if (assigned && !assigned.system) return stored;
  if (stored.length > 0) return stored;
  return [...ROLE_PERMISSIONS[fallback]];
}
