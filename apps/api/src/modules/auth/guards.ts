import { CanActivate, ExecutionContext, ForbiddenException, Injectable, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthGuard } from '@nestjs/passport';
import { hasPermission, type Permission } from '@seap/shared';
import { timingSafeEqual } from 'node:crypto';
import { IS_PUBLIC, PERMISSIONS_KEY } from '../../common/decorators';
import type { AppRequest } from '../../common/types';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(private readonly reflector: Reflector) {
    super();
  }

  override canActivate(context: ExecutionContext) {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) return true;
    return super.canActivate(context);
  }

  override handleRequest<T>(error: unknown, user: T): T {
    if (error || !user) throw new UnauthorizedException('Authentication required');
    return user;
  }
}

@Injectable()
export class PermissionsGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const required = this.reflector.getAllAndOverride<Permission[]>(PERMISSIONS_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (!required || required.length === 0) return true;
    const request = context.switchToHttp().getRequest<AppRequest>();
    const user = request.user;
    if (!user) throw new UnauthorizedException('Authentication required');
    const allowed = required.every((permission) => hasPermission(user.role, permission));
    if (!allowed) throw new ForbiddenException('Insufficient permissions');
    return true;
  }
}

@Injectable()
export class CsrfGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC, [
      context.getHandler(),
      context.getClass(),
    ]);
    const request = context.switchToHttp().getRequest<AppRequest>();
    if (request.method === 'GET' || request.method === 'HEAD' || request.method === 'OPTIONS') return true;
    const bearer = request.headers.authorization?.startsWith('Bearer ');
    if (bearer) return true;
    if (isPublic && !request.cookies?.seap_access && !request.cookies?.seap_csrf) return true;
    const cookie = request.cookies?.seap_csrf;
    const header = request.header('x-csrf-token');
    if (!cookie || !header || cookie.length !== header.length) {
      throw new ForbiddenException('CSRF token missing or invalid');
    }
    const valid = timingSafeEqual(Buffer.from(cookie), Buffer.from(header));
    if (!valid) throw new ForbiddenException('CSRF token missing or invalid');
    return true;
  }
}
