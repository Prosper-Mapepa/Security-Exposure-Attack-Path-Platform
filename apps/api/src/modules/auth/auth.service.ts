import {
  ConflictException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { DEFAULT_RISK_WEIGHTS, RISK_FORMULA_VERSION } from '@seap/shared';
import {
  decryptString,
  encryptString,
  hashPassword,
  randomToken,
  sha256,
  slugify,
  verifyPassword,
} from '@seap/security';
import type { Response } from 'express';
import { clearAuthCookies, clientIp, newCsrfToken, setAuthCookies } from '../../common/http';
import { PrismaService } from '../../common/prisma.module';
import { resolvePlatformOrganization } from '../../common/tenant';
import type { AppRequest } from '../../common/types';
import { AuditService } from '../audit/audit.service';

const LOCK_THRESHOLD = 5;
const LOCK_MINUTES = 15;

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
    private readonly audit: AuditService,
  ) {}

  async register(input: { email: string; password: string; name: string; organizationName: string }, request: AppRequest, response: Response) {
    const email = input.email.toLowerCase();
    const existing = await this.prisma.db.user.findUnique({ where: { email } });
    if (existing) throw new ConflictException('An account with that email already exists');
    const passwordHash = await hashPassword(input.password);
    let slug = slugify(input.organizationName);
    const slugTaken = await this.prisma.db.organization.findUnique({ where: { slug } });
    if (slugTaken) slug = `${slug}-${randomToken(3)}`;
    const created = await this.prisma.db.$transaction(async (tx) => {
      const organization = await tx.organization.create({
        data: { name: input.organizationName, slug },
      });
      const user = await tx.user.create({
        data: { email, name: input.name, passwordHash },
      });
      await tx.membership.create({
        data: { userId: user.id, organizationId: organization.id, role: 'SECURITY_ADMIN' },
      });
      await tx.networkNode.create({
        data: {
          organizationId: organization.id,
          kind: 'INTERNET',
          stableKey: 'internet',
          label: 'Internet',
          properties: { exposure: 'PUBLIC' },
        },
      });
      await tx.riskModelConfig.create({
        data: {
          organizationId: organization.id,
          weights: DEFAULT_RISK_WEIGHTS,
          formulaVersion: RISK_FORMULA_VERSION,
        },
      });
      return { organization, user };
    });
    await this.audit.write({
      organizationId: created.organization.id,
      userId: created.user.id,
      action: 'auth.register',
      resource: 'organization',
      resourceId: created.organization.id,
      ip: clientIp(request.header('x-forwarded-for'), request.ip),
      userAgent: request.header('user-agent'),
    });
    return this.issueSession(created.user.id, created.organization.id, 'SECURITY_ADMIN', false, request, response);
  }

  async login(input: { email: string; password: string; organizationSlug?: string; mfaCode?: string }, request: AppRequest, response: Response) {
    const email = input.email.toLowerCase();
    const user = await this.prisma.db.user.findFirst({
      where: { email, deletedAt: null },
      include: { mfaFactor: true },
    });
    const ip = clientIp(request.header('x-forwarded-for'), request.ip);
    const userAgent = request.header('user-agent');
    if (!user) {
      await this.audit.write({ action: 'auth.login.failure', resource: 'user', ip, userAgent, metadata: { email } });
      throw new UnauthorizedException('Invalid email or password');
    }
    if (user.lockedUntil && user.lockedUntil > new Date()) {
      throw new UnauthorizedException('Account is temporarily locked');
    }
    const valid = await verifyPassword(user.passwordHash, input.password);
    if (!valid) {
      const failedLoginCount = user.failedLoginCount + 1;
      await this.prisma.db.user.update({
        where: { id: user.id },
        data: {
          failedLoginCount,
          lockedUntil: failedLoginCount >= LOCK_THRESHOLD ? new Date(Date.now() + LOCK_MINUTES * 60_000) : null,
        },
      });
      await this.audit.write({
        userId: user.id,
        action: 'auth.login.failure',
        resource: 'user',
        resourceId: user.id,
        ip,
        userAgent,
      });
      throw new UnauthorizedException('Invalid email or password');
    }
    if (user.mfaFactor?.enabled) {
      if (!input.mfaCode) return { mfaRequired: true };
      const secret = decryptString(user.mfaFactor.secretEncrypted, this.mfaKey());
      if (!(await this.verifyTotp(secret, input.mfaCode))) {
        throw new UnauthorizedException('Invalid authentication code');
      }
    }
    await this.prisma.db.user.update({
      where: { id: user.id },
      data: { failedLoginCount: 0, lockedUntil: null, lastLoginAt: new Date() },
    });
    if (user.isPlatformAdmin) {
      const organizationId = input.organizationSlug
        ? (await this.prisma.db.organization.findFirst({ where: { slug: input.organizationSlug, deletedAt: null } }))?.id
        : await resolvePlatformOrganization(this.prisma.db, null);
      if (input.organizationSlug && !organizationId) throw new UnauthorizedException('Organization was not found');
      await this.audit.write({
        organizationId,
        userId: user.id,
        action: 'auth.login.success',
        resource: 'user',
        resourceId: user.id,
        ip,
        userAgent,
      });
      return this.issueSession(user.id, organizationId ?? null, 'PLATFORM_ADMIN', true, request, response);
    }
    const memberships = await this.prisma.db.membership.findMany({
      where: { userId: user.id },
      include: { organization: true, organizationRole: true },
    });
    const membership = input.organizationSlug
      ? memberships.find((item) => item.organization.slug === input.organizationSlug)
      : memberships.length === 1
        ? memberships[0]
        : undefined;
    if (!membership) {
      throw new UnauthorizedException(
        memberships.length > 1 ? 'organizationSlug is required' : 'Invalid email or password',
      );
    }
    await this.audit.write({
      organizationId: membership.organizationId,
      userId: user.id,
      action: 'auth.login.success',
      resource: 'user',
      resourceId: user.id,
      ip,
      userAgent,
    });
    return this.issueSession(user.id, membership.organizationId, membership.organizationRole?.name ?? membership.role, false, request, response);
  }

  async refresh(request: AppRequest, response: Response) {
    const token = request.cookies?.seap_refresh;
    if (!token) throw new UnauthorizedException('Refresh token missing');
    const tokenHash = sha256(token);
    const stored = await this.prisma.db.refreshToken.findUnique({ where: { tokenHash } });
    if (!stored || stored.revokedAt || stored.expiresAt < new Date()) {
      if (stored?.revokedAt) {
        await this.prisma.db.refreshToken.updateMany({
          where: { familyId: stored.familyId, revokedAt: null },
          data: { revokedAt: new Date() },
        });
      }
      throw new UnauthorizedException('Refresh token is not valid');
    }
    const user = await this.prisma.db.user.findFirst({ where: { id: stored.userId, deletedAt: null } });
    if (!user) throw new UnauthorizedException('Refresh token is not valid');
    await this.prisma.db.refreshToken.update({ where: { id: stored.id }, data: { revokedAt: new Date() } });
    const context = await this.sessionContext(user.id, user.isPlatformAdmin, stored.organizationId);
    return this.issueSession(
      user.id,
      context.organizationId,
      context.role,
      user.isPlatformAdmin,
      request,
      response,
      stored.familyId,
    );
  }

  async logout(request: AppRequest, response: Response) {
    const token = request.cookies?.seap_refresh;
    if (token) {
      const stored = await this.prisma.db.refreshToken.findUnique({ where: { tokenHash: sha256(token) } });
      if (stored) {
        await this.prisma.db.refreshToken.updateMany({
          where: { familyId: stored.familyId, revokedAt: null },
          data: { revokedAt: new Date() },
        });
      }
    }
    clearAuthCookies(response);
    if (request.user) {
      await this.audit.write({
        organizationId: request.user.organizationId,
        userId: request.user.id,
        action: 'auth.logout',
        resource: 'user',
        resourceId: request.user.id,
        ip: clientIp(request.header('x-forwarded-for'), request.ip),
        userAgent: request.header('user-agent'),
      });
    }
    return { success: true };
  }

  async forgotPassword(email: string) {
    const user = await this.prisma.db.user.findFirst({ where: { email: email.toLowerCase(), deletedAt: null } });
    if (!user) return { success: true };
    const token = randomToken(32);
    await this.prisma.db.passwordResetToken.create({
      data: {
        userId: user.id,
        tokenHash: sha256(token),
        expiresAt: new Date(Date.now() + 60 * 60 * 1000),
      },
    });
    const { createEmailAdapter } = await import('@seap/integrations');
    await createEmailAdapter().send({
      to: user.email,
      subject: 'Reset your Security Exposure platform password',
      text: `Use this password reset token within one hour: ${token}`,
    });
    const expose = process.env.NODE_ENV !== 'production' && process.env.EXPOSE_RESET_TOKEN === 'true';
    return expose ? { success: true, resetToken: token } : { success: true };
  }

  async resetPassword(token: string, password: string, request: AppRequest) {
    const stored = await this.prisma.db.passwordResetToken.findUnique({ where: { tokenHash: sha256(token) } });
    if (!stored || stored.usedAt || stored.expiresAt < new Date()) {
      throw new UnauthorizedException('Reset token is not valid');
    }
    await this.prisma.db.$transaction([
      this.prisma.db.user.update({
        where: { id: stored.userId },
        data: { passwordHash: await hashPassword(password), passwordChangedAt: new Date(), failedLoginCount: 0, lockedUntil: null },
      }),
      this.prisma.db.passwordResetToken.update({ where: { id: stored.id }, data: { usedAt: new Date() } }),
      this.prisma.db.refreshToken.updateMany({ where: { userId: stored.userId, revokedAt: null }, data: { revokedAt: new Date() } }),
    ]);
    await this.audit.write({
      userId: stored.userId,
      action: 'auth.password.reset',
      resource: 'user',
      resourceId: stored.userId,
      ip: clientIp(request.header('x-forwarded-for'), request.ip),
      userAgent: request.header('user-agent'),
    });
    return { success: true };
  }

  me(request: AppRequest) {
    return { user: request.user };
  }

  async enrollMfa(request: AppRequest) {
    const OTPAuth = await import('otpauth');
    const secret = new OTPAuth.Secret({ size: 20 }).base32;
    await this.prisma.db.mfaFactor.upsert({
      where: { userId: request.user!.id },
      create: {
        userId: request.user!.id,
        secretEncrypted: encryptString(secret, this.mfaKey()),
        enabled: false,
      },
      update: {
        secretEncrypted: encryptString(secret, this.mfaKey()),
        enabled: false,
        verifiedAt: null,
      },
    });
    const totp = new OTPAuth.TOTP({
      issuer: 'Security Exposure Platform',
      label: request.user!.email,
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      secret: OTPAuth.Secret.fromBase32(secret),
    });
    return { otpauthUrl: totp.toString() };
  }

  async verifyMfa(request: AppRequest, code: string) {
    const factor = await this.prisma.db.mfaFactor.findUnique({ where: { userId: request.user!.id } });
    if (!factor) throw new UnauthorizedException('MFA is not enrolled');
    const secret = decryptString(factor.secretEncrypted, this.mfaKey());
    if (!(await this.verifyTotp(secret, code))) throw new UnauthorizedException('Invalid authentication code');
    await this.prisma.db.mfaFactor.update({
      where: { userId: request.user!.id },
      data: { enabled: true, verifiedAt: new Date() },
    });
    await this.audit.write({
      organizationId: request.user!.organizationId,
      userId: request.user!.id,
      action: 'auth.mfa.enabled',
      resource: 'user',
      resourceId: request.user!.id,
      ip: clientIp(request.header('x-forwarded-for'), request.ip),
      userAgent: request.header('user-agent'),
    });
    return { enabled: true };
  }

  async switchOrganization(request: AppRequest, organizationId: string, response: Response) {
    const user = request.user!;
    if (!user.isPlatformAdmin) {
      const membership = await this.prisma.db.membership.findUnique({
        where: { userId_organizationId: { userId: user.id, organizationId } },
        include: { organizationRole: true },
      });
      if (!membership) throw new UnauthorizedException('Organization membership was not found');
      return this.issueSession(user.id, organizationId, membership.organizationRole?.name ?? membership.role, false, request, response);
    }
    const organization = await this.prisma.db.organization.findFirst({ where: { id: organizationId, deletedAt: null } });
    if (!organization) throw new UnauthorizedException('Organization was not found');
    return this.issueSession(user.id, organizationId, 'PLATFORM_ADMIN', true, request, response);
  }

  csrf(response: Response) {
    const token = newCsrfToken();
    response.cookie('seap_csrf', token, {
      secure: process.env.COOKIE_SECURE === 'true',
      sameSite: 'lax',
      httpOnly: false,
      path: '/',
    });
    return { csrfToken: token };
  }

  private async issueSession(
    userId: string,
    organizationId: string | null,
    role: string,
    isPlatformAdmin: boolean,
    request: AppRequest,
    response: Response,
    familyId = randomToken(16),
  ) {
    const accessToken = await this.jwt.signAsync({
      sub: userId,
      organizationId,
      role,
      isPlatformAdmin,
    });
    const refreshToken = randomToken(48);
    const csrfToken = newCsrfToken();
    await this.prisma.db.refreshToken.create({
      data: {
        userId,
        tokenHash: sha256(refreshToken),
        familyId,
        organizationId,
        expiresAt: new Date(Date.now() + Number(process.env.REFRESH_TOKEN_TTL_DAYS ?? 14) * 86_400_000),
        ip: clientIp(request.header('x-forwarded-for'), request.ip),
        userAgent: request.header('user-agent')?.slice(0, 300),
      },
    });
    setAuthCookies(response, accessToken, refreshToken, csrfToken);
    const user = await this.prisma.db.user.findUnique({ where: { id: userId } });
    return {
      accessToken,
      csrfToken,
      user: {
        id: userId,
        email: user?.email,
        name: user?.name,
        organizationId,
        role,
        isPlatformAdmin,
      },
    };
  }

  private async sessionContext(userId: string, isPlatformAdmin: boolean, organizationId?: string | null) {
    if (isPlatformAdmin) return { organizationId: organizationId ?? null, role: 'PLATFORM_ADMIN' };
    const membership = organizationId
      ? await this.prisma.db.membership.findUnique({
          where: { userId_organizationId: { userId, organizationId } },
          include: { organizationRole: true },
        })
      : await this.prisma.db.membership.findFirst({ where: { userId }, include: { organizationRole: true } });
    if (!membership) throw new UnauthorizedException('Organization membership was not found');
    return { organizationId: membership.organizationId, role: membership.organizationRole?.name ?? membership.role };
  }

  private async verifyTotp(secret: string, code: string): Promise<boolean> {
    const OTPAuth = await import('otpauth');
    const totp = new OTPAuth.TOTP({
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      secret: OTPAuth.Secret.fromBase32(secret),
    });
    return totp.validate({ token: code, window: 1 }) !== null;
  }

  private mfaKey(): string {
    const key = process.env.MFA_ENCRYPTION_KEY;
    if (!key) throw new UnauthorizedException('MFA is not configured');
    return key;
  }
}
