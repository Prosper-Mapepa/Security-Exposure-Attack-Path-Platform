import { Body, Controller, Delete, Get, Headers, Param, Patch, Post, Req } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { createTeamSchema, createUserSchema, updateMemberSchema } from '@seap/shared';
import { hashPassword } from '@seap/security';
import { z } from 'zod';
import { BadRequestException, NotFoundException } from '@nestjs/common';
import { RequirePermissions } from '../../common/decorators';
import { clientIp } from '../../common/http';
import { PrismaService } from '../../common/prisma.module';
import { requireOrganization } from '../../common/tenant';
import type { AppRequest } from '../../common/types';
import { ZodValidationPipe } from '../../common/zod.pipe';
import { AuditService } from '../audit/audit.service';

@ApiTags('users')
@ApiBearerAuth()
@Controller()
export class UsersController {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
  ) {}

  @Get('users')
  @RequirePermissions('user:read')
  @ApiOperation({ summary: 'List organization members' })
  async list(@Req() request: AppRequest, @Headers('x-organization-id') organizationHeader: string | undefined) {
    const organizationId = requireOrganization(request.user!, organizationHeader);
    const memberships = await this.prisma.db.membership.findMany({
      where: { organizationId, user: { deletedAt: null } },
      include: { user: { select: { id: true, email: true, name: true, lastLoginAt: true, createdAt: true } } },
    });
    return memberships.map((membership) => ({ ...membership.user, role: membership.role }));
  }

  @Post('users')
  @RequirePermissions('user:manage')
  @ApiOperation({ summary: 'Provision a user into the organization' })
  async create(
    @Req() request: AppRequest,
    @Headers('x-organization-id') organizationHeader: string | undefined,
    @Body(new ZodValidationPipe(createUserSchema)) body: z.infer<typeof createUserSchema>,
  ) {
    const organizationId = requireOrganization(request.user!, organizationHeader);
    const email = body.email.toLowerCase();
    const existing = await this.prisma.db.user.findUnique({ where: { email } });
    const user = existing ?? (await this.prisma.db.user.create({
      data: { email, name: body.name, passwordHash: await hashPassword(body.password) },
    }));
    if (existing?.isPlatformAdmin) throw new BadRequestException('That account cannot be added');
    await this.prisma.db.membership.upsert({
      where: { userId_organizationId: { userId: user.id, organizationId } },
      create: { userId: user.id, organizationId, role: body.role },
      update: { role: body.role },
    });
    await this.audit.write({
      organizationId,
      userId: request.user?.id,
      action: 'user.provision',
      resource: 'user',
      resourceId: user.id,
      ip: clientIp(request.header('x-forwarded-for'), request.ip),
      userAgent: request.header('user-agent'),
      metadata: { role: body.role },
    });
    return { id: user.id, email: user.email, name: user.name, role: body.role };
  }

  @Patch('users/:id')
  @RequirePermissions('user:manage')
  @ApiOperation({ summary: 'Change a member role' })
  async update(
    @Req() request: AppRequest,
    @Headers('x-organization-id') organizationHeader: string | undefined,
    @Param('id') id: string,
    @Body(new ZodValidationPipe(updateMemberSchema)) body: z.infer<typeof updateMemberSchema>,
  ) {
    const organizationId = requireOrganization(request.user!, organizationHeader);
    const membership = await this.prisma.db.membership.findUnique({ where: { userId_organizationId: { userId: id, organizationId } } });
    if (!membership) throw new NotFoundException('Member was not found');
    const updated = await this.prisma.db.membership.update({ where: { id: membership.id }, data: { role: body.role } });
    await this.audit.write({
      organizationId,
      userId: request.user?.id,
      action: 'user.role',
      resource: 'user',
      resourceId: id,
      ip: clientIp(request.header('x-forwarded-for'), request.ip),
      userAgent: request.header('user-agent'),
      metadata: { role: body.role },
    });
    return updated;
  }

  @Delete('users/:id')
  @RequirePermissions('user:manage')
  @ApiOperation({ summary: 'Remove a member from the organization' })
  async remove(
    @Req() request: AppRequest,
    @Headers('x-organization-id') organizationHeader: string | undefined,
    @Param('id') id: string,
  ) {
    const organizationId = requireOrganization(request.user!, organizationHeader);
    await this.prisma.db.membership.deleteMany({ where: { userId: id, organizationId } });
    await this.audit.write({
      organizationId,
      userId: request.user?.id,
      action: 'user.remove',
      resource: 'user',
      resourceId: id,
      ip: clientIp(request.header('x-forwarded-for'), request.ip),
      userAgent: request.header('user-agent'),
    });
    return { success: true };
  }

  @Get('teams')
  @RequirePermissions('user:read')
  @ApiOperation({ summary: 'List teams' })
  teams(@Req() request: AppRequest, @Headers('x-organization-id') organizationHeader: string | undefined) {
    return this.prisma.db.team.findMany({
      where: { organizationId: requireOrganization(request.user!, organizationHeader), deletedAt: null },
      include: { members: true },
    });
  }

  @Post('teams')
  @RequirePermissions('user:manage')
  @ApiOperation({ summary: 'Create a team' })
  async createTeam(
    @Req() request: AppRequest,
    @Headers('x-organization-id') organizationHeader: string | undefined,
    @Body(new ZodValidationPipe(createTeamSchema)) body: { name: string },
  ) {
    const organizationId = requireOrganization(request.user!, organizationHeader);
    const team = await this.prisma.db.team.create({ data: { organizationId, name: body.name } });
    await this.audit.write({
      organizationId,
      userId: request.user?.id,
      action: 'team.create',
      resource: 'team',
      resourceId: team.id,
      ip: clientIp(request.header('x-forwarded-for'), request.ip),
      userAgent: request.header('user-agent'),
    });
    return team;
  }
}
