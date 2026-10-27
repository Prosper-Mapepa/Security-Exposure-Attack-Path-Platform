import { BadRequestException, Body, ConflictException, Controller, Delete, Get, Headers, NotFoundException, Param, Patch, Post, Req } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { Prisma } from '@seap/db';
import { createRoleSchema, updateRoleSchema } from '@seap/shared';
import { z } from 'zod';
import { RequirePermissions } from '../../common/decorators';
import { clientIp } from '../../common/http';
import { PrismaService } from '../../common/prisma.module';
import { requireOrganization } from '../../common/tenant';
import type { AppRequest } from '../../common/types';
import { ZodValidationPipe } from '../../common/zod.pipe';
import { AuditService } from '../audit/audit.service';
import { ensureSystemRoles, isSystemRole, SYSTEM_ROLES } from './roles';

@ApiTags('roles')
@ApiBearerAuth()
@Controller('roles')
export class RolesController {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
  ) {}

  @Get()
  @RequirePermissions('user:read')
  @ApiOperation({ summary: 'List built-in and custom organization roles' })
  async list(@Req() request: AppRequest, @Headers('x-organization-id') organizationHeader: string | undefined) {
    const organizationId = requireOrganization(request.user!, organizationHeader);
    await ensureSystemRoles(this.prisma, organizationId);
    const roles = await this.prisma.db.organizationRole.findMany({ where: { organizationId }, orderBy: { name: 'asc' } });
    const memberships = await this.prisma.db.membership.findMany({
      where: { organizationId },
      select: { role: true, roleId: true },
    });
    const ordered = [
      ...SYSTEM_ROLES.flatMap((name) => roles.filter((role) => role.system && role.name === name)),
      ...roles.filter((role) => !role.system).sort((left, right) => left.name.localeCompare(right.name)),
    ];
    return {
      data: ordered.map((role) => ({
        id: role.system ? role.name : role.id,
        name: role.name,
        description: role.description,
        permissions: role.permissions,
        system: role.system,
        members: memberships.filter((membership) => (role.system ? membership.roleId === null && membership.role === role.name : membership.roleId === role.id)).length,
      })),
    };
  }

  @Post()
  @RequirePermissions('user:manage')
  @ApiOperation({ summary: 'Create a custom role' })
  async create(
    @Req() request: AppRequest,
    @Headers('x-organization-id') organizationHeader: string | undefined,
    @Body(new ZodValidationPipe(createRoleSchema)) body: z.infer<typeof createRoleSchema>,
  ) {
    const organizationId = requireOrganization(request.user!, organizationHeader);
    await ensureSystemRoles(this.prisma, organizationId);
    this.assertNameAvailable(body.name);
    try {
      const role = await this.prisma.db.organizationRole.create({
        data: {
          organizationId,
          name: body.name.trim(),
          description: body.description,
          permissions: body.permissions,
          system: false,
        },
      });
      await this.audit.write({
        organizationId,
        userId: request.user?.id,
        action: 'role.create',
        resource: 'role',
        resourceId: role.id,
        ip: clientIp(request.header('x-forwarded-for'), request.ip),
        userAgent: request.header('user-agent'),
        metadata: { name: role.name },
      });
      return { id: role.id, name: role.name, description: role.description, permissions: role.permissions, system: false, members: 0 };
    } catch (error) {
      this.rethrowConflict(error);
    }
  }

  @Patch(':id')
  @RequirePermissions('user:manage')
  @ApiOperation({ summary: 'Update a role name, description, or permissions' })
  async update(
    @Req() request: AppRequest,
    @Headers('x-organization-id') organizationHeader: string | undefined,
    @Param('id') id: string,
    @Body(new ZodValidationPipe(updateRoleSchema)) body: z.infer<typeof updateRoleSchema>,
  ) {
    const organizationId = requireOrganization(request.user!, organizationHeader);
    await ensureSystemRoles(this.prisma, organizationId);
    const existing = await this.findRole(organizationId, id);
    if (body.name && body.name.trim() !== existing.name) {
      if (existing.system) throw new BadRequestException('Built-in roles cannot be renamed');
      this.assertNameAvailable(body.name);
    }
    try {
      const role = await this.prisma.db.organizationRole.update({
        where: { id: existing.id },
        data: {
          ...(body.name && !existing.system ? { name: body.name.trim() } : {}),
          ...(body.description !== undefined ? { description: body.description } : {}),
          ...(body.permissions ? { permissions: body.permissions } : {}),
        },
      });
      await this.audit.write({
        organizationId,
        userId: request.user?.id,
        action: 'role.update',
        resource: 'role',
        resourceId: role.id,
        ip: clientIp(request.header('x-forwarded-for'), request.ip),
        userAgent: request.header('user-agent'),
        metadata: { name: role.name },
      });
      return { id: role.system ? role.name : role.id, name: role.name, description: role.description, permissions: role.permissions, system: role.system };
    } catch (error) {
      this.rethrowConflict(error);
    }
  }

  @Delete(':id')
  @RequirePermissions('user:manage')
  @ApiOperation({ summary: 'Delete a custom role' })
  async remove(
    @Req() request: AppRequest,
    @Headers('x-organization-id') organizationHeader: string | undefined,
    @Param('id') id: string,
  ) {
    const organizationId = requireOrganization(request.user!, organizationHeader);
    const existing = await this.findRole(organizationId, id);
    if (existing.system) throw new BadRequestException('Built-in roles cannot be deleted');
    const members = await this.prisma.db.membership.count({ where: { roleId: existing.id } });
    if (members > 0) throw new BadRequestException('Reassign members before deleting this role');
    await this.prisma.db.organizationRole.delete({ where: { id: existing.id } });
    await this.audit.write({
      organizationId,
      userId: request.user?.id,
      action: 'role.delete',
      resource: 'role',
      resourceId: existing.id,
      ip: clientIp(request.header('x-forwarded-for'), request.ip),
      userAgent: request.header('user-agent'),
      metadata: { name: existing.name },
    });
    return { success: true };
  }

  private assertNameAvailable(name: string) {
    if (isSystemRole(name) || name.toLowerCase() === 'platform_admin' || SYSTEM_ROLES.some((role) => role.toLowerCase() === name.toLowerCase())) {
      throw new BadRequestException('That name is reserved for a built-in role');
    }
  }

  private async findRole(organizationId: string, id: string) {
    const role = isSystemRole(id)
      ? await this.prisma.db.organizationRole.findUnique({ where: { organizationId_name: { organizationId, name: id } } })
      : await this.prisma.db.organizationRole.findFirst({ where: { id, organizationId } });
    if (!role) throw new NotFoundException('Role was not found');
    return role;
  }

  private rethrowConflict(error: unknown): never {
    if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
      throw new ConflictException('A role with that name already exists');
    }
    throw error;
  }
}
