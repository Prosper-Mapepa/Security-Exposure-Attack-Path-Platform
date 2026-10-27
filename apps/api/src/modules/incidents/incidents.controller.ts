import { Body, Controller, Get, Headers, Param, Patch, Post, Req } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { createIncidentSchema, incidentNoteSchema, updateIncidentSchema } from '@seap/shared';
import { NotFoundException } from '@nestjs/common';
import type { z } from 'zod';
import { RequirePermissions } from '../../common/decorators';
import { clientIp } from '../../common/http';
import { PrismaService } from '../../common/prisma.module';
import { requireOrganization } from '../../common/tenant';
import type { AppRequest } from '../../common/types';
import { ZodValidationPipe } from '../../common/zod.pipe';
import { AuditService } from '../audit/audit.service';

@ApiTags('incidents')
@ApiBearerAuth()
@Controller('incidents')
export class IncidentsController {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
  ) {}

  @Get()
  @RequirePermissions('incident:read')
  @ApiOperation({ summary: 'List incidents' })
  list(@Req() request: AppRequest, @Headers('x-organization-id') organizationHeader: string | undefined) {
    const organizationId = requireOrganization(request.user!, organizationHeader);
    return this.prisma.db.incident.findMany({
      where: { organizationId, deletedAt: null },
      include: {
        assignee: { select: { id: true, name: true } },
        assets: { include: { asset: { select: { id: true, name: true } } } },
        findings: true,
        events: true,
        attackPaths: { include: { attackPath: { select: { id: true, title: true, score: true } } } },
      },
      orderBy: { updatedAt: 'desc' },
    });
  }

  @Post()
  @RequirePermissions('incident:write')
  @ApiOperation({ summary: 'Open an incident from findings, events, or attack paths' })
  async create(
    @Req() request: AppRequest,
    @Headers('x-organization-id') organizationHeader: string | undefined,
    @Body(new ZodValidationPipe(createIncidentSchema)) body: z.infer<typeof createIncidentSchema>,
  ) {
    const organizationId = requireOrganization(request.user!, organizationHeader);
    const linked = await this.linkedRecords(organizationId, body);
    const incident = await this.prisma.db.incident.create({
      data: {
        organizationId,
        title: body.title,
        summary: body.summary,
        severity: body.severity,
        assigneeId: body.assigneeId,
        createdById: request.user?.id,
        assets: linked.assetIds.length ? { create: linked.assetIds.map((assetId) => ({ assetId })) } : undefined,
        findings: linked.vulnerabilityIds.length ? { create: linked.vulnerabilityIds.map((vulnerabilityId) => ({ vulnerabilityId })) } : undefined,
        events: linked.eventIds.length ? { create: linked.eventIds.map((eventId) => ({ eventId })) } : undefined,
        attackPaths: linked.attackPathIds.length ? { create: linked.attackPathIds.map((attackPathId) => ({ attackPathId })) } : undefined,
        timeline: { create: { action: 'incident.opened', detail: body.title, actorId: request.user?.id } },
      },
    });
    await this.audit.write({
      organizationId,
      userId: request.user?.id,
      action: 'incident.create',
      resource: 'incident',
      resourceId: incident.id,
      ip: clientIp(request.header('x-forwarded-for'), request.ip),
      userAgent: request.header('user-agent'),
    });
    return incident;
  }

  @Get(':id')
  @RequirePermissions('incident:read')
  @ApiOperation({ summary: 'Incident detail and investigation timeline' })
  async get(@Req() request: AppRequest, @Headers('x-organization-id') organizationHeader: string | undefined, @Param('id') id: string) {
    const organizationId = requireOrganization(request.user!, organizationHeader);
    const incident = await this.prisma.db.incident.findFirst({
      where: { id, organizationId, deletedAt: null },
      include: {
        assignee: { select: { id: true, name: true, email: true } },
        assets: { include: { asset: true } },
        findings: { include: { vulnerability: true } },
        events: { include: { event: true } },
        attackPaths: { include: { attackPath: true } },
        notes: { orderBy: { createdAt: 'asc' }, include: { author: { select: { id: true, name: true } } } },
        timeline: { orderBy: { createdAt: 'asc' } },
      },
    });
    if (!incident) throw new NotFoundException('Incident was not found');
    return incident;
  }

  @Patch(':id')
  @RequirePermissions('incident:write')
  @ApiOperation({ summary: 'Update incident status, severity, or assignee' })
  async update(
    @Req() request: AppRequest,
    @Headers('x-organization-id') organizationHeader: string | undefined,
    @Param('id') id: string,
    @Body(new ZodValidationPipe(updateIncidentSchema)) body: z.infer<typeof updateIncidentSchema>,
  ) {
    const organizationId = requireOrganization(request.user!, organizationHeader);
    const existing = await this.prisma.db.incident.findFirst({ where: { id, organizationId, deletedAt: null } });
    if (!existing) throw new NotFoundException('Incident was not found');
    const incident = await this.prisma.db.incident.update({
      where: { id },
      data: {
        title: body.title,
        summary: body.summary,
        severity: body.severity,
        status: body.status,
        assigneeId: body.assigneeId === undefined ? undefined : body.assigneeId,
        closedAt: body.status === 'CLOSED' || body.status === 'RESOLVED' ? new Date() : undefined,
        timeline: body.status ? { create: { action: 'incident.status', detail: body.status, actorId: request.user?.id } } : undefined,
      },
    });
    await this.audit.write({
      organizationId,
      userId: request.user?.id,
      action: 'incident.update',
      resource: 'incident',
      resourceId: id,
      ip: clientIp(request.header('x-forwarded-for'), request.ip),
      userAgent: request.header('user-agent'),
      metadata: { status: body.status ?? existing.status },
    });
    return incident;
  }

  @Post(':id/notes')
  @RequirePermissions('incident:write')
  @ApiOperation({ summary: 'Add an investigation note' })
  async note(
    @Req() request: AppRequest,
    @Headers('x-organization-id') organizationHeader: string | undefined,
    @Param('id') id: string,
    @Body(new ZodValidationPipe(incidentNoteSchema)) body: { body: string },
  ) {
    const organizationId = requireOrganization(request.user!, organizationHeader);
    const existing = await this.prisma.db.incident.findFirst({ where: { id, organizationId, deletedAt: null } });
    if (!existing) throw new NotFoundException('Incident was not found');
    const note = await this.prisma.db.incidentNote.create({ data: { incidentId: id, authorId: request.user?.id, body: body.body } });
    await this.prisma.db.incidentTimeline.create({ data: { incidentId: id, action: 'incident.note', detail: 'Note added', actorId: request.user?.id } });
    return note;
  }

  private async linkedRecords(
    organizationId: string,
    body: { assetIds?: string[]; vulnerabilityIds?: string[]; eventIds?: string[]; attackPathIds?: string[] },
  ) {
    const assetIds = new Set(body.assetIds ?? []);
    const vulnerabilityIds = new Set(body.vulnerabilityIds ?? []);
    const attackPathIds = body.attackPathIds ?? [];
    if (attackPathIds.length > 0) {
      const paths = await this.prisma.db.attackPath.findMany({
        where: { organizationId, id: { in: attackPathIds } },
        include: { nodes: { include: { networkNode: true } } },
      });
      for (const path of paths) {
        for (const step of path.nodes) {
          if (step.networkNode.assetId) assetIds.add(step.networkNode.assetId);
          if (step.networkNode.kind === 'VULNERABILITY' && step.networkNode.stableKey.startsWith('vuln:')) {
            vulnerabilityIds.add(step.networkNode.stableKey.slice('vuln:'.length));
          }
        }
      }
    }
    if (assetIds.size > 0) {
      const related = await this.prisma.db.vulnerability.findMany({
        where: {
          organizationId,
          deletedAt: null,
          assetId: { in: [...assetIds] },
          severity: { in: ['CRITICAL', 'HIGH', 'MEDIUM'] },
          status: { in: ['OPEN', 'ACKNOWLEDGED', 'IN_PROGRESS', 'REOPENED'] },
        },
        select: { id: true },
        take: 50,
      });
      for (const item of related) vulnerabilityIds.add(item.id);
    }
    return {
      assetIds: [...assetIds],
      vulnerabilityIds: [...vulnerabilityIds],
      eventIds: body.eventIds ?? [],
      attackPathIds,
    };
  }
}
