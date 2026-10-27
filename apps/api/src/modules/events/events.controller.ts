import { Body, Controller, Get, Headers, Post, Query, Req } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { createDetectionSchema, createThreatSchema, eventQuerySchema, ingestEventSchema } from '@seap/shared';
import type { Prisma } from '@seap/db';
import { maskUnknown } from '@seap/security';
import type { z } from 'zod';
import { RequirePermissions } from '../../common/decorators';
import { pageWindow } from '../../common/http';
import { PrismaService } from '../../common/prisma.module';
import { requireOrganization } from '../../common/tenant';
import type { AppRequest } from '../../common/types';
import { ZodValidationPipe } from '../../common/zod.pipe';

const RANK: Record<string, number> = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

@ApiTags('events')
@ApiBearerAuth()
@Controller()
export class EventsController {
  constructor(private readonly prisma: PrismaService) {}

  @Post('events')
  @RequirePermissions('event:write')
  @ApiOperation({ summary: 'Ingest a normalized security event' })
  async ingest(
    @Req() request: AppRequest,
    @Headers('x-organization-id') organizationHeader: string | undefined,
    @Body(new ZodValidationPipe(ingestEventSchema)) body: z.infer<typeof ingestEventSchema>,
  ) {
    const organizationId = requireOrganization(request.user!, organizationHeader);
    const detections = await this.prisma.db.detection.findMany({ where: { organizationId, enabled: true, eventType: body.eventType } });
    const detection = detections.find((item) => (RANK[body.severity] ?? 0) >= (RANK[item.minSeverity] ?? 0));
    const event = await this.prisma.db.securityEvent.create({
      data: {
        organizationId,
        timestamp: new Date(body.timestamp),
        source: body.source,
        eventType: body.eventType,
        severity: body.severity,
        sourceIp: body.sourceIp,
        destinationIp: body.destinationIp,
        actor: body.actor || request.user?.email || request.user?.name,
        assetId: body.assetId,
        detectionId: detection?.id,
        rawEvent: maskUnknown(body.rawEvent) as Prisma.InputJsonValue,
        metadata: body.metadata ? (maskUnknown(body.metadata) as Prisma.InputJsonValue) : undefined,
      },
    });
    if (detection && (body.severity === 'CRITICAL' || body.severity === 'HIGH')) {
      await this.prisma.db.notification.create({
        data: {
          organizationId,
          channel: 'IN_APP',
          event: 'security.event',
          title: `Detection ${detection.name}`,
          body: `${body.eventType} from ${body.source}`,
        },
      });
    }
    return event;
  }

  @Get('events')
  @RequirePermissions('event:read')
  @ApiOperation({ summary: 'Filter the security event timeline' })
  async list(
    @Req() request: AppRequest,
    @Headers('x-organization-id') organizationHeader: string | undefined,
    @Query(new ZodValidationPipe(eventQuerySchema)) query: z.infer<typeof eventQuerySchema>,
  ) {
    const organizationId = requireOrganization(request.user!, organizationHeader);
    const where: Prisma.SecurityEventWhereInput = {
      organizationId,
      ...(query.severity ? { severity: query.severity } : {}),
      ...(query.assetId ? { assetId: query.assetId } : {}),
      ...(query.actor ? { actor: { contains: query.actor, mode: 'insensitive' } } : {}),
      ...(query.eventType ? { eventType: query.eventType } : {}),
      ...(query.source ? { source: query.source } : {}),
      ...(query.from || query.to
        ? { timestamp: { gte: query.from ? new Date(query.from) : undefined, lte: query.to ? new Date(query.to) : undefined } }
        : {}),
    };
    const [total, data] = await this.prisma.db.$transaction([
      this.prisma.db.securityEvent.count({ where }),
      this.prisma.db.securityEvent.findMany({
        where,
        orderBy: { timestamp: 'desc' },
        include: { incidents: { include: { incident: { select: { id: true, title: true } } } } },
        ...pageWindow(query.page, query.pageSize),
      }),
    ]);
    const assetIds = [...new Set(data.flatMap((event) => (event.assetId ? [event.assetId] : [])))];
    const assets = assetIds.length
      ? await this.prisma.db.asset.findMany({ where: { id: { in: assetIds } }, select: { id: true, name: true } })
      : [];
    const names = new Map(assets.map((asset) => [asset.id, asset.name]));
    return {
      data: data.map((event) => ({ ...event, asset: event.assetId ? { id: event.assetId, name: names.get(event.assetId) ?? 'Unknown asset' } : null })),
      page: query.page,
      pageSize: query.pageSize,
      total,
    };
  }

  @Get('threats')
  @RequirePermissions('event:read')
  @ApiOperation({ summary: 'List tracked threats' })
  threats(@Req() request: AppRequest, @Headers('x-organization-id') organizationHeader: string | undefined) {
    return this.prisma.db.threat.findMany({ where: { organizationId: requireOrganization(request.user!, organizationHeader) }, include: { detections: true } });
  }

  @Post('threats')
  @RequirePermissions('event:write')
  @ApiOperation({ summary: 'Create a threat record' })
  createThreat(
    @Req() request: AppRequest,
    @Headers('x-organization-id') organizationHeader: string | undefined,
    @Body(new ZodValidationPipe(createThreatSchema)) body: z.infer<typeof createThreatSchema>,
  ) {
    return this.prisma.db.threat.create({ data: { ...body, organizationId: requireOrganization(request.user!, organizationHeader) } });
  }

  @Get('detections')
  @RequirePermissions('event:read')
  @ApiOperation({ summary: 'List detection rules' })
  detections(@Req() request: AppRequest, @Headers('x-organization-id') organizationHeader: string | undefined) {
    return this.prisma.db.detection.findMany({ where: { organizationId: requireOrganization(request.user!, organizationHeader) } });
  }

  @Post('detections')
  @RequirePermissions('event:write')
  @ApiOperation({ summary: 'Create a detection rule that matches ingested events' })
  createDetection(
    @Req() request: AppRequest,
    @Headers('x-organization-id') organizationHeader: string | undefined,
    @Body(new ZodValidationPipe(createDetectionSchema)) body: z.infer<typeof createDetectionSchema>,
  ) {
    return this.prisma.db.detection.create({ data: { ...body, organizationId: requireOrganization(request.user!, organizationHeader) } });
  }
}
