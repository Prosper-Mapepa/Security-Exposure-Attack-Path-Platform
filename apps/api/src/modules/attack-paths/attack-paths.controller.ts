import { Controller, Get, Headers, NotFoundException, Param, Post, Req } from '@nestjs/common';
import { InjectQueue } from '@nestjs/bullmq';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import type { Queue } from 'bullmq';
import { ServiceUnavailableException } from '@nestjs/common';
import { RequirePermissions } from '../../common/decorators';
import { PrismaService } from '../../common/prisma.module';
import { requireOrganization } from '../../common/tenant';
import type { AppRequest } from '../../common/types';

@ApiTags('attack-paths')
@ApiBearerAuth()
@Controller()
export class AttackPathsController {
  constructor(
    private readonly prisma: PrismaService,
    @InjectQueue('graph') private readonly queue: Queue,
  ) {}

  @Get('attack-paths')
  @RequirePermissions('attackpath:read')
  @ApiOperation({ summary: 'List discovered attack paths' })
  list(@Req() request: AppRequest, @Headers('x-organization-id') organizationHeader: string | undefined) {
    const organizationId = requireOrganization(request.user!, organizationHeader);
    return this.prisma.db.attackPath.findMany({
      where: { organizationId },
      include: { nodes: { orderBy: { position: 'asc' }, include: { networkNode: true } }, edges: { orderBy: { position: 'asc' } } },
      orderBy: { score: 'desc' },
    });
  }

  @Get('attack-paths/:id')
  @RequirePermissions('attackpath:read')
  @ApiOperation({ summary: 'Inspect one attack path and why each node is included' })
  async get(@Req() request: AppRequest, @Headers('x-organization-id') organizationHeader: string | undefined, @Param('id') id: string) {
    const path = await this.prisma.db.attackPath.findFirst({
      where: { id, organizationId: requireOrganization(request.user!, organizationHeader) },
      include: { nodes: { orderBy: { position: 'asc' }, include: { networkNode: true } }, edges: { orderBy: { position: 'asc' } } },
    });
    if (!path) throw new NotFoundException('Attack path was not found');
    return path;
  }

  @Post('attack-paths/rebuild')
  @RequirePermissions('attackpath:write')
  @ApiOperation({ summary: 'Queue attack-path discovery from the stored relationship graph' })
  async rebuild(@Req() request: AppRequest, @Headers('x-organization-id') organizationHeader: string | undefined) {
    const organizationId = requireOrganization(request.user!, organizationHeader);
    try {
      await this.queue.add('rebuild', { organizationId }, { removeOnComplete: 50 });
    } catch {
      throw new ServiceUnavailableException('Graph queue is unavailable');
    }
    return { status: 'queued' };
  }

  @Get('network/nodes')
  @RequirePermissions('attackpath:read')
  @ApiOperation({ summary: 'List network graph nodes' })
  nodes(@Req() request: AppRequest, @Headers('x-organization-id') organizationHeader: string | undefined) {
    return this.prisma.db.networkNode.findMany({
      where: { organizationId: requireOrganization(request.user!, organizationHeader) },
      include: { outgoing: true },
    });
  }
}
