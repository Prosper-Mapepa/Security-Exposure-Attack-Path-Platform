import { Controller, Get, Headers, NotFoundException, Param, Post, Req } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { RequirePermissions } from '../../common/decorators';
import { PrismaService } from '../../common/prisma.module';
import { requireOrganization } from '../../common/tenant';
import type { AppRequest } from '../../common/types';

@ApiTags('notifications')
@ApiBearerAuth()
@Controller('notifications')
export class NotificationsController {
  constructor(private readonly prisma: PrismaService) {}

  @Get()
  @RequirePermissions('notification:read')
  @ApiOperation({ summary: 'List in-app notifications' })
  list(@Req() request: AppRequest, @Headers('x-organization-id') organizationHeader: string | undefined) {
    const organizationId = requireOrganization(request.user!, organizationHeader);
    return this.prisma.db.notification.findMany({
      where: { organizationId, OR: [{ userId: request.user!.id }, { userId: null }] },
      orderBy: { createdAt: 'desc' },
      take: 100,
    });
  }

  @Post(':id/read')
  @RequirePermissions('notification:read')
  @ApiOperation({ summary: 'Mark a notification as read' })
  async read(@Req() request: AppRequest, @Headers('x-organization-id') organizationHeader: string | undefined, @Param('id') id: string) {
    const organizationId = requireOrganization(request.user!, organizationHeader);
    const notification = await this.prisma.db.notification.findFirst({ where: { id, organizationId } });
    if (!notification) throw new NotFoundException('Notification was not found');
    return this.prisma.db.notification.update({ where: { id }, data: { readAt: new Date() } });
  }
}
