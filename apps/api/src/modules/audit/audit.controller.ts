import { Controller, Get, Headers, Query, Req } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { paginationSchema } from '@seap/shared';
import { RequirePermissions } from '../../common/decorators';
import { pageWindow } from '../../common/http';
import { PrismaService } from '../../common/prisma.module';
import { requireOrganization } from '../../common/tenant';
import type { AppRequest } from '../../common/types';
import { ZodValidationPipe } from '../../common/zod.pipe';

@ApiTags('audit')
@ApiBearerAuth()
@Controller('audit')
export class AuditController {
  constructor(private readonly prisma: PrismaService) {}

  @Get()
  @RequirePermissions('audit:read')
  @ApiOperation({ summary: 'List append-only audit events for the organization' })
  async list(
    @Req() request: AppRequest,
    @Headers('x-organization-id') organizationHeader: string | undefined,
    @Query(new ZodValidationPipe(paginationSchema)) query: { page: number; pageSize: number; q?: string },
  ) {
    const organizationId = requireOrganization(request.user!, organizationHeader);
    const where = {
      organizationId,
      ...(query.q
        ? {
            OR: [
              { action: { contains: query.q, mode: 'insensitive' as const } },
              { resource: { contains: query.q, mode: 'insensitive' as const } },
            ],
          }
        : {}),
    };
    const [total, data] = await this.prisma.db.$transaction([
      this.prisma.db.auditLog.count({ where }),
      this.prisma.db.auditLog.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        ...pageWindow(query.page, query.pageSize),
      }),
    ]);
    return { data, page: query.page, pageSize: query.pageSize, total };
  }
}
