import { Controller, Get, Headers, Req } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { RequirePermissions } from '../../common/decorators';
import { requireOrganization } from '../../common/tenant';
import type { AppRequest } from '../../common/types';
import { DashboardService } from './dashboard.service';

@ApiTags('dashboard')
@ApiBearerAuth()
@Controller('dashboard')
export class DashboardController {
  constructor(private readonly dashboard: DashboardService) {}

  @Get()
  @RequirePermissions('dashboard:read')
  @ApiOperation({ summary: 'Security posture metrics computed from stored findings' })
  summary(@Req() request: AppRequest, @Headers('x-organization-id') organizationHeader: string | undefined) {
    if (request.user?.isPlatformAdmin && !request.user.organizationId && !organizationHeader) {
      return { empty: true, message: 'No security data available' };
    }
    return this.dashboard.summary(requireOrganization(request.user!, organizationHeader));
  }
}
