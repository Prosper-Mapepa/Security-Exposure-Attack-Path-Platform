import { Body, Controller, Get, Headers, Param, Post, Query, Req } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { createScanSchema, paginationSchema } from '@seap/shared';
import type { z } from 'zod';
import { RequirePermissions } from '../../common/decorators';
import { requireOrganization } from '../../common/tenant';
import type { AppRequest } from '../../common/types';
import { ZodValidationPipe } from '../../common/zod.pipe';
import { ScansService } from './scans.service';

@ApiTags('scans')
@ApiBearerAuth()
@Controller()
export class ScansController {
  constructor(private readonly scans: ScansService) {}

  @Get('scanners')
  @RequirePermissions('scan:read')
  @ApiOperation({ summary: 'Report whether each scanner binary or API is available' })
  status() {
    return this.scans.scannerStatus();
  }

  @Post('scans')
  @RequirePermissions('scan:run')
  @ApiOperation({ summary: 'Queue a scan. The HTTP request does not run the scanner.' })
  create(
    @Req() request: AppRequest,
    @Headers('x-organization-id') organizationHeader: string | undefined,
    @Body(new ZodValidationPipe(createScanSchema)) body: z.infer<typeof createScanSchema>,
  ) {
    return this.scans.create(requireOrganization(request.user!, organizationHeader), body, request);
  }

  @Get('scans')
  @RequirePermissions('scan:read')
  @ApiOperation({ summary: 'List scans' })
  list(
    @Req() request: AppRequest,
    @Headers('x-organization-id') organizationHeader: string | undefined,
    @Query(new ZodValidationPipe(paginationSchema)) query: z.infer<typeof paginationSchema>,
  ) {
    return this.scans.list(requireOrganization(request.user!, organizationHeader), query);
  }

  @Get('scans/:id')
  @RequirePermissions('scan:read')
  @ApiOperation({ summary: 'Get scan status, result summary, and logs' })
  get(
    @Req() request: AppRequest,
    @Headers('x-organization-id') organizationHeader: string | undefined,
    @Param('id') id: string,
  ) {
    return this.scans.get(requireOrganization(request.user!, organizationHeader), id);
  }

  @Post('scans/:id/cancel')
  @RequirePermissions('scan:run')
  @ApiOperation({ summary: 'Request cancellation of a queued or running scan' })
  cancel(
    @Req() request: AppRequest,
    @Headers('x-organization-id') organizationHeader: string | undefined,
    @Param('id') id: string,
  ) {
    return this.scans.cancel(requireOrganization(request.user!, organizationHeader), id, request);
  }

  @Post('scans/:id/rescan')
  @RequirePermissions('scan:run')
  @ApiOperation({ summary: 'Queue a new scan with the same target' })
  rescan(
    @Req() request: AppRequest,
    @Headers('x-organization-id') organizationHeader: string | undefined,
    @Param('id') id: string,
  ) {
    return this.scans.rescan(requireOrganization(request.user!, organizationHeader), id, request);
  }
}
