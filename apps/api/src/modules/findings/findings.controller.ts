import { Body, Controller, Get, Headers, Param, Patch, Post, Query, Req } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { paginationSchema, severities, updateFindingStatusSchema } from '@seap/shared';
import { z } from 'zod';
import { RequirePermissions } from '../../common/decorators';
import { requireOrganization } from '../../common/tenant';
import type { AppRequest } from '../../common/types';
import { ZodValidationPipe } from '../../common/zod.pipe';
import { FindingsService } from './findings.service';

const listSchema = paginationSchema.extend({
  severity: z.enum(severities).optional(),
  status: z.string().max(40).optional(),
  assetId: z.string().optional(),
  source: z.enum(['SEMGREP', 'TRIVY', 'ZAP', 'GITLEAKS']).optional(),
});

@ApiTags('findings')
@ApiBearerAuth()
@Controller()
export class FindingsController {
  constructor(private readonly findings: FindingsService) {}

  @Get('findings')
  @RequirePermissions('finding:read')
  @ApiOperation({ summary: 'List normalized vulnerabilities' })
  list(
    @Req() request: AppRequest,
    @Headers('x-organization-id') organizationHeader: string | undefined,
    @Query(new ZodValidationPipe(listSchema)) query: z.infer<typeof listSchema>,
  ) {
    return this.findings.list(requireOrganization(request.user!, organizationHeader), query);
  }

  @Get('me/findings')
  @RequirePermissions('finding:read')
  @ApiOperation({ summary: 'Findings owned by or assigned to the current user' })
  mine(@Req() request: AppRequest, @Headers('x-organization-id') organizationHeader: string | undefined) {
    return this.findings.mine(requireOrganization(request.user!, organizationHeader), request.user!.id);
  }

  @Get('vulnerabilities/:id')
  @RequirePermissions('finding:read')
  @ApiOperation({ summary: 'Vulnerability detail, risk explanation, attack paths, remediation, and audit history' })
  get(
    @Req() request: AppRequest,
    @Headers('x-organization-id') organizationHeader: string | undefined,
    @Param('id') id: string,
  ) {
    return this.findings.get(requireOrganization(request.user!, organizationHeader), id);
  }

  @Patch('vulnerabilities/:id/status')
  @RequirePermissions('finding:triage')
  @ApiOperation({ summary: 'Triage a vulnerability. RESOLVED is only set by validation.' })
  status(
    @Req() request: AppRequest,
    @Headers('x-organization-id') organizationHeader: string | undefined,
    @Param('id') id: string,
    @Body(new ZodValidationPipe(updateFindingStatusSchema)) body: z.infer<typeof updateFindingStatusSchema>,
  ) {
    return this.findings.updateStatus(requireOrganization(request.user!, organizationHeader), id, body.status, request, body.note);
  }

  @Post('vulnerabilities/:id/validate')
  @RequirePermissions('scan:run')
  @ApiOperation({ summary: 'Queue a validation scan. The finding is resolved only if the scanner no longer reports it.' })
  validate(
    @Req() request: AppRequest,
    @Headers('x-organization-id') organizationHeader: string | undefined,
    @Param('id') id: string,
  ) {
    return this.findings.validate(requireOrganization(request.user!, organizationHeader), id, request);
  }
}
