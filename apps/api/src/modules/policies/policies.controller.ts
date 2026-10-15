import { Body, Controller, Get, Headers, Post, Put, Req } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { createPolicySchema, riskWeightsSchema } from '@seap/shared';
import { RISK_FORMULA_VERSION } from '@seap/shared';
import { explainPolicyViolation } from '@seap/shared';
import type { Prisma } from '@seap/db';
import type { z } from 'zod';
import { RequirePermissions } from '../../common/decorators';
import { clientIp } from '../../common/http';
import { PrismaService } from '../../common/prisma.module';
import { requireOrganization } from '../../common/tenant';
import type { AppRequest } from '../../common/types';
import { ZodValidationPipe } from '../../common/zod.pipe';
import { AuditService } from '../audit/audit.service';

@ApiTags('policies')
@ApiBearerAuth()
@Controller()
export class PoliciesController {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
  ) {}

  @Get('policies')
  @RequirePermissions('policy:read')
  @ApiOperation({ summary: 'List security policies' })
  list(@Req() request: AppRequest, @Headers('x-organization-id') organizationHeader: string | undefined) {
    return this.prisma.db.securityPolicy.findMany({
      where: { organizationId: requireOrganization(request.user!, organizationHeader), deletedAt: null },
    });
  }

  @Post('policies')
  @RequirePermissions('policy:write')
  @ApiOperation({ summary: 'Create a security policy' })
  async create(
    @Req() request: AppRequest,
    @Headers('x-organization-id') organizationHeader: string | undefined,
    @Body(new ZodValidationPipe(createPolicySchema)) body: z.infer<typeof createPolicySchema>,
  ) {
    const organizationId = requireOrganization(request.user!, organizationHeader);
    const policy = await this.prisma.db.securityPolicy.create({
      data: { organizationId, name: body.name, description: body.description, rule: body.rule as Prisma.InputJsonValue, enabled: body.enabled },
    });
    await this.audit.write({
      organizationId,
      userId: request.user?.id,
      action: 'policy.create',
      resource: 'policy',
      resourceId: policy.id,
      ip: clientIp(request.header('x-forwarded-for'), request.ip),
      userAgent: request.header('user-agent'),
    });
    return policy;
  }

  @Get('policies/violations')
  @RequirePermissions('policy:read')
  @ApiOperation({ summary: 'List policy violations' })
  violations(@Req() request: AppRequest, @Headers('x-organization-id') organizationHeader: string | undefined) {
    return this.prisma.db.policyViolation.findMany({
      where: { organizationId: requireOrganization(request.user!, organizationHeader) },
      include: { policy: true, asset: true },
      orderBy: { detectedAt: 'desc' },
    });
  }

  @Post('policies/evaluate')
  @RequirePermissions('policy:write')
  @ApiOperation({ summary: 'Evaluate enabled policies against current assets and findings' })
  async evaluate(@Req() request: AppRequest, @Headers('x-organization-id') organizationHeader: string | undefined) {
    const organizationId = requireOrganization(request.user!, organizationHeader);
    const policies = await this.prisma.db.securityPolicy.findMany({ where: { organizationId, enabled: true, deletedAt: null } });
    const assets = await this.prisma.db.asset.findMany({
      where: { organizationId, deletedAt: null },
      include: { vulnerabilities: { where: { deletedAt: null } } },
    });
    let created = 0;
    for (const policy of policies) {
      for (const asset of assets) {
        const contexts = asset.vulnerabilities.length ? asset.vulnerabilities : [undefined];
        for (const finding of contexts) {
          const detail = explainPolicyViolation(
            policy.rule,
            { type: asset.type, exposure: asset.exposure, environment: asset.environment, ownerId: asset.ownerId, riskScore: finding?.riskScore },
            finding ? { severity: finding.severity, status: finding.status } : undefined,
          );
          if (!detail) continue;
          await this.prisma.db.policyViolation.create({
            data: { organizationId, policyId: policy.id, assetId: asset.id, findingId: finding ? undefined : undefined, detail },
          });
          created += 1;
        }
      }
    }
    return { created };
  }

  @Get('risk-model')
  @RequirePermissions('policy:read')
  @ApiOperation({ summary: 'Return the organization risk model weights' })
  async risk(@Req() request: AppRequest, @Headers('x-organization-id') organizationHeader: string | undefined) {
    const organizationId = requireOrganization(request.user!, organizationHeader);
    return this.prisma.db.riskModelConfig.findUnique({ where: { organizationId } });
  }

  @Put('risk-model')
  @RequirePermissions('policy:write')
  @ApiOperation({ summary: 'Update risk model weights' })
  async updateRisk(
    @Req() request: AppRequest,
    @Headers('x-organization-id') organizationHeader: string | undefined,
    @Body(new ZodValidationPipe(riskWeightsSchema)) body: z.infer<typeof riskWeightsSchema>,
  ) {
    const organizationId = requireOrganization(request.user!, organizationHeader);
    const config = await this.prisma.db.riskModelConfig.upsert({
      where: { organizationId },
      create: { organizationId, weights: body, formulaVersion: RISK_FORMULA_VERSION },
      update: { weights: body, formulaVersion: RISK_FORMULA_VERSION },
    });
    await this.audit.write({
      organizationId,
      userId: request.user?.id,
      action: 'risk-model.update',
      resource: 'risk_model',
      resourceId: config.id,
      ip: clientIp(request.header('x-forwarded-for'), request.ip),
      userAgent: request.header('user-agent'),
    });
    return config;
  }
}
