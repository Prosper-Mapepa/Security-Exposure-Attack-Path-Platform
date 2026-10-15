import { Controller, Get, Headers, Query, Req, Res } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { maskSecrets } from '@seap/security';
import PDFDocument from 'pdfkit';
import type { Response } from 'express';
import { z } from 'zod';
import { RequirePermissions } from '../../common/decorators';
import { PrismaService } from '../../common/prisma.module';
import { requireOrganization } from '../../common/tenant';
import type { AppRequest } from '../../common/types';
import { ZodValidationPipe } from '../../common/zod.pipe';
import { DashboardService } from '../dashboard/dashboard.service';

const querySchema = z.object({ format: z.enum(['pdf', 'csv', 'json']).default('json') });

function csvCell(value: unknown): string {
  const text = maskSecrets(value == null ? '' : String(value));
  const safe = /^[=+\-@]/.test(text) ? `'${text}` : text;
  return `"${safe.replace(/"/g, '""')}"`;
}

@ApiTags('reports')
@ApiBearerAuth()
@Controller('reports')
export class ReportsController {
  constructor(
    private readonly prisma: PrismaService,
    private readonly dashboard: DashboardService,
  ) {}

  @Get()
  @RequirePermissions('report:read')
  @ApiOperation({ summary: 'List generated report records' })
  list(@Req() request: AppRequest, @Headers('x-organization-id') organizationHeader: string | undefined) {
    return this.prisma.db.report.findMany({
      where: { organizationId: requireOrganization(request.user!, organizationHeader) },
      orderBy: { createdAt: 'desc' },
    });
  }

  @Get('export')
  @RequirePermissions('report:export')
  @ApiOperation({ summary: 'Generate a security report as PDF, CSV, or JSON' })
  async export(
    @Req() request: AppRequest,
    @Headers('x-organization-id') organizationHeader: string | undefined,
    @Query(new ZodValidationPipe(querySchema)) query: { format: 'pdf' | 'csv' | 'json' },
    @Res() response: Response,
  ) {
    const organizationId = requireOrganization(request.user!, organizationHeader);
    const [summary, findings, paths, organization] = await Promise.all([
      this.dashboard.summary(organizationId),
      this.prisma.db.vulnerability.findMany({
        where: { organizationId, deletedAt: null, severity: { in: ['CRITICAL', 'HIGH'] }, status: { in: ['OPEN', 'ACKNOWLEDGED', 'IN_PROGRESS', 'REOPENED'] } },
        include: { asset: true },
        orderBy: { riskScore: 'desc' },
        take: 100,
      }),
      this.prisma.db.attackPath.findMany({ where: { organizationId }, orderBy: { score: 'desc' }, take: 25 }),
      this.prisma.db.organization.findUnique({ where: { id: organizationId } }),
    ]);
    await this.prisma.db.report.create({
      data: { organizationId, format: query.format, title: 'Security posture report', createdById: request.user?.id },
    });
    const payload = {
      title: 'Security posture report',
      organization: organization?.name,
      generatedAt: new Date().toISOString(),
      executiveSummary: summary,
      criticalAndHighFindings: findings.map((finding) => ({
        title: finding.title,
        severity: finding.severity,
        riskScore: finding.riskScore,
        cve: finding.cve,
        asset: finding.asset.name,
        status: finding.status,
      })),
      attackPaths: paths.map((path) => ({ title: path.title, score: path.score, summary: path.summary })),
    };
    if (query.format === 'json') {
      response.json(payload);
      return;
    }
    if (query.format === 'csv') {
      const header = ['title', 'severity', 'riskScore', 'cve', 'asset', 'status'];
      const lines = [header.join(',')];
      for (const finding of payload.criticalAndHighFindings) {
        lines.push([finding.title, finding.severity, finding.riskScore, finding.cve, finding.asset, finding.status].map(csvCell).join(','));
      }
      response.setHeader('Content-Type', 'text/csv');
      response.setHeader('Content-Disposition', 'attachment; filename="security-report.csv"');
      response.send(lines.join('\n'));
      return;
    }
    const doc = new PDFDocument({ margin: 48 });
    response.setHeader('Content-Type', 'application/pdf');
    response.setHeader('Content-Disposition', 'attachment; filename="security-report.pdf"');
    doc.pipe(response);
    doc.fontSize(18).text('Security Exposure Report');
    doc.moveDown(0.5).fontSize(11).text(`${payload.organization ?? 'Organization'} · ${payload.generatedAt}`);
    doc.moveDown();
    if ('empty' in summary && summary.empty) {
      doc.text('No security data available');
    } else if (!summary.empty) {
      doc.text(`Risk score: ${summary.securityRiskScore ?? 'n/a'}`);
      doc.text(`Open critical: ${summary.openCritical}`);
      doc.text(`Open high: ${summary.openHigh}`);
      doc.text(`Attack paths: ${summary.attackPaths}`);
      doc.text(`Active incidents: ${summary.activeIncidents}`);
      doc.text(`Overdue remediation: ${summary.overdueRemediation}`);
    }
    doc.moveDown().fontSize(14).text('Critical and high findings');
    doc.fontSize(10);
    if (payload.criticalAndHighFindings.length === 0) doc.text('None');
    for (const finding of payload.criticalAndHighFindings) {
      doc.moveDown(0.4).text(`${finding.severity} · ${finding.title} · ${finding.asset} · risk ${finding.riskScore}`);
    }
    doc.moveDown().fontSize(14).text('Attack paths');
    doc.fontSize(10);
    if (payload.attackPaths.length === 0) doc.text('None');
    for (const path of payload.attackPaths) doc.moveDown(0.4).text(`${path.score} · ${path.title}`);
    doc.end();
  }
}
