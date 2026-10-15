import { Injectable, NotFoundException } from '@nestjs/common';
import type { FindingStatus, Prisma } from '@seap/db';
import { securePatternForCwe } from '@seap/scanner-adapters';
import { clientIp, pageWindow } from '../../common/http';
import { PrismaService } from '../../common/prisma.module';
import type { AppRequest } from '../../common/types';
import { AuditService } from '../audit/audit.service';
import { ScansService } from '../scans/scans.service';

const OPEN = ['OPEN', 'ACKNOWLEDGED', 'IN_PROGRESS', 'REOPENED'] as const;

@Injectable()
export class FindingsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
    private readonly scans: ScansService,
  ) {}

  async list(
    organizationId: string,
    query: { page: number; pageSize: number; q?: string; severity?: string; status?: string; assetId?: string; source?: string },
  ) {
    const where: Prisma.VulnerabilityWhereInput = {
      organizationId,
      deletedAt: null,
      ...(query.severity ? { severity: query.severity as never } : {}),
      ...(query.status ? { status: query.status as never } : {}),
      ...(query.assetId ? { assetId: query.assetId } : {}),
      ...(query.q ? { OR: [{ title: { contains: query.q, mode: 'insensitive' } }, { cve: { contains: query.q, mode: 'insensitive' } }] } : {}),
      ...(query.source ? { findings: { some: { source: query.source as never } } } : {}),
    };
    const [total, data] = await this.prisma.db.$transaction([
      this.prisma.db.vulnerability.count({ where }),
      this.prisma.db.vulnerability.findMany({
        where,
        include: { asset: { select: { id: true, name: true, criticality: true, exposure: true } }, findings: { select: { source: true, location: true } } },
        orderBy: [{ riskScore: 'desc' }, { lastSeen: 'desc' }],
        ...pageWindow(query.page, query.pageSize),
      }),
    ]);
    return { data, page: query.page, pageSize: query.pageSize, total };
  }

  async mine(organizationId: string, userId: string) {
    return this.prisma.db.vulnerability.findMany({
      where: {
        organizationId,
        deletedAt: null,
        status: { in: [...OPEN] },
        OR: [{ asset: { ownerId: userId } }, { remediations: { some: { assigneeId: userId } } }],
      },
      include: { asset: true, findings: true },
      orderBy: { riskScore: 'desc' },
      take: 100,
    });
  }

  async get(organizationId: string, id: string) {
    const vulnerability = await this.prisma.db.vulnerability.findFirst({
      where: { id, organizationId, deletedAt: null },
      include: {
        asset: true,
        findings: { include: { evidence: true, scan: true } },
        remediations: { include: { tasks: true, comments: { include: { author: { select: { id: true, name: true } } } }, assignee: { select: { id: true, name: true } } } },
        validations: { orderBy: { createdAt: 'desc' } },
      },
    });
    if (!vulnerability) throw new NotFoundException('Vulnerability was not found');
    const node = await this.prisma.db.networkNode.findFirst({ where: { organizationId, stableKey: `vuln:${vulnerability.id}` } });
    const attackPaths = node
      ? await this.prisma.db.attackPath.findMany({
          where: { organizationId, nodes: { some: { networkNodeId: node.id } } },
          include: { nodes: { orderBy: { position: 'asc' }, include: { networkNode: true } }, edges: { orderBy: { position: 'asc' } } },
        })
      : [];
    const audit = await this.prisma.db.auditLog.findMany({
      where: { organizationId, resourceId: id },
      orderBy: { createdAt: 'desc' },
      take: 100,
    });
    const guidance = securePatternForCwe(vulnerability.cwe ?? undefined);
    return { vulnerability, attackPaths, audit, securePattern: guidance };
  }

  async updateStatus(organizationId: string, id: string, status: FindingStatus, request: AppRequest, note?: string) {
    const current = await this.prisma.db.vulnerability.findFirst({ where: { id, organizationId, deletedAt: null } });
    if (!current) throw new NotFoundException('Vulnerability was not found');
    const updated = await this.prisma.db.vulnerability.update({
      where: { id },
      data: { status, resolvedAt: status === 'RESOLVED' ? new Date() : null },
    });
    await this.prisma.db.finding.updateMany({ where: { vulnerabilityId: id }, data: { status } });
    await this.audit.write({
      organizationId,
      userId: request.user?.id,
      action: 'finding.status',
      resource: 'vulnerability',
      resourceId: id,
      ip: clientIp(request.header('x-forwarded-for'), request.ip),
      userAgent: request.header('user-agent'),
      metadata: { from: current.status, to: status, note: note ?? null },
    });
    return updated;
  }

  async validate(organizationId: string, id: string, request: AppRequest) {
    const vulnerability = await this.prisma.db.vulnerability.findFirst({
      where: { id, organizationId, deletedAt: null },
      include: { findings: { orderBy: { lastSeen: 'desc' }, include: { scan: { include: { targets: true } } } } },
    });
    if (!vulnerability) throw new NotFoundException('Vulnerability was not found');
    const sourceFinding = vulnerability.findings.find((finding) => finding.scan?.targets[0]);
    const target = sourceFinding?.scan?.targets[0];
    if (!sourceFinding?.scan || !target) {
      throw new NotFoundException('No previous scan target is available to validate this finding');
    }
    const validation = await this.prisma.db.validationRun.create({
      data: { organizationId, vulnerabilityId: id, outcome: 'PENDING', summary: 'Validation scan queued' },
    });
    const scan = await this.scans.create(
      organizationId,
      {
        name: `Validate ${vulnerability.title}`.slice(0, 200),
        scanner: sourceFinding.scan.scanner,
        assetId: vulnerability.assetId,
        targetType: target.targetType,
        location: target.location,
        validationVulnerabilityId: id,
      },
      request,
    );
    await this.prisma.db.validationRun.update({ where: { id: validation.id }, data: { scanId: scan.id } });
    await this.prisma.db.remediation.updateMany({
      where: { vulnerabilityId: id, organizationId },
      data: { status: 'PENDING_VALIDATION' },
    });
    await this.audit.write({
      organizationId,
      userId: request.user?.id,
      action: 'finding.validate',
      resource: 'vulnerability',
      resourceId: id,
      ip: clientIp(request.header('x-forwarded-for'), request.ip),
      userAgent: request.header('user-agent'),
      metadata: { scanId: scan.id },
    });
    return { validationId: validation.id, scan };
  }
}
