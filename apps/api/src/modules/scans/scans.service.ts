import { BadRequestException, Injectable, NotFoundException, ServiceUnavailableException } from '@nestjs/common';
import { InjectQueue } from '@nestjs/bullmq';
import type { Prisma, ScannerType, ScanTargetType } from '@seap/db';
import { createScanner } from '@seap/scanner-adapters';
import { assertSafeScanUrl, isPathInsideAllowlist } from '@seap/security';
import type { Queue } from 'bullmq';
import { clientIp, pageWindow } from '../../common/http';
import { PrismaService } from '../../common/prisma.module';
import type { AppRequest } from '../../common/types';
import { AuditService } from '../audit/audit.service';

@Injectable()
export class ScansService {
  constructor(
    @InjectQueue('scans') private readonly queue: Queue,
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
  ) {}

  async scannerStatus() {
    const scanners = ['SEMGREP', 'TRIVY', 'ZAP', 'GITLEAKS'] as const;
    return Promise.all(scanners.map((name) => createScanner(name).getStatus()));
  }

  async create(
    organizationId: string,
    input: { name: string; scanner: ScannerType; assetId: string; targetType: ScanTargetType; location: string; metadata?: Record<string, unknown>; validationVulnerabilityId?: string },
    request: AppRequest,
  ) {
    const asset = await this.prisma.db.asset.findFirst({ where: { id: input.assetId, organizationId, deletedAt: null } });
    if (!asset) throw new NotFoundException('Asset was not found');
    await this.assertTarget(input.targetType, input.location);
    const scan = await this.prisma.db.scan.create({
      data: {
        organizationId,
        name: input.name,
        scanner: input.scanner,
        assetId: input.assetId,
        requestedById: request.user?.id,
        validationVulnerabilityId: input.validationVulnerabilityId,
        targets: {
          create: {
            targetType: input.targetType,
            location: input.location,
            metadata: input.metadata as Prisma.InputJsonValue | undefined,
          },
        },
      },
      include: { targets: true },
    });
    try {
      await this.queue.add('run', { scanId: scan.id, organizationId }, { jobId: scan.id, removeOnComplete: 100, removeOnFail: 100 });
    } catch {
      await this.prisma.db.scan.update({ where: { id: scan.id }, data: { status: 'FAILED', error: 'Queue is unavailable' } });
      throw new ServiceUnavailableException('Scan queue is unavailable');
    }
    await this.audit.write({
      organizationId,
      userId: request.user?.id,
      action: 'scan.create',
      resource: 'scan',
      resourceId: scan.id,
      ip: clientIp(request.header('x-forwarded-for'), request.ip),
      userAgent: request.header('user-agent'),
      metadata: { scanner: input.scanner, assetId: input.assetId },
    });
    return scan;
  }

  async list(organizationId: string, query: { page: number; pageSize: number; q?: string }) {
    const where: Prisma.ScanWhereInput = {
      organizationId,
      ...(query.q ? { name: { contains: query.q, mode: 'insensitive' } } : {}),
    };
    const [total, data] = await this.prisma.db.$transaction([
      this.prisma.db.scan.count({ where }),
      this.prisma.db.scan.findMany({
        where,
        include: { asset: { select: { id: true, name: true } }, result: true, targets: true },
        orderBy: { createdAt: 'desc' },
        ...pageWindow(query.page, query.pageSize),
      }),
    ]);
    return { data, page: query.page, pageSize: query.pageSize, total };
  }

  async get(organizationId: string, id: string) {
    const scan = await this.prisma.db.scan.findFirst({
      where: { id, organizationId },
      include: { targets: true, result: true, logs: { orderBy: { createdAt: 'asc' }, take: 500 }, asset: true },
    });
    if (!scan) throw new NotFoundException('Scan was not found');
    return scan;
  }

  async cancel(organizationId: string, id: string, request: AppRequest) {
    const scan = await this.get(organizationId, id);
    if (scan.status === 'COMPLETED' || scan.status === 'FAILED' || scan.status === 'CANCELLED') {
      throw new BadRequestException('Scan is already finished');
    }
    await this.prisma.db.scan.update({ where: { id }, data: { cancelRequested: true } });
    await this.audit.write({
      organizationId,
      userId: request.user?.id,
      action: 'scan.cancel',
      resource: 'scan',
      resourceId: id,
      ip: clientIp(request.header('x-forwarded-for'), request.ip),
      userAgent: request.header('user-agent'),
    });
    return { success: true };
  }

  async rescan(organizationId: string, id: string, request: AppRequest) {
    const scan = await this.get(organizationId, id);
    const target = scan.targets[0];
    if (!target) throw new BadRequestException('Scan has no target');
    return this.create(
      organizationId,
      {
        name: `${scan.name} rescan`,
        scanner: scan.scanner,
        assetId: scan.assetId,
        targetType: target.targetType,
        location: target.location,
        metadata: (target.metadata ?? undefined) as Record<string, unknown> | undefined,
        validationVulnerabilityId: scan.validationVulnerabilityId ?? undefined,
      },
      request,
    );
  }

  private async assertTarget(targetType: ScanTargetType, location: string) {
    if (targetType === 'PATH') {
      const allowlist = (process.env.SCAN_PATH_ALLOWLIST ?? '').split(',').map((item) => item.trim()).filter(Boolean);
      if (!isPathInsideAllowlist(location, allowlist)) {
        throw new BadRequestException('Scan path is outside the configured allowlist');
      }
      return;
    }
    if (targetType === 'URL' || targetType === 'GIT') {
      try {
        await assertSafeScanUrl(location, {
          allowPrivate: process.env.ALLOW_PRIVATE_SCAN_TARGETS === 'true',
          labCidrs: (process.env.LAB_NETWORK_CIDR ?? '').split(',').filter(Boolean),
        });
      } catch (error) {
        throw new BadRequestException(error instanceof Error ? error.message : 'Scan target rejected');
      }
      return;
    }
    if (!/^[a-zA-Z0-9][a-zA-Z0-9._:/@-]{0,300}$/.test(location) || location.includes('..')) {
      throw new BadRequestException('Container image reference is invalid');
    }
  }
}
