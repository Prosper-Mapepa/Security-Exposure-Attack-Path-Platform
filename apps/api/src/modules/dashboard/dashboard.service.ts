import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../common/prisma.module';

const OPEN = ['OPEN', 'ACKNOWLEDGED', 'IN_PROGRESS', 'REOPENED'] as const;

@Injectable()
export class DashboardService {
  constructor(private readonly prisma: PrismaService) {}

  async summary(organizationId: string) {
    const [assetCount, findingCount] = await Promise.all([
      this.prisma.db.asset.count({ where: { organizationId, deletedAt: null } }),
      this.prisma.db.vulnerability.count({ where: { organizationId, deletedAt: null } }),
    ]);
    if (assetCount === 0 && findingCount === 0) {
      return { empty: true, message: 'No security data available' };
    }
    const openWhere = { organizationId, deletedAt: null, status: { in: [...OPEN] } };
    const [
      grouped,
      internetFacing,
      assetsWithVulns,
      attackPaths,
      activeIncidents,
      overdue,
      bySource,
      byAsset,
      resolved,
      snapshots,
    ] = await Promise.all([
      this.prisma.db.vulnerability.groupBy({ by: ['severity'], where: openWhere, _count: true }),
      this.prisma.db.asset.count({ where: { organizationId, deletedAt: null, OR: [{ internetFacing: true }, { exposure: 'PUBLIC' }] } }),
      this.prisma.db.asset.count({ where: { organizationId, deletedAt: null, vulnerabilities: { some: { status: { in: [...OPEN] }, deletedAt: null } } } }),
      this.prisma.db.attackPath.count({ where: { organizationId } }),
      this.prisma.db.incident.count({ where: { organizationId, deletedAt: null, status: { notIn: ['RESOLVED', 'CLOSED'] } } }),
      this.prisma.db.remediation.count({ where: { organizationId, dueAt: { lt: new Date() }, status: { notIn: ['VALIDATED', 'CLOSED'] } } }),
      this.prisma.db.finding.groupBy({ by: ['source'], where: { organizationId, deletedAt: null, status: { in: [...OPEN] } }, _count: true }),
      this.prisma.db.vulnerability.groupBy({
        by: ['assetId'],
        where: openWhere,
        _count: true,
        orderBy: { _count: { assetId: 'desc' } },
        take: 8,
      }),
      this.prisma.db.vulnerability.findMany({
        where: {
          organizationId,
          deletedAt: null,
          resolvedAt: { not: null },
          status: { in: ['RESOLVED', 'MITIGATED'] },
        },
        select: { id: true, firstSeen: true, resolvedAt: true },
        take: 500,
      }),
      this.prisma.db.riskSnapshot.findMany({
        where: { organizationId },
        orderBy: { capturedOn: 'asc' },
        take: 30,
      }),
    ]);
    const count = (severity: string) => grouped.find((row) => row.severity === severity)?._count ?? 0;
    const openScores = await this.prisma.db.vulnerability.aggregate({ where: openWhere, _avg: { riskScore: true } });
    const validationResolved = await this.prisma.db.validationRun.findMany({
      where: {
        organizationId,
        outcome: 'RESOLVED',
        completedAt: { not: null },
        vulnerabilityId: { notIn: resolved.map((item) => item.id) },
      },
      select: { completedAt: true, vulnerability: { select: { firstSeen: true } } },
      take: 500,
    });
    const durations = [
      ...resolved.map((item) => (item.resolvedAt && item.firstSeen ? item.resolvedAt.getTime() - item.firstSeen.getTime() : 0)),
      ...validationResolved.map((item) =>
        item.completedAt && item.vulnerability.firstSeen ? item.completedAt.getTime() - item.vulnerability.firstSeen.getTime() : 0,
      ),
    ].filter((value) => value > 0);
    const mttrHours = durations.length
      ? Math.round((durations.reduce((sum, value) => sum + value, 0) / durations.length / 3_600_000) * 10) / 10
      : 0;
    const assetIds = byAsset.map((row) => row.assetId);
    const assets = await this.prisma.db.asset.findMany({ where: { id: { in: assetIds } }, select: { id: true, name: true } });
    return {
      empty: false,
      // No open findings → posture is 0, not unknown.
      securityRiskScore: openScores._avg.riskScore == null ? 0 : Math.round(openScores._avg.riskScore),
      openCritical: count('CRITICAL'),
      openHigh: count('HIGH'),
      openMedium: count('MEDIUM'),
      openLow: count('LOW'),
      openInfo: count('INFO'),
      internetFacingAssets: internetFacing,
      assetsWithVulnerabilities: assetsWithVulns,
      attackPaths,
      activeIncidents,
      overdueRemediation: overdue,
      findingsBySeverity: grouped.map((row) => ({ severity: row.severity, count: row._count })),
      findingsBySource: bySource.map((row) => ({ source: row.source, count: row._count })),
      findingsByAsset: byAsset.map((row) => ({
        assetId: row.assetId,
        name: assets.find((asset) => asset.id === row.assetId)?.name ?? row.assetId,
        count: row._count,
      })),
      meanTimeToRemediateHours: mttrHours,
      riskTrend: snapshots.map((snapshot) => ({
        date: snapshot.capturedOn,
        averageRisk: snapshot.averageRisk,
        openCritical: snapshot.openCritical,
        openHigh: snapshot.openHigh,
      })),
    };
  }
}
