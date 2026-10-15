import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import type { AssetType, Prisma } from '@seap/db';
import type { CreateAssetInput } from '@seap/shared';
import { clientIp, pageWindow } from '../../common/http';
import { PrismaService } from '../../common/prisma.module';
import type { AppRequest } from '../../common/types';
import { AuditService } from '../audit/audit.service';

const OPEN_STATUSES = ['OPEN', 'ACKNOWLEDGED', 'IN_PROGRESS', 'REOPENED'] as const;

function text(value: unknown, max = 500): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed ? trimmed.slice(0, max) : undefined;
}

@Injectable()
export class AssetsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
  ) {}

  async list(organizationId: string, query: { page: number; pageSize: number; q?: string; type?: AssetType }) {
    const where: Prisma.AssetWhereInput = {
      organizationId,
      deletedAt: null,
      ...(query.type ? { type: query.type } : {}),
      ...(query.q
        ? {
            OR: [
              { name: { contains: query.q, mode: 'insensitive' } },
              { businessService: { contains: query.q, mode: 'insensitive' } },
              { technology: { contains: query.q, mode: 'insensitive' } },
            ],
          }
        : {}),
    };
    const [total, data] = await this.prisma.db.$transaction([
      this.prisma.db.asset.count({ where }),
      this.prisma.db.asset.findMany({
        where,
        include: { tags: true, owner: { select: { id: true, name: true, email: true } } },
        orderBy: { updatedAt: 'desc' },
        ...pageWindow(query.page, query.pageSize),
      }),
    ]);
    return { data, page: query.page, pageSize: query.pageSize, total };
  }

  async create(organizationId: string, input: CreateAssetInput, request: AppRequest) {
    const asset = await this.prisma.db.$transaction(async (tx) => {
      const created = await tx.asset.create({
        data: {
          organizationId,
          name: input.name,
          type: input.type,
          description: input.description,
          environment: input.environment,
          criticality: input.criticality,
          exposure: input.exposure,
          dataSensitivity: input.dataSensitivity,
          technology: input.technology,
          businessService: input.businessService,
          ownerId: input.ownerId,
          teamId: input.teamId,
          authRequired: input.authRequired,
          privilegeRequired: input.privilegeRequired,
          internetFacing: input.internetFacing ?? input.exposure === 'PUBLIC',
          metadata: (input.metadata ?? undefined) as Prisma.InputJsonValue | undefined,
          lastSeenAt: new Date(),
          tags: input.tags ? { create: input.tags.map((value) => ({ value })) } : undefined,
        },
      });
      await this.createDetail(tx, created.id, input);
      await tx.networkNode.create({
        data: {
          organizationId,
          assetId: created.id,
          kind: kindFor(input.type, input.detail),
          stableKey: `asset:${created.id}`,
          label: created.name,
          properties: {
            exposure: created.exposure,
            criticality: created.criticality,
            dataSensitivity: created.dataSensitivity,
            privileged: input.type === 'IAM_ROLE' ? Boolean(input.detail?.privileged) : false,
          },
        },
      });
      if (input.ownerId) {
        await tx.assetOwner.create({ data: { assetId: created.id, userId: input.ownerId } });
      }
      return created;
    });
    await this.audit.write({
      organizationId,
      userId: request.user?.id,
      action: 'asset.create',
      resource: 'asset',
      resourceId: asset.id,
      ip: clientIp(request.header('x-forwarded-for'), request.ip),
      userAgent: request.header('user-agent'),
      metadata: { type: asset.type, name: asset.name },
    });
    return asset;
  }

  async get(organizationId: string, id: string) {
    const asset = await this.prisma.db.asset.findFirst({
      where: { id, organizationId, deletedAt: null },
      include: {
        tags: true,
        owner: { select: { id: true, name: true, email: true } },
        application: true,
        api: true,
        repository: true,
        cloudAccount: true,
        cloudResource: true,
        container: true,
        containerImage: true,
        kubernetesCluster: true,
        kubernetesWorkload: true,
        identity: true,
        serviceAccount: true,
        iamRole: true,
        endpoints: { where: { deletedAt: null } },
      },
    });
    if (!asset) throw new NotFoundException('Asset was not found');
    return asset;
  }

  async posture(organizationId: string, id: string) {
    const asset = await this.get(organizationId, id);
    const [findings, scans, node] = await Promise.all([
      this.prisma.db.vulnerability.findMany({
        where: { organizationId, assetId: id, deletedAt: null },
        orderBy: { riskScore: 'desc' },
        take: 50,
      }),
      this.prisma.db.scan.findMany({
        where: { organizationId, assetId: id },
        orderBy: { createdAt: 'desc' },
        take: 15,
        include: { result: true },
      }),
      this.prisma.db.networkNode.findUnique({ where: { assetId: id } }),
    ]);
    const attackPaths = node
      ? await this.prisma.db.attackPath.findMany({
          where: { organizationId, nodes: { some: { networkNodeId: node.id } } },
          orderBy: { score: 'desc' },
          include: { nodes: { orderBy: { position: 'asc' }, include: { networkNode: true } } },
          take: 20,
        })
      : [];
    const severity = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    for (const finding of findings) {
      if (OPEN_STATUSES.includes(finding.status as (typeof OPEN_STATUSES)[number])) {
        severity[finding.severity] += 1;
      }
    }
    return { asset, severity, findings, scans, attackPaths };
  }

  async update(organizationId: string, id: string, input: Partial<CreateAssetInput>, request: AppRequest) {
    await this.get(organizationId, id);
    const asset = await this.prisma.db.asset.update({
      where: { id },
      data: {
        name: input.name,
        description: input.description,
        environment: input.environment,
        criticality: input.criticality,
        exposure: input.exposure,
        dataSensitivity: input.dataSensitivity,
        technology: input.technology,
        businessService: input.businessService,
        ownerId: input.ownerId,
        teamId: input.teamId,
        authRequired: input.authRequired,
        privilegeRequired: input.privilegeRequired,
        internetFacing: input.internetFacing,
        lastSeenAt: new Date(),
      },
    });
    if (input.tags) {
      await this.prisma.db.assetTag.deleteMany({ where: { assetId: id } });
      await this.prisma.db.assetTag.createMany({ data: input.tags.map((value) => ({ assetId: id, value })) });
    }
    await this.audit.write({
      organizationId,
      userId: request.user?.id,
      action: 'asset.update',
      resource: 'asset',
      resourceId: id,
      ip: clientIp(request.header('x-forwarded-for'), request.ip),
      userAgent: request.header('user-agent'),
    });
    return asset;
  }

  async remove(organizationId: string, id: string, request: AppRequest) {
    await this.get(organizationId, id);
    await this.prisma.db.asset.update({ where: { id }, data: { deletedAt: new Date() } });
    await this.audit.write({
      organizationId,
      userId: request.user?.id,
      action: 'asset.delete',
      resource: 'asset',
      resourceId: id,
      ip: clientIp(request.header('x-forwarded-for'), request.ip),
      userAgent: request.header('user-agent'),
    });
    return { success: true };
  }

  async importCsv(organizationId: string, csv: string, request: AppRequest) {
    const lines = csv.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
    const header = lines.shift()?.split(',').map((cell) => cell.trim().toLowerCase());
    if (!header || !header.includes('name') || !header.includes('type')) {
      throw new BadRequestException('CSV must include name and type columns');
    }
    let created = 0;
    for (const line of lines) {
      const cells = line.split(',').map((cell) => cell.trim());
      const record = Object.fromEntries(header.map((key, index) => [key, cells[index] ?? '']));
      if (!record.name || !record.type) continue;
      await this.create(
        organizationId,
        {
          name: record.name,
          type: record.type as CreateAssetInput['type'],
          environment: (record.environment || 'UNKNOWN') as CreateAssetInput['environment'],
          criticality: (record.criticality || 'MEDIUM') as CreateAssetInput['criticality'],
          exposure: (record.exposure || 'UNKNOWN') as CreateAssetInput['exposure'],
          dataSensitivity: 'UNKNOWN',
          technology: record.technology,
          businessService: record.businessservice || record.business_service,
        },
        request,
      );
      created += 1;
    }
    return { created };
  }

  async addEndpoint(organizationId: string, assetId: string, input: { method: string; path: string; authRequired: boolean }) {
    await this.get(organizationId, assetId);
    return this.prisma.db.endpoint.create({
      data: { organizationId, apiAssetId: assetId, method: input.method.toUpperCase(), path: input.path, authRequired: input.authRequired },
    });
  }

  async relate(organizationId: string, sourceAssetId: string, targetAssetId: string, type: Prisma.NetworkRelationshipCreateInput['type'] | string, request: AppRequest) {
    const [source, target] = await Promise.all([
      this.prisma.db.networkNode.findFirst({ where: { organizationId, assetId: sourceAssetId } }),
      this.prisma.db.networkNode.findFirst({ where: { organizationId, assetId: targetAssetId } }),
    ]);
    if (!source || !target) throw new NotFoundException('Both assets must exist in this organization');
    const relationship = await this.prisma.db.networkRelationship.upsert({
      where: {
        organizationId_sourceId_targetId_type: {
          organizationId,
          sourceId: source.id,
          targetId: target.id,
          type: type as never,
        },
      },
      create: {
        organizationId,
        sourceId: source.id,
        targetId: target.id,
        type: type as never,
        properties: { system: false },
      },
      update: {},
    });
    await this.audit.write({
      organizationId,
      userId: request.user?.id,
      action: 'relationship.create',
      resource: 'network_relationship',
      resourceId: relationship.id,
      ip: clientIp(request.header('x-forwarded-for'), request.ip),
      userAgent: request.header('user-agent'),
      metadata: { type },
    });
    return relationship;
  }

  private async createDetail(tx: Prisma.TransactionClient, assetId: string, input: CreateAssetInput) {
    const detail = input.detail ?? {};
    switch (input.type) {
      case 'APPLICATION':
        await tx.application.create({ data: { assetId, repositoryUrl: text(detail.repositoryUrl), runtime: text(detail.runtime) } });
        break;
      case 'API':
        await tx.api.create({
          data: { assetId, baseUrl: text(detail.baseUrl), protocol: text(detail.protocol), authType: text(detail.authType) },
        });
        break;
      case 'REPOSITORY':
        await tx.repository.create({
          data: {
            assetId,
            provider: text(detail.provider),
            url: text(detail.url),
            defaultBranch: text(detail.defaultBranch) ?? 'main',
            localPath: text(detail.localPath),
          },
        });
        break;
      case 'CLOUD_ACCOUNT':
        await tx.cloudAccount.create({
          data: {
            assetId,
            provider: text(detail.provider) ?? 'AWS',
            accountId: text(detail.accountId) ?? 'unknown',
            region: text(detail.region),
          },
        });
        break;
      case 'CLOUD_RESOURCE':
        await tx.cloudResource.create({
          data: {
            assetId,
            provider: text(detail.provider) ?? 'AWS',
            resourceType: text(detail.resourceType) ?? 'unknown',
            resourceId: text(detail.resourceId) ?? 'unknown',
            region: text(detail.region),
            accountAssetId: text(detail.accountAssetId),
          },
        });
        break;
      case 'CONTAINER':
        await tx.container.create({
          data: { assetId, image: text(detail.image), runtime: text(detail.runtime), imageAssetId: text(detail.imageAssetId) },
        });
        break;
      case 'CONTAINER_IMAGE':
        await tx.containerImage.create({
          data: { assetId, registry: text(detail.registry), repository: text(detail.repository), tag: text(detail.tag), digest: text(detail.digest) },
        });
        break;
      case 'KUBERNETES_CLUSTER':
        await tx.kubernetesCluster.create({ data: { assetId, version: text(detail.version), distribution: text(detail.distribution) } });
        break;
      case 'KUBERNETES_WORKLOAD':
        await tx.kubernetesWorkload.create({
          data: {
            assetId,
            kind: text(detail.kind) ?? 'Deployment',
            namespace: text(detail.namespace) ?? 'default',
            clusterAssetId: text(detail.clusterAssetId),
          },
        });
        break;
      case 'IDENTITY':
        await tx.identity.create({
          data: { assetId, identityType: text(detail.identityType) ?? 'user', externalId: text(detail.externalId), email: text(detail.email) },
        });
        break;
      case 'SERVICE_ACCOUNT':
        await tx.serviceAccount.create({
          data: { assetId, provider: text(detail.provider) ?? 'kubernetes', externalId: text(detail.externalId) },
        });
        break;
      case 'IAM_ROLE':
        await tx.iamRole.create({
          data: {
            assetId,
            provider: text(detail.provider) ?? 'AWS',
            roleArn: text(detail.roleArn),
            privileged: detail.privileged === true,
          },
        });
        break;
      default:
        break;
    }
  }
}

function kindFor(type: AssetType, detail?: Record<string, unknown>) {
  if (type === 'CLOUD_RESOURCE' && text(detail?.resourceType)?.toLowerCase().includes('s3')) return 'S3_BUCKET' as const;
  const map: Partial<Record<AssetType, 'APPLICATION' | 'API' | 'DOMAIN' | 'ENDPOINT' | 'IDENTITY' | 'IAM_ROLE' | 'SERVER' | 'CONTAINER' | 'DATABASE' | 'KUBERNETES_WORKLOAD' | 'CLOUD_RESOURCE' | 'ASSET'>> = {
    APPLICATION: 'APPLICATION',
    API: 'API',
    DOMAIN: 'DOMAIN',
    ENDPOINT: 'ENDPOINT',
    IDENTITY: 'IDENTITY',
    SERVICE_ACCOUNT: 'IDENTITY',
    IAM_ROLE: 'IAM_ROLE',
    SERVER: 'SERVER',
    CONTAINER: 'CONTAINER',
    CONTAINER_IMAGE: 'CONTAINER',
    DATABASE: 'DATABASE',
    KUBERNETES_WORKLOAD: 'KUBERNETES_WORKLOAD',
    CLOUD_RESOURCE: 'CLOUD_RESOURCE',
  };
  return map[type] ?? 'ASSET';
}
