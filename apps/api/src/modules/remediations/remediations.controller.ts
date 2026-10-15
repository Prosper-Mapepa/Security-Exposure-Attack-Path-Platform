import { BadRequestException, Body, Controller, Get, Headers, NotFoundException, Param, Patch, Post, Req, UploadedFile, UseInterceptors } from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { ApiBearerAuth, ApiConsumes, ApiOperation, ApiTags } from '@nestjs/swagger';
import { commentSchema, createRemediationSchema, taskSchema, updateRemediationSchema } from '@seap/shared';
import { randomToken } from '@seap/security';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import type { z } from 'zod';
import { RequirePermissions } from '../../common/decorators';
import { clientIp } from '../../common/http';
import { PrismaService } from '../../common/prisma.module';
import { requireOrganization } from '../../common/tenant';
import type { AppRequest } from '../../common/types';
import { ZodValidationPipe } from '../../common/zod.pipe';
import { AuditService } from '../audit/audit.service';
import { FindingsService } from '../findings/findings.service';

const ALLOWED = new Map([
  ['image/png', '.png'],
  ['image/jpeg', '.jpg'],
  ['application/pdf', '.pdf'],
  ['text/plain', '.txt'],
  ['application/json', '.json'],
  ['text/csv', '.csv'],
]);

@ApiTags('remediations')
@ApiBearerAuth()
@Controller('remediations')
export class RemediationsController {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
    private readonly findings: FindingsService,
  ) {}

  @Get()
  @RequirePermissions('remediation:read')
  @ApiOperation({ summary: 'List remediation workflows' })
  list(@Req() request: AppRequest, @Headers('x-organization-id') organizationHeader: string | undefined) {
    return this.prisma.db.remediation.findMany({
      where: { organizationId: requireOrganization(request.user!, organizationHeader) },
      include: { vulnerability: true, assignee: { select: { id: true, name: true } }, tasks: true },
      orderBy: { updatedAt: 'desc' },
    });
  }

  @Post()
  @RequirePermissions('remediation:write')
  @ApiOperation({ summary: 'Assign remediation for a vulnerability' })
  async create(
    @Req() request: AppRequest,
    @Headers('x-organization-id') organizationHeader: string | undefined,
    @Body(new ZodValidationPipe(createRemediationSchema)) body: z.infer<typeof createRemediationSchema>,
  ) {
    const organizationId = requireOrganization(request.user!, organizationHeader);
    const vulnerability = await this.prisma.db.vulnerability.findFirst({ where: { id: body.vulnerabilityId, organizationId, deletedAt: null } });
    if (!vulnerability) throw new NotFoundException('Vulnerability was not found');
    const remediation = await this.prisma.db.remediation.create({
      data: {
        organizationId,
        vulnerabilityId: vulnerability.id,
        assigneeId: body.assigneeId,
        dueAt: body.dueAt ? new Date(body.dueAt) : null,
        notes: body.notes,
        status: body.assigneeId ? 'ASSIGNED' : 'OPEN',
        tasks: body.taskTitle ? { create: { title: body.taskTitle, assigneeId: body.assigneeId, dueAt: body.dueAt ? new Date(body.dueAt) : null } } : undefined,
      },
    });
    await this.prisma.db.vulnerability.update({ where: { id: vulnerability.id }, data: { status: 'IN_PROGRESS' } });
    await this.audit.write({
      organizationId,
      userId: request.user?.id,
      action: 'remediation.create',
      resource: 'remediation',
      resourceId: remediation.id,
      ip: clientIp(request.header('x-forwarded-for'), request.ip),
      userAgent: request.header('user-agent'),
    });
    return remediation;
  }

  @Get(':id')
  @RequirePermissions('remediation:read')
  @ApiOperation({ summary: 'Remediation detail' })
  async get(@Req() request: AppRequest, @Headers('x-organization-id') organizationHeader: string | undefined, @Param('id') id: string) {
    const remediation = await this.prisma.db.remediation.findFirst({
      where: { id, organizationId: requireOrganization(request.user!, organizationHeader) },
      include: { tasks: true, comments: { include: { author: { select: { id: true, name: true } } } }, evidence: true, vulnerability: true, assignee: { select: { id: true, name: true } } },
    });
    if (!remediation) throw new NotFoundException('Remediation was not found');
    return remediation;
  }

  @Patch(':id')
  @RequirePermissions('remediation:write')
  @ApiOperation({ summary: 'Update assignment, due date, notes, or workflow status' })
  async update(
    @Req() request: AppRequest,
    @Headers('x-organization-id') organizationHeader: string | undefined,
    @Param('id') id: string,
    @Body(new ZodValidationPipe(updateRemediationSchema)) body: z.infer<typeof updateRemediationSchema>,
  ) {
    const organizationId = requireOrganization(request.user!, organizationHeader);
    const existing = await this.prisma.db.remediation.findFirst({ where: { id, organizationId } });
    if (!existing) throw new NotFoundException('Remediation was not found');
    const remediation = await this.prisma.db.remediation.update({
      where: { id },
      data: {
        assigneeId: body.assigneeId === undefined ? undefined : body.assigneeId,
        dueAt: body.dueAt === undefined ? undefined : body.dueAt ? new Date(body.dueAt) : null,
        notes: body.notes,
        status: body.status,
      },
    });
    await this.audit.write({
      organizationId,
      userId: request.user?.id,
      action: 'remediation.update',
      resource: 'remediation',
      resourceId: id,
      ip: clientIp(request.header('x-forwarded-for'), request.ip),
      userAgent: request.header('user-agent'),
    });
    return remediation;
  }

  @Post(':id/comments')
  @RequirePermissions('remediation:write')
  @ApiOperation({ summary: 'Add a remediation comment' })
  async comment(
    @Req() request: AppRequest,
    @Headers('x-organization-id') organizationHeader: string | undefined,
    @Param('id') id: string,
    @Body(new ZodValidationPipe(commentSchema)) body: { body: string },
  ) {
    const organizationId = requireOrganization(request.user!, organizationHeader);
    const existing = await this.prisma.db.remediation.findFirst({ where: { id, organizationId } });
    if (!existing) throw new NotFoundException('Remediation was not found');
    return this.prisma.db.remediationComment.create({ data: { remediationId: id, authorId: request.user?.id, body: body.body } });
  }

  @Post(':id/tasks')
  @RequirePermissions('remediation:write')
  @ApiOperation({ summary: 'Add a remediation task' })
  async task(
    @Req() request: AppRequest,
    @Headers('x-organization-id') organizationHeader: string | undefined,
    @Param('id') id: string,
    @Body(new ZodValidationPipe(taskSchema)) body: z.infer<typeof taskSchema>,
  ) {
    const organizationId = requireOrganization(request.user!, organizationHeader);
    const existing = await this.prisma.db.remediation.findFirst({ where: { id, organizationId } });
    if (!existing) throw new NotFoundException('Remediation was not found');
    return this.prisma.db.remediationTask.create({
      data: { remediationId: id, title: body.title, description: body.description, assigneeId: body.assigneeId, dueAt: body.dueAt ? new Date(body.dueAt) : null },
    });
  }

  @Post(':id/evidence')
  @RequirePermissions('remediation:write')
  @UseInterceptors(FileInterceptor('file', { limits: { fileSize: Number(process.env.MAX_UPLOAD_BYTES ?? 5_242_880) } }))
  @ApiConsumes('multipart/form-data')
  @ApiOperation({ summary: 'Attach remediation evidence. Executable uploads are rejected.' })
  async evidence(
    @Req() request: AppRequest,
    @Headers('x-organization-id') organizationHeader: string | undefined,
    @Param('id') id: string,
    @UploadedFile() file?: { originalname: string; mimetype: string; size: number; buffer: Buffer },
  ) {
    const organizationId = requireOrganization(request.user!, organizationHeader);
    const existing = await this.prisma.db.remediation.findFirst({ where: { id, organizationId } });
    if (!existing) throw new NotFoundException('Remediation was not found');
    if (!file) throw new BadRequestException('File is required');
    const extension = ALLOWED.get(file.mimetype);
    if (!extension) throw new BadRequestException('File type is not allowed');
    const storageKey = path.join(organizationId, `${randomToken(16)}${extension}`);
    const root = path.resolve(process.env.UPLOAD_DIR ?? './uploads');
    const destination = path.join(root, storageKey);
    await mkdir(path.dirname(destination), { recursive: true });
    await writeFile(destination, file.buffer);
    return this.prisma.db.remediationEvidence.create({
      data: {
        remediationId: id,
        filename: path.basename(file.originalname).slice(0, 180),
        storageKey,
        contentType: file.mimetype,
        size: file.size,
        uploadedById: request.user?.id,
      },
    });
  }

  @Post(':id/validate')
  @RequirePermissions('scan:run')
  @ApiOperation({ summary: 'Validate the fix by re-running the scanner that discovered the finding' })
  validate(@Req() request: AppRequest, @Headers('x-organization-id') organizationHeader: string | undefined, @Param('id') id: string) {
    return this.validateRemediation(requireOrganization(request.user!, organizationHeader), id, request);
  }

  private async validateRemediation(organizationId: string, id: string, request: AppRequest) {
    const remediation = await this.prisma.db.remediation.findFirst({ where: { id, organizationId } });
    if (!remediation) throw new NotFoundException('Remediation was not found');
    return this.findings.validate(organizationId, remediation.vulnerabilityId, request);
  }
}
