import { Body, Controller, Delete, Get, Headers, Param, Patch, Post, Query, Req } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { assetTypes, createAssetSchema, createEndpointSchema, paginationSchema, relationshipSchema, updateAssetSchema } from '@seap/shared';
import { z } from 'zod';
import { RequirePermissions } from '../../common/decorators';
import { requireOrganization } from '../../common/tenant';
import type { AppRequest } from '../../common/types';
import { ZodValidationPipe } from '../../common/zod.pipe';
import { AssetsService } from './assets.service';

const listSchema = paginationSchema.extend({ type: z.enum(assetTypes).optional() });
const csvSchema = z.object({ csv: z.string().min(1).max(500_000) });

@ApiTags('assets')
@ApiBearerAuth()
@Controller('assets')
export class AssetsController {
  constructor(private readonly assets: AssetsService) {}

  @Get()
  @RequirePermissions('asset:read')
  @ApiOperation({ summary: 'List assets in the current organization' })
  list(
    @Req() request: AppRequest,
    @Headers('x-organization-id') organizationHeader: string | undefined,
    @Query(new ZodValidationPipe(listSchema)) query: z.infer<typeof listSchema>,
  ) {
    return this.assets.list(requireOrganization(request.user!, organizationHeader), query);
  }

  @Post()
  @RequirePermissions('asset:write')
  @ApiOperation({ summary: 'Create an asset and its type-specific detail record' })
  create(
    @Req() request: AppRequest,
    @Headers('x-organization-id') organizationHeader: string | undefined,
    @Body(new ZodValidationPipe(createAssetSchema)) body: z.infer<typeof createAssetSchema>,
  ) {
    return this.assets.create(requireOrganization(request.user!, organizationHeader), body, request);
  }

  @Post('import')
  @RequirePermissions('asset:write')
  @ApiOperation({ summary: 'Import assets from a CSV document' })
  importCsv(
    @Req() request: AppRequest,
    @Headers('x-organization-id') organizationHeader: string | undefined,
    @Body(new ZodValidationPipe(csvSchema)) body: { csv: string },
  ) {
    return this.assets.importCsv(requireOrganization(request.user!, organizationHeader), body.csv, request);
  }

  @Post('relationships')
  @RequirePermissions('asset:write')
  @ApiOperation({ summary: 'Create a network relationship between two assets' })
  relate(
    @Req() request: AppRequest,
    @Headers('x-organization-id') organizationHeader: string | undefined,
    @Body(new ZodValidationPipe(relationshipSchema)) body: z.infer<typeof relationshipSchema>,
  ) {
    return this.assets.relate(
      requireOrganization(request.user!, organizationHeader),
      body.sourceAssetId,
      body.targetAssetId,
      body.type,
      request,
    );
  }

  @Get(':id')
  @RequirePermissions('asset:read')
  @ApiOperation({ summary: 'Get an asset' })
  get(
    @Req() request: AppRequest,
    @Headers('x-organization-id') organizationHeader: string | undefined,
    @Param('id') id: string,
  ) {
    return this.assets.get(requireOrganization(request.user!, organizationHeader), id);
  }

  @Get(':id/posture')
  @RequirePermissions('asset:read')
  @ApiOperation({ summary: 'Asset security posture, findings, scans, and attack paths' })
  posture(
    @Req() request: AppRequest,
    @Headers('x-organization-id') organizationHeader: string | undefined,
    @Param('id') id: string,
  ) {
    return this.assets.posture(requireOrganization(request.user!, organizationHeader), id);
  }

  @Patch(':id')
  @RequirePermissions('asset:write')
  @ApiOperation({ summary: 'Update an asset' })
  update(
    @Req() request: AppRequest,
    @Headers('x-organization-id') organizationHeader: string | undefined,
    @Param('id') id: string,
    @Body(new ZodValidationPipe(updateAssetSchema)) body: z.infer<typeof updateAssetSchema>,
  ) {
    return this.assets.update(requireOrganization(request.user!, organizationHeader), id, body, request);
  }

  @Delete(':id')
  @RequirePermissions('asset:write')
  @ApiOperation({ summary: 'Soft-delete an asset' })
  remove(
    @Req() request: AppRequest,
    @Headers('x-organization-id') organizationHeader: string | undefined,
    @Param('id') id: string,
  ) {
    return this.assets.remove(requireOrganization(request.user!, organizationHeader), id, request);
  }

  @Post(':id/endpoints')
  @RequirePermissions('asset:write')
  @ApiOperation({ summary: 'Add an API endpoint to an asset' })
  endpoint(
    @Req() request: AppRequest,
    @Headers('x-organization-id') organizationHeader: string | undefined,
    @Param('id') id: string,
    @Body(new ZodValidationPipe(createEndpointSchema)) body: z.infer<typeof createEndpointSchema>,
  ) {
    return this.assets.addEndpoint(requireOrganization(request.user!, organizationHeader), id, body);
  }
}
