import { Body, Controller, Get, Post, Req, Res } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import {
  forgotPasswordSchema,
  loginSchema,
  mfaCodeSchema,
  registerSchema,
  resetPasswordSchema,
  switchOrgSchema,
} from '@seap/shared';
import type { Response } from 'express';
import { Public } from '../../common/decorators';
import type { AppRequest } from '../../common/types';
import { ZodValidationPipe } from '../../common/zod.pipe';
import { AuthService } from './auth.service';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  @Public()
  @Get('csrf')
  @ApiOperation({ summary: 'Issue a CSRF token cookie for browser sessions' })
  csrf(@Res({ passthrough: true }) response: Response) {
    return this.auth.csrf(response);
  }

  @Public()
  @Post('register')
  @ApiOperation({ summary: 'Create an organization and its first security admin' })
  register(
    @Body(new ZodValidationPipe(registerSchema)) body: { email: string; password: string; name: string; organizationName: string },
    @Req() request: AppRequest,
    @Res({ passthrough: true }) response: Response,
  ) {
    return this.auth.register(body, request, response);
  }

  @Public()
  @Post('login')
  @ApiOperation({ summary: 'Authenticate with email and password' })
  login(
    @Body(new ZodValidationPipe(loginSchema))
    body: { email: string; password: string; organizationSlug?: string; mfaCode?: string },
    @Req() request: AppRequest,
    @Res({ passthrough: true }) response: Response,
  ) {
    return this.auth.login(body, request, response);
  }

  @Public()
  @Post('refresh')
  @ApiOperation({ summary: 'Rotate the refresh token and issue a new access token' })
  refresh(@Req() request: AppRequest, @Res({ passthrough: true }) response: Response) {
    return this.auth.refresh(request, response);
  }

  @Post('logout')
  @ApiOperation({ summary: 'Revoke the refresh-token family and clear cookies' })
  logout(@Req() request: AppRequest, @Res({ passthrough: true }) response: Response) {
    return this.auth.logout(request, response);
  }

  @Get('me')
  @ApiOperation({ summary: 'Return the authenticated principal' })
  me(@Req() request: AppRequest) {
    return this.auth.me(request);
  }

  @Public()
  @Post('forgot-password')
  @ApiOperation({ summary: 'Start a password reset. The response does not reveal whether the account exists.' })
  forgot(@Body(new ZodValidationPipe(forgotPasswordSchema)) body: { email: string }) {
    return this.auth.forgotPassword(body.email);
  }

  @Public()
  @Post('reset-password')
  @ApiOperation({ summary: 'Reset a password with a single-use token' })
  reset(
    @Body(new ZodValidationPipe(resetPasswordSchema)) body: { token: string; password: string },
    @Req() request: AppRequest,
  ) {
    return this.auth.resetPassword(body.token, body.password, request);
  }

  @Post('mfa/enroll')
  @ApiOperation({ summary: 'Begin TOTP enrollment' })
  enroll(@Req() request: AppRequest) {
    return this.auth.enrollMfa(request);
  }

  @Post('mfa/verify')
  @ApiOperation({ summary: 'Verify a TOTP code and enable MFA' })
  verify(@Req() request: AppRequest, @Body(new ZodValidationPipe(mfaCodeSchema)) body: { code: string }) {
    return this.auth.verifyMfa(request, body.code);
  }

  @Post('switch-organization')
  @ApiOperation({ summary: 'Switch the active organization and rotate tokens' })
  switchOrg(
    @Req() request: AppRequest,
    @Body(new ZodValidationPipe(switchOrgSchema)) body: { organizationId: string },
    @Res({ passthrough: true }) response: Response,
  ) {
    return this.auth.switchOrganization(request, body.organizationId, response);
  }
}
