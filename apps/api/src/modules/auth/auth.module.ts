import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { CsrfGuard, JwtAuthGuard, PermissionsGuard } from './guards';
import { JwtStrategy } from './jwt.strategy';

@Module({
  imports: [
    PassportModule,
    JwtModule.register({
      secret: process.env.JWT_ACCESS_SECRET ?? 'development-only-change-me',
      signOptions: {
        expiresIn: 15 * 60,
        issuer: process.env.JWT_ISSUER ?? 'seap',
      },
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy, JwtAuthGuard, PermissionsGuard, CsrfGuard],
  exports: [AuthService, JwtAuthGuard, PermissionsGuard, CsrfGuard],
})
export class AuthModule {}
