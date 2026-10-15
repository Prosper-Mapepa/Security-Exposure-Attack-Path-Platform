import { BullModule } from '@nestjs/bullmq';
import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import { randomUUID } from 'node:crypto';
import type { NextFunction, Response } from 'express';
import { PrismaModule } from './common/prisma.module';
import { QueueModule } from './common/queue.module';
import { incrementMetric } from './common/metrics';
import type { AppRequest } from './common/types';
import { AssetsModule } from './modules/assets/assets.module';
import { AttackPathsModule } from './modules/attack-paths/attack-paths.module';
import { AuditModule } from './modules/audit/audit.module';
import { AuthModule } from './modules/auth/auth.module';
import { CsrfGuard, JwtAuthGuard, PermissionsGuard } from './modules/auth/guards';
import { DashboardModule } from './modules/dashboard/dashboard.module';
import { EventsModule } from './modules/events/events.module';
import { FindingsModule } from './modules/findings/findings.module';
import { HealthModule } from './modules/health/health.module';
import { IncidentsModule } from './modules/incidents/incidents.module';
import { NotificationsModule } from './modules/notifications/notifications.module';
import { PoliciesModule } from './modules/policies/policies.module';
import { RealtimeModule } from './modules/realtime/realtime.module';
import { RemediationsModule } from './modules/remediations/remediations.module';
import { ReportsModule } from './modules/reports/reports.module';
import { ScansModule } from './modules/scans/scans.module';
import { UsersModule } from './modules/users/users.module';

@Module({
  imports: [
    ThrottlerModule.forRoot([{ ttl: 60_000, limit: 120 }]),
    BullModule.forRoot({ connection: { url: process.env.REDIS_URL ?? 'redis://localhost:6379' } }),
    QueueModule,
    PrismaModule,
    AuditModule,
    AuthModule,
    UsersModule,
    AssetsModule,
    FindingsModule,
    ScansModule,
    AttackPathsModule,
    IncidentsModule,
    RemediationsModule,
    EventsModule,
    NotificationsModule,
    ReportsModule,
    DashboardModule,
    PoliciesModule,
    HealthModule,
    RealtimeModule,
  ],
  providers: [
    { provide: APP_GUARD, useClass: ThrottlerGuard },
    { provide: APP_GUARD, useClass: JwtAuthGuard },
    { provide: APP_GUARD, useClass: PermissionsGuard },
    { provide: APP_GUARD, useClass: CsrfGuard },
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer): void {
    consumer
      .apply((request: AppRequest, response: Response, next: NextFunction) => {
        const incoming = request.header('x-request-id');
        const requestId = incoming && /^[a-zA-Z0-9-]{8,80}$/.test(incoming) ? incoming : randomUUID();
        request.requestId = requestId;
        response.setHeader('x-request-id', requestId);
        const started = Date.now();
        response.on('finish', () => {
          incrementMetric('http_requests_total', { method: request.method, status: String(response.statusCode) });
          console.info(
            JSON.stringify({
              time: new Date().toISOString(),
              service: 'api',
              level: 'info',
              event: 'http.request',
              requestId,
              method: request.method,
              path: request.path,
              status: response.statusCode,
              durationMs: Date.now() - started,
              userId: request.user?.id,
              organizationId: request.user?.organizationId,
            }),
          );
        });
        next();
      })
      .forRoutes('*');
  }
}
