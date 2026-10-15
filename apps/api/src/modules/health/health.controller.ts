import { Controller, Get, ServiceUnavailableException } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import Redis from 'ioredis';
import { Public } from '../../common/decorators';
import { renderMetrics } from '../../common/metrics';
import { PrismaService } from '../../common/prisma.module';

@ApiTags('health')
@Controller()
export class HealthController {
  constructor(private readonly prisma: PrismaService) {}

  @Public()
  @Get('health')
  @ApiOperation({ summary: 'Liveness probe' })
  health() {
    return { status: 'ok', service: 'api', time: new Date().toISOString() };
  }

  @Public()
  @Get('ready')
  @ApiOperation({ summary: 'Readiness probe for database and redis' })
  async ready() {
    try {
      await this.prisma.db.$queryRaw`SELECT 1`;
      const redis = new Redis(process.env.REDIS_URL ?? 'redis://localhost:6379', { maxRetriesPerRequest: 1, connectTimeout: 2000 });
      const pong = await redis.ping();
      await redis.quit();
      if (pong !== 'PONG') throw new Error('redis');
      return { status: 'ready' };
    } catch {
      throw new ServiceUnavailableException('Dependencies are not ready');
    }
  }

  @Public()
  @Get('metrics')
  @ApiOperation({ summary: 'Prometheus-format process metrics' })
  metrics() {
    return renderMetrics();
  }
}
