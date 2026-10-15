import { Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { OnGatewayConnection, WebSocketGateway, WebSocketServer } from '@nestjs/websockets';
import Redis from 'ioredis';
import type { Server, Socket } from 'socket.io';

@WebSocketGateway({ namespace: '/ws', cors: { origin: true, credentials: true } })
export class RealtimeGateway implements OnGatewayConnection {
  private readonly logger = new Logger('realtime');

  @WebSocketServer()
  server!: Server;

  constructor(private readonly jwt: JwtService) {}

  async onModuleInit(): Promise<void> {
    const subscriber = new Redis(process.env.REDIS_URL ?? 'redis://localhost:6379', { maxRetriesPerRequest: 1, lazyConnect: true });
    try {
      await subscriber.connect();
    } catch (error) {
      this.logger.warn(error instanceof Error ? error.message : 'redis subscriber unavailable');
      return;
    }
    await subscriber.subscribe('scan.progress');
    subscriber.on('message', (_channel, message) => {
      try {
        const event = JSON.parse(message) as { organizationId?: string; scanId?: string };
        if (event.organizationId) this.server.to(event.organizationId).emit('scan.progress', event);
      } catch (error) {
        this.logger.warn(error instanceof Error ? error.message : 'invalid realtime payload');
      }
    });
  }

  async handleConnection(client: Socket): Promise<void> {
    const token = typeof client.handshake.auth.token === 'string' ? client.handshake.auth.token : '';
    try {
      const payload = await this.jwt.verifyAsync<{ organizationId?: string | null }>(token);
      if (payload.organizationId) await client.join(payload.organizationId);
    } catch {
      client.disconnect();
    }
  }
}
