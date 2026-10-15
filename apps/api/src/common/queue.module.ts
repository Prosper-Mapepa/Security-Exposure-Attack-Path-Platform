import { BullModule } from '@nestjs/bullmq';
import { Global, Module } from '@nestjs/common';

const queues = BullModule.registerQueue({ name: 'scans' }, { name: 'graph' }, { name: 'maintenance' });

@Global()
@Module({
  imports: [queues],
  exports: [queues],
})
export class QueueModule {}
