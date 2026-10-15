import { Queue, Worker } from 'bullmq';
import Redis from 'ioredis';
import { executeScan, rebuildGraph, runMaintenance } from './pipeline';

const connection = { url: process.env.REDIS_URL ?? 'redis://localhost:6379' };

function log(event: string, fields: Record<string, unknown> = {}) {
  console.info(JSON.stringify({ time: new Date().toISOString(), service: 'worker', level: 'info', event, ...fields }));
}

async function main() {
  const redis = new Redis(connection.url, { maxRetriesPerRequest: 1 });
  await redis.ping();
  await redis.quit();

  const maintenance = new Queue('maintenance', { connection });
  await maintenance.add('tick', {}, { repeat: { every: 60 * 60 * 1000 }, jobId: 'maintenance-hourly' });

  const scanWorker = new Worker(
    'scans',
    async (job) => {
      const scanId = String((job.data as { scanId?: string }).scanId ?? '');
      if (!scanId) return;
      log('scan.start', { scanId });
      await executeScan(scanId);
    },
    { connection, concurrency: 2 },
  );
  const graphWorker = new Worker(
    'graph',
    async (job) => {
      const organizationId = String((job.data as { organizationId?: string }).organizationId ?? '');
      if (!organizationId) return;
      await rebuildGraph(organizationId);
    },
    { connection, concurrency: 1 },
  );
  const maintenanceWorker = new Worker('maintenance', async () => runMaintenance(), { connection, concurrency: 1 });

  for (const worker of [scanWorker, graphWorker, maintenanceWorker]) {
    worker.on('failed', (job, error) => log('job.failed', { queue: worker.name, jobId: job?.id, message: error.message }));
  }
  log('worker.ready', {});
}

void main();
