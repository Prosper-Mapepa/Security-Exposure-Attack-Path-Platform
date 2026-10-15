import { Global, Injectable, Module, type OnModuleDestroy } from '@nestjs/common';
import { prisma } from '@seap/db';

@Injectable()
export class PrismaService implements OnModuleDestroy {
  readonly db = prisma;

  async onModuleDestroy(): Promise<void> {
    await prisma.$disconnect();
  }
}

@Global()
@Module({
  providers: [PrismaService],
  exports: [PrismaService],
})
export class PrismaModule {}
