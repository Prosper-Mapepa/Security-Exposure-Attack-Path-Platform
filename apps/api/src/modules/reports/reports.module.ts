import { Module } from '@nestjs/common';
import { DashboardModule } from '../dashboard/dashboard.module';
import { DashboardService } from '../dashboard/dashboard.service';
import { ReportsController } from './reports.controller';

@Module({
  imports: [DashboardModule],
  controllers: [ReportsController],
  providers: [DashboardService],
})
export class ReportsModule {}
