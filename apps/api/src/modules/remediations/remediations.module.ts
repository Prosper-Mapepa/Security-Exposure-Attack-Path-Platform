import { Module } from '@nestjs/common';
import { FindingsModule } from '../findings/findings.module';
import { RemediationsController } from './remediations.controller';

@Module({ imports: [FindingsModule], controllers: [RemediationsController] })
export class RemediationsModule {}
