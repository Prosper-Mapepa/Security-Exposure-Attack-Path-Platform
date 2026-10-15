import { Module } from '@nestjs/common';
import { AttackPathsController } from './attack-paths.controller';

@Module({ controllers: [AttackPathsController] })
export class AttackPathsModule {}
