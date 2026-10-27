import { Module } from '@nestjs/common';
import { RolesController } from './roles.controller';
import { UsersController } from './users.controller';

@Module({ controllers: [UsersController, RolesController] })
export class UsersModule {}
