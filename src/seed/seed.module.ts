import { Module } from '@nestjs/common';

import { SeedController } from './seed.controller';
import { SeedService } from './seed.service';
import { UsersModule } from '../users/users.module';

@Module({
  controllers: [SeedController],
  providers: [SeedService],
  imports: [UsersModule],
})
export class SeedModule {}
