import { Module } from '@nestjs/common';
import { PositionsController } from './position.controller';
import { PositionsService } from './position.service';
import { DatabaseModule } from '../database/database.module';

@Module({
  imports: [DatabaseModule],
  controllers: [PositionsController],
  providers: [PositionsService],
  exports: [PositionsService],
})
export class PositionsModule {}
