import { Module } from '@nestjs/common';
import { PositionsModule } from './positions/position.module';
import { DatabaseModule } from './database/database.module';

@Module({
  imports: [DatabaseModule, PositionsModule],
})
export class AppModule {}
