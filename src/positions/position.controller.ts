import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Body,
  Param,
  UseGuards,
} from '@nestjs/common';
import { PositionsService } from './position.service';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';

@Controller('positions')
export class PositionsController {
  constructor(private readonly positionsService: PositionsService) {}

  @Get()
  getAll() {
    return this.positionsService.getAll();
  }

  @Get(':id')
  getOne(@Param('id') id: string) {
    return this.positionsService.findById(+id);
  }

  @Post()
  create(@Body() body: { position_code: string; position_name: string }) {
    const { position_code, position_name } = body;
    return this.positionsService.create(position_code, position_name);
  }

  @Put(':id')
  update(
    @Param('id') id: string,
    @Body() body: { position_code?: string; position_name?: string },
  ) {
    return this.positionsService.updatePosition(+id, body);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.positionsService.deletePosition(+id);
  }
}
