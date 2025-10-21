import { Injectable, NotFoundException } from '@nestjs/common';
import { DatabaseService } from '../database/database.service';
import { RowDataPacket, OkPacket } from 'mysql2';

@Injectable()
export class PositionsService {
  constructor(private db: DatabaseService) {}

  private pool = () => this.db.getPool();

  // ✅ Create new position
  async create(position_code: string, position_name: string) {
    const [result] = await this.pool().execute<OkPacket>(
      'INSERT INTO positions (position_code, position_name) VALUES (?, ?)',
      [position_code, position_name],
    );

    return {
      id: result.insertId,
      position_code,
      position_name,
    };
  }

  // ✅ Get all positions
  async getAll() {
    const [rows] = await this.pool().execute<RowDataPacket[]>(
      'SELECT * FROM positions',
    );
    return rows;
  }

  // ✅ Get one position by ID
  async findById(id: number) {
    const [rows] = await this.pool().execute<RowDataPacket[]>(
      'SELECT * FROM positions WHERE id = ?',
      [id],
    );

    if (!rows.length) {
      throw new NotFoundException(`Position with ID ${id} not found`);
    }

    return rows[0];
  }

  // ✅ Update position
  async updatePosition(
    id: number,
    partial: { position_code?: string; position_name?: string },
  ) {
    const fields: string[] = [];
    const values: any[] = [];

    if (partial.position_code) {
      fields.push('position_code = ?');
      values.push(partial.position_code);
    }

    if (partial.position_name) {
      fields.push('position_name = ?');
      values.push(partial.position_name);
    }

    if (fields.length === 0) return this.findById(id);

    const sql = `UPDATE positions SET ${fields.join(', ')} WHERE id = ?`;
    values.push(id);

    await this.pool().execute<OkPacket>(sql, values);

    return this.findById(id);
  }

  // ✅ Delete position
  async deletePosition(id: number) {
    const [res] = await this.pool().execute<OkPacket>(
      'DELETE FROM positions WHERE id = ?',
      [id],
    );

    if (res.affectedRows === 0) {
      throw new NotFoundException(`Position with ID ${id} not found`);
    }

    return { message: `Position with ID ${id} deleted successfully` };
  }
}
