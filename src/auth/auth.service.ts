import { Injectable, BadRequestException } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import * as bcrypt from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import * as jwt from 'jsonwebtoken';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
  ) {}

  async validateUser(username: string, password: string) {
    const user = await this.usersService.findByUsername(username);
    if (user && (await bcrypt.compare(password, user.password))) {
      return user;
    }
    return null;
  }

  async login(user: any) {
    const payload = { username: user.username, sub: user.id, role: user.role };
    
    const accessSecret = process.env.JWT_ACCESS_TOKEN_SECRET || 'access_secret';
    const refreshSecret = process.env.JWT_REFRESH_TOKEN_SECRET || 'refresh_secret';
    
    const accessToken = jwt.sign(payload, accessSecret, { expiresIn: '15m' });
    const refreshToken = jwt.sign(payload, refreshSecret, { expiresIn: '7d' });
    
    return {
      access_token: accessToken,
      refresh_token: refreshToken,
    };
  }

  async logout(userId: number) {
    // Just a mock logout for now
    return { message: `User ${userId} logged out.` };
  }

  async refreshTokens(refreshToken: string) {
    // Optional: add logic here
    return { message: 'Tokens refreshed.' };
  }
}
