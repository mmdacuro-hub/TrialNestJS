import { Injectable, BadRequestException } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import * as bcrypt from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';

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
  async login(user: any) {
    try {
      const payload = { username: user.username, sub: user.id, role: user.role };
      
      // Access token - short lived (15 minutes)
      const accessToken = this.jwtService.sign(payload, { expiresIn: '15m' });
      
      // Refresh token - long lived (7 days) using same service but different expiration
      const refreshToken = this.jwtService.sign(payload, { expiresIn: '7d' });
      
      return {
        access_token: accessToken,
        refresh_token: refreshToken,
      };
    } catch (error) {
      console.error('Login error:', error);
      throw error;
    }
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
