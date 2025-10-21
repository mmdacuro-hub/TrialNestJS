//I added status, address, firstName, lastName, and contactNumber 
// to the validate method so they are available in req.user. If some is missing, it will be null. 
// Now you can access the users ID, username, role, and these extra details.
// I use "?? null" because if it only replace null or undefined without affecting valid values like empty string. 
import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, ExtractJwt } from 'passport-jwt';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: process.env.JWT_ACCESS_TOKEN_SECRET || 'access_secret',
    });
  }

  async validate(payload: any) {
    // payload contains { sub, username, role, status, address, firstName, lastName, contactNumber }
    return { 
      userId: payload.sub,
      username: payload.username, 
      role: payload.role,
      status: payload.status ?? null,
      address: payload.address ?? null,
      firstName: payload.firstName ?? null,
      lastName: payload.lastName ?? null,
      contactNumber: payload.contactNumber ?? null,
    };
  }
}
