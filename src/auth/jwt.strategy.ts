import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { UserService } from '@user/user.service';
import { Request } from 'express';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private readonly userService: UserService) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (request: Request) => {
          const token = request?.cookies?.access_token;
          if (!token) {
            throw new UnauthorizedException('Access token not found');
          }
          return token;
        },
      ]),
      ignoreExpiration: false,
      secretOrKey: 'secret',
    });
  }

  async validate(payload: JwtPayload): Promise<any> {
    const user = await this.userService.findOne(payload.sub);
    if (!user) {
      throw new UnauthorizedException('User not found');
    }
    return user;
  }
}
