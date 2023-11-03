import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';

import { AuthService } from '../auth.service';
import { JwtPayload } from '../interfaces/auth.interface';

export class InvalidatedRefreshToken extends Error {}

@Injectable()
export class RefreshTokenStrategy extends PassportStrategy(Strategy, 'jwt-refresh-token') {
  private readonly logger = new Logger('RefreshTokenStrategy');

  constructor(private readonly authService: AuthService, configService: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get('jwtSecret'),
    });
  }

  async validate(payload: JwtPayload) {
    const { id } = payload;

    const user = await this.authService.validateUser(id);

    return user;
  }
}
