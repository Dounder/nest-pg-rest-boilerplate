import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';

import { UsersModule } from '../users/users.module';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { RefreshTokenStrategy, JwtStrategy } from './strategies';
import { RefreshTokenService } from './refresh-token.service';

@Module({
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy, RefreshTokenStrategy, RefreshTokenService],
  imports: [
    UsersModule,

    PassportModule.register({ defaultStrategy: 'jwt' }),

    JwtModule.registerAsync({
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get('jwtSecret'),
        signOptions: { expiresIn: '6h' },
      }),
    }),
  ],
  exports: [AuthService],
})
export class AuthModule {}
