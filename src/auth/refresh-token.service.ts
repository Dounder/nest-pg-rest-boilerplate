import { Injectable, OnApplicationBootstrap, OnApplicationShutdown } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import Redis from 'ioredis';

export class InvalidatedRefreshToken extends Error {}

@Injectable()
export class RefreshTokenService implements OnApplicationBootstrap, OnApplicationShutdown {
  private redis: Redis;

  constructor(private configService: ConfigService, private readonly jwtService: JwtService) {}

  onApplicationBootstrap() {
    this.redis = new Redis({
      host: this.configService.get('redisHost'),
      port: this.configService.get('redisPort'),
    });
  }

  onApplicationShutdown() {
    return this.redis.quit();
  }

  async insert(userId: string, tokenId: string) {
    await this.redis.set(userId, tokenId);
  }

  async validate(userId: string, tokenId: string) {
    const storedTokenId = await this.redis.get(userId);

    if (storedTokenId !== tokenId) throw new InvalidatedRefreshToken(`Invalidated refresh token.`);

    // Check if the token expired
    const { exp } = this.jwtService.decode(tokenId) as { exp: number };
    if (exp < Date.now() / 1000) throw new InvalidatedRefreshToken(`Refresh token expired.`);

    return storedTokenId === tokenId;
  }

  async invalidate(userId: string) {
    await this.redis.del(userId);
  }
}
