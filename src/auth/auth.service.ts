import { BadRequestException, Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import * as bcrypt from 'bcrypt';
import { Repository } from 'typeorm';

import { ExceptionHandler } from '../common/helpers';
import { CreateUserDto } from '../users/dto';
import { User } from '../users/entities/user.entity';
import { SignInDto } from './dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { AuthResponse } from './interfaces/auth.interface';
import { RefreshTokenService } from './refresh-token.service';

@Injectable()
export class AuthService {
  private readonly logger = new Logger('AuthService');

  constructor(
    @InjectRepository(User)
    private readonly usersRepository: Repository<User>,

    private readonly jwtService: JwtService,
    private readonly jwtRefreshService: RefreshTokenService,
    private readonly configService: ConfigService,
  ) {}

  async signUp(createUserDto: CreateUserDto): Promise<AuthResponse> {
    try {
      const { password, ...userData } = createUserDto;

      const user = this.usersRepository.create({
        ...userData,
        password: bcrypt.hashSync(password, 10),
      });

      await this.usersRepository.save(user);
      delete user.password;

      const token = this.createToken(user.id);
      const refreshToken = await this.createRefreshToken(user.id);

      return { accessToken: token, refreshToken, user };
    } catch (error) {
      ExceptionHandler(error);
    }
  }

  async signIn({ username, password }: SignInDto): Promise<AuthResponse> {
    const user = await this.usersRepository.findOneBy({ username });

    if (!user) throw new BadRequestException('Invalid credentials');

    if (!bcrypt.compareSync(password, user.password)) throw new BadRequestException('Invalid credentials');

    delete user.password;

    const token = this.createToken(user.id);

    return { accessToken: token, user };
  }

  async refreshToken(refreshTokenDto: RefreshTokenDto): Promise<AuthResponse> {
    try {
      const { refreshToken } = refreshTokenDto;
      const token = this.jwtService.decode(refreshToken);

      if (!token['id']) throw new UnauthorizedException('Invalid token');

      const tokenId = token['id'];

      await this.jwtRefreshService.validate(tokenId, refreshToken);

      const user = await this.validateUser(tokenId);

      const newToken = this.createToken(user.id);

      return { accessToken: newToken, user };
    } catch (error) {
      this.logger.error(error);

      throw new UnauthorizedException(error.message);
    }
  }

  async renewToken(refreshTokenDto: RefreshTokenDto): Promise<{ refreshToken: string }> {
    try {
      const { refreshToken } = refreshTokenDto;
      const token = this.jwtService.decode(refreshToken);

      if (!token['id']) throw new UnauthorizedException('Invalid token');

      const tokenId = token['id'];

      await this.jwtRefreshService.invalidate(tokenId);

      const user = await this.validateUser(tokenId);

      const newToken = await this.createRefreshToken(user.id);

      return { refreshToken: newToken };
    } catch (error) {
      this.logger.error(error);
      throw new UnauthorizedException('Invalid token');
    }
  }

  async validateUser(id: string): Promise<User> {
    const user = await this.usersRepository.findOneBy({ id });

    if (user.deletedAt) throw new UnauthorizedException(`User is inactive, please contact support`);

    delete user.password;

    return user;
  }

  private createToken(id: string, expiresIn?: string | null) {
    const expires = this.configService.get('jwtExpiresIn');

    return this.jwtService.sign({ id }, { expiresIn: expiresIn || expires });
  }

  private async createRefreshToken(id: string) {
    const refreshToken = this.createToken(id, '7d');

    await this.jwtRefreshService.insert(id, refreshToken);

    return refreshToken;
  }
}
