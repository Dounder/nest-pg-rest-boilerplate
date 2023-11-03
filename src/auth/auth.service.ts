import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import * as bcrypt from 'bcrypt';
import { Repository } from 'typeorm';

import { ExceptionHandler } from '../common/helpers';
import { CreateUserDto } from '../users/dto';
import { User } from '../users/entities/user.entity';
import { SignInDto } from './dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { AuthResponse, JwtPayload } from './interfaces/auth.interface';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private readonly usersRepository: Repository<User>,

    private readonly jwtService: JwtService,
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

      return { token, user };
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

    return { token, user };
  }

  async refreshToken(refreshTokenDto: RefreshTokenDto): Promise<AuthResponse> {
    const { token } = refreshTokenDto;
    const { id } = this.jwtService.verify(token) as JwtPayload;

    const user = await this.validateUser(id);

    const newToken = this.createToken(user.id);

    return { token: newToken, user };
  }

  async validateUser(id: string): Promise<User> {
    const user = await this.usersRepository.findOneBy({ id });

    if (user.deletedAt) throw new UnauthorizedException(`User is inactive, please contact support`);

    delete user.password;

    return user;
  }

  private createToken(id: string) {
    return this.jwtService.sign({ id });
  }
}
