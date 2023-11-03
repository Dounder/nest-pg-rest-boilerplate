import { IsNotEmpty, IsString, Matches, MinLength } from 'class-validator';

export class SignInDto {
  @IsString()
  @IsNotEmpty()
  @MinLength(8)
  @Matches(/(?:(?=.*\d)|(?=.*\W+))(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$/, {
    message: 'Password must contain at least 8 characters, one uppercase letter, one lowercase letter and one number',
  })
  password: string;

  @IsNotEmpty()
  username: string;
}
