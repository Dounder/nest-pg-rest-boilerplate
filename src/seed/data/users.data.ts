import { CreateUserDto } from '../../users/dto';
import { UserRole } from '../../users/enums/user-role.enum';

export const USERS_TO_CREATE: CreateUserDto[] = [
  {
    username: 'admin',
    email: 'admin@admin.com',
    password: 'Aa1234!',
    roles: [UserRole.ADMIN],
  },
];
