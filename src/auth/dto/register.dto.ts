import { ApiProperty } from '@nestjs/swagger';
import {
  IsEmail,
  IsNotEmpty,
  IsString,
  Matches,
  MinLength,
} from 'class-validator';

export class RegisterDto {
  @IsString()
  @IsNotEmpty()
  @Matches(/^(?!.*[_.]{2})[a-zA-Z0-9._]{3,20}(?<![_.])$/, {
    message:
      'Username must be between 3-20 characters, and may contain letters, numbers, underscores, and dots. It cannot start or end with a dot or underscore, nor have consecutive dots/underscores.',
  })
  @ApiProperty({
    type: String,
    description: 'The new username for registration',
    example: 'johndoe',
    required: true,
    nullable: false,
  })
  username: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(8)
  @ApiProperty({
    type: String,
    description: 'The new password for registration',
    example: 'password123',
    required: true,
    nullable: false,
  })
  password: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(8)
  @ApiProperty({
    type: String,
    description: 'Confirmation of the new password',
    example: 'password123',
    required: true,
  })
  passwordConfirm: string;

  @IsEmail()
  @IsNotEmpty()
  @Matches(/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/, {
    message: 'Email must be a valid email address',
  })
  @ApiProperty({
    type: String,
    description: 'Email of the user',
    example: 'johndoe@example.com',
    required: true,
  })
  email: string;

  @IsString()
  @IsNotEmpty()
  @ApiProperty({
    type: String,
    description: 'First name of the user',
    example: 'John',
    required: true,
  })
  firstName: string;

  @IsString()
  @IsNotEmpty()
  @ApiProperty({
    type: String,
    description: 'Last name of the user',
    example: 'Doe',
    required: true,
  })
  lastName: string;
}
