import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator';

export class RegisterDto {
  @IsString()
  @IsNotEmpty()
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
