import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString, MinLength } from 'class-validator';

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
}
