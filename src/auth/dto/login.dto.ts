import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class LoginDto {
  @IsString()
  @IsNotEmpty()
  @ApiProperty({
    type: String,
    description: 'The username of the user',
    example: 'johndoe',
    required: true,
    nullable: false,
  })
  username: string;

  @IsString()
  @IsNotEmpty()
  @ApiProperty({
    type: String,
    description: 'The password of the user',
    example: 'password123',
    required: true,
    nullable: false,
  })
  password: string;
}
