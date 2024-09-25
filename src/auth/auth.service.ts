import {
  BadRequestException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { User } from '@user/user.entity';
import { UserService } from '@user/user.service';
import * as bcrypt from 'bcryptjs';
import { Request, Response } from 'express';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { JwtPayload } from './interfaces/jwt-payload.interface';

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  async validateUser(loginDto: LoginDto) {
    const user = await this.userService.findOneByUsername(loginDto.username);
    if (!user) {
      throw new NotFoundException('User not found');
    }
    if (!(await bcrypt.compare(loginDto.password, user.password))) {
      throw new UnauthorizedException('Invalid credentials');
    }
    return user;
  }

  async login(user: User, res: Response) {
    const payload: JwtPayload = { username: user.username, sub: user.id };
    const accessToken = this.jwtService.sign(payload);
    const refreshToken = await this.generateRefreshToken(user.id);

    res.cookie('access_token', accessToken, {
      httpOnly: true,
      secure: true,
      maxAge: 15 * 60 * 1000,
    });
    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      secure: true,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.status(200).json({ message: 'Login successful' });
  }

  async register(registerDto: RegisterDto) {
    const { email, firstName, lastName, username, password, passwordConfirm } =
      registerDto;
    if (password !== passwordConfirm) {
      throw new BadRequestException('Passwords do not match');
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    return this.userService.create({
      username,
      password: hashedPassword,
      email,
      firstName,
      lastName,
    });
  }

  async generateRefreshToken(userId: number) {
    const secret = this.configService.get<string>('JWT_SECRET');
    const expiresIn = this.configService.get<string>('JWT_EXPIRATION');
    const refreshToken = this.jwtService.sign(
      {
        sub: userId,
      },
      { secret, expiresIn },
    );
    const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);
    await this.userService.updateRefreshToken(userId, hashedRefreshToken);
    return refreshToken;
  }

  async refreshTokens(userId: number, req: Request, res: Response) {
    const user = await this.userService.findOne(userId);

    if (!user || !user.refreshToken) {
      throw new UnauthorizedException('Refresh token not found');
    }

    const refreshTokenMatches = await bcrypt.compare(
      req?.cookies?.refresh_token,
      user.refreshToken,
    );
    if (!refreshTokenMatches) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const newAccessToken = this.jwtService.sign({ sub: user.id });
    const newRefreshToken = await this.generateRefreshToken(userId);

    res.cookie('access_token', newAccessToken, {
      httpOnly: true,
      maxAge: 15 * 60 * 1000,
    });
    res.cookie('refresh_token', newRefreshToken, {
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.status(200).json({ message: 'Tokens refreshed' });
  }

  async logout(res: Response) {
    res.clearCookie('access_token');
    res.clearCookie('refresh_token');
    return res.status(200).json({ message: 'Logout successful' });
  }

  async deleteAccount(userId: number, res: Response) {
    res.clearCookie('access_token');
    res.clearCookie('refresh_token');
    const result = await this.userService.remove(userId);
    if (!result.affected) {
      throw new UnauthorizedException('User not found or already deleted');
    }
    return res.status(200).json({ message: 'Account deleted successfully' });
  }
}
