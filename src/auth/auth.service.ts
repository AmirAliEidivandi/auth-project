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
import * as crypto from 'crypto';
import { Request, Response } from 'express';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { RequestPasswordResetDto } from './dto/request-password-reset.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { SendVerificationCodeDto } from './dto/send-verification.dto';
import { VerifyEmailDto } from './dto/verify-email.dto';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { MailerService } from './mailer.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly mailService: MailerService,
  ) {}

  async requestPasswordReset(dto: RequestPasswordResetDto) {
    const user = await this.userService.findByEmail(dto.email);
    if (!user) {
      throw new NotFoundException('User with this email does not exist');
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    const hashedToken = await bcrypt.hash(resetToken, 10);

    // Set token and expiration (1 hour)
    user.resetPasswordToken = hashedToken;
    user.resetPasswordExpires = new Date(Date.now() + 3600000);
    await this.userService.save(user);

    // Send email with the reset token
    const resetUrl = `${this.configService.get(
      'FRONTEND_URL',
    )}/reset-password?token=${hashedToken}`;
    const subject = 'Password Reset';
    const text = `You are receiving this email because you (or someone else) has requested the reset of the password for your account.\n\nPlease click on the following link, or paste this into your browser to complete the process:\n\n${resetUrl}\n\nIf you did not request this, please ignore this email and your password will remain unchanged.\n`;
    const html = `<p>You are receiving this email because you (or someone else) has requested the reset of the password for your account.</p><p>Please click on the following link, or paste this into your browser to complete the process:</p><p><a href="${resetUrl}">${resetUrl}</a></p><p>If you did not request this, please ignore this email and your password will remain unchanged.</p>`;

    await this.mailService.sendMail(user.email, subject, text, html);

    return { message: 'Password reset link sent to email' };
  }

  async resetPassword(dto: ResetPasswordDto) {
    const user = await this.userService.findOneByResetToken(dto.token);
    if (
      !user ||
      !user.resetPasswordExpires ||
      user.resetPasswordExpires < new Date()
    ) {
      throw new BadRequestException('Invalid or expired password reset token');
    }

    if (dto.newPassword !== dto.confirmNewPassword) {
      throw new BadRequestException('Passwords do not match');
    }

    user.password = await bcrypt.hash(dto.newPassword, 10);
    user.resetPasswordToken = null;
    user.resetPasswordExpires = null;
    await this.userService.save(user);
    return { message: 'Password has been reset successfully' };
  }

  async sendVerificationCode(dto: SendVerificationCodeDto) {
    const user = await this.userService.findByEmail(dto.email);
    if (!user) {
      throw new NotFoundException('User with this email does not exist');
    }

    const updatedUser =
      await this.userService.generateEmailVerificationCode(user);

    const subject = 'Email Verification';
    const text = `Your email verification code is: ${updatedUser.emailVerificationCode}`;
    const html = `<p>Your email verification code is: <b>${updatedUser.emailVerificationCode}</b></p>`;

    await this.mailService.sendMail(user.email, subject, text, html);

    return { message: 'Verification code sent to email' };
  }

  async verifyEmail(dto: VerifyEmailDto) {
    const isValid = await this.userService.verifyEmail(
      dto.email,
      dto.verificationCode,
    );
    if (!isValid) {
      throw new BadRequestException('Invalid verification code');
    }
    return { message: 'Email verified successfully' };
  }

  async validateUser(loginDto: LoginDto) {
    const user = await this.userService.findOneByUsername(loginDto.username);
    if (!user) {
      throw new NotFoundException('User not found');
    }
    if (!(await bcrypt.compare(loginDto.password, user.password))) {
      throw new UnauthorizedException('Invalid credentials');
    }
    if (!user.isEmailVerified) {
      throw new UnauthorizedException(
        'Please verify your email before logging in',
      );
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
