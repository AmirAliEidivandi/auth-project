import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';

@Injectable()
export class MailerService {
  private transporter: nodemailer.Transporter;

  constructor(private readonly configService: ConfigService) {
    this.transporter = nodemailer.createTransport({
      host: this.configService.get<string>('MAILER_HOST'),
      port: this.configService.get<number>('MAILER_PORT'),
      auth: {
        user: this.configService.get<string>('MAILER_USER'),
        pass: this.configService.get<string>('MAILER_PASSWORD'),
      },
      tls: {
        rejectUnauthorized: false,
      },
    });
  }

  async sendPasswordResetEmail(to: string, url: string) {
    const mailOptions = {
      from: this.configService.get<string>('MAILER_USER'),
      to,
      subject: 'Password Reset Request',
      text: `You requested a password reset. Click the link to reset your password: ${url}`,
      html: `<p>You requested a password reset. Click the link to reset your password:</p> <a href="${url}">${url}</a>`,
    };

    try {
      const info = await this.transporter.sendMail(mailOptions);
      console.log('Email sent: ', info.response);
    } catch (error) {
      console.error('Error sending email: ', error);
      throw new Error('Unable to send email');
    }
  }
}
