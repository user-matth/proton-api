import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { User, Token } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import * as nodemailer from 'nodemailer';
import { PrismaService } from 'prisma/prisma.service';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService
  ) { }

  async register(userDto: any): Promise<User> {
    const salt = await bcrypt.genSalt();
    const hashedPassword = await bcrypt.hash(userDto.password, salt);

    const user = await this.prisma.user.create({
      data: {
        email: userDto.email,
        password: hashedPassword,
        name: userDto.name,
        avatar: userDto.avatar,
        username: userDto.username,
      },
    });

    return user;
  }

  async sendMagicLink(email: string) {
    const user = await this.prisma.user.findUnique({
      where: { email },
    });

    if (!user) throw new Error('User not found');

    const jwtToken = this.jwtService.sign(
      { email },
      { expiresIn: '15m' }
    );

    await this.prisma.token.create({
      data: {
        token: jwtToken,
        userId: user.id,
        expiresAt: new Date(new Date().getTime() + 15 * 60000),
      },
    });

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: 'Login Magic Link',
      text: `Click here to login: http://localhost:4200/auth/login?token=${jwtToken}`,
    };

    await transporter.sendMail(mailOptions);

    return { message: 'Magic link sent to your email' };
  }

  async loginWithMagicLink(token: string) {
    try {
      const payload = this.jwtService.verify(token);
  
      const tokenRecord = await this.prisma.token.findUnique({
        where: { token },
        include: { user: true },
      });
  
      if (!tokenRecord || tokenRecord.expiresAt < new Date()) {
        throw new Error('Token expired or invalid');
      }
  
      await this.prisma.token.delete({
        where: { id: tokenRecord.id },
      });
  
      const refreshToken = this.jwtService.sign(
        { userId: tokenRecord.user.id },
        { expiresIn: '30d' } 
      );
  
      await this.prisma.token.create({
        data: {
          token: refreshToken,
          userId: tokenRecord.user.id,
          expiresAt: new Date(new Date().getTime() + 30 * 24 * 60 * 60 * 1000),  // 30 days from now
        },
      });
  
      return {
        user: tokenRecord.user,
        refreshToken
      };
    } catch (error) {
      throw new Error('Token expired or invalid');
    }
  }

  async getUserById(userId: number): Promise<User | null> {
    return this.prisma.user.findUnique({
      where: { id: userId },
    });
  }  
  
}
