import { Controller, Post, Body, Get, Query, UseGuards, Request } from '@nestjs/common';
import { AuthService } from '../service/auth.service';
import { JwtAuthGuard } from '../guard/jwt-auth.guard';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) { }

  @Post('register')
  async register(@Body() userDto: any) {
    return this.authService.register(userDto);
  }

  @Get('send-magic-link')
  async sendMagicLink(@Query('email') email: string) {
    return this.authService.sendMagicLink(email);
  }

  @Get('login')
  async loginWithMagicLink(@Query('token') token: string) {
    return this.authService.loginWithMagicLink(token);
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  async getProfile(@Request() req) {
    return req.user;
  }
  
}
