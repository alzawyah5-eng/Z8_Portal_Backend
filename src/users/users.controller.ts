import { Body, Controller, Delete, Get, Post, UseGuards } from '@nestjs/common';
import { CurrentUser } from '../auth/current-user.decorator';
import { FirebaseAuthGuard } from '../auth/firebase-auth.guard';
import { FirebasePrincipal } from '../auth/firebase-principal';
import { UsersService } from './users.service';
import { RegisterDeviceDto } from './register-device.dto';
import { RemoveDeviceDto } from './remove-device.dto';

@Controller('me')
@UseGuards(FirebaseAuthGuard)
export class UsersController {
  constructor(private readonly users: UsersService) {}

  @Get()
  getMe(@CurrentUser() principal: FirebasePrincipal) {
    return this.users.getFromFirebase(principal);
  }

  @Post()
  register(@CurrentUser() principal: FirebasePrincipal) {
    return this.users.registerFromFirebase(principal);
  }

  @Post('devices')
  registerDevice(@CurrentUser() principal: FirebasePrincipal, @Body() dto: RegisterDeviceDto) {
    return this.users.registerDevice(principal, dto.token, dto.platform);
  }

  @Delete('devices')
  removeDevice(@CurrentUser() principal: FirebasePrincipal, @Body() dto: RemoveDeviceDto) {
    return this.users.removeDevice(principal, dto.token);
  }
}
