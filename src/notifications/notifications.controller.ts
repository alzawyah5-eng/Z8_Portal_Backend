import { Controller, Post, UseGuards } from '@nestjs/common';
import { CurrentUser } from '../auth/current-user.decorator';
import { FirebaseAuthGuard } from '../auth/firebase-auth.guard';
import { FirebasePrincipal } from '../auth/firebase-principal';
import { NotificationsService } from './notifications.service';

@Controller('me/notifications')
@UseGuards(FirebaseAuthGuard)
export class NotificationsController {
  constructor(private readonly notifications: NotificationsService) {}

  @Post('test')
  sendTest(@CurrentUser() principal: FirebasePrincipal) {
    return this.notifications.sendTestToUser(principal.uid);
  }
}
