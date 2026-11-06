import { Body, Controller, Post, UseGuards } from '@nestjs/common';
import { CurrentUser } from './current-user.decorator';
import { FirebaseAuthGuard } from './firebase-auth.guard';
import { FirebasePrincipal } from './firebase-principal';
import { GoogleAuthDto } from './google-auth.dto';
import { GoogleAuthService } from './google-auth.service';

@Controller('auth/google')
export class GoogleAuthController {
  constructor(private readonly googleAuth: GoogleAuthService) {}

  @Post('session')
  createSession(@Body() body: GoogleAuthDto) {
    return this.googleAuth.createSession(body.idToken);
  }

  @Post('firebase-session')
  @UseGuards(FirebaseAuthGuard)
  createFirebaseSession(@CurrentUser() principal: FirebasePrincipal) {
    return this.googleAuth.createFirebaseGoogleSession(principal);
  }
}
