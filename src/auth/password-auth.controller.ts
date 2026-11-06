import { Body, Controller, Post, UseGuards } from '@nestjs/common';
import { CurrentUser } from './current-user.decorator';
import { FirebaseAuthGuard } from './firebase-auth.guard';
import { LegacyPasswordMigrationGuard } from './legacy-password-migration.guard';
import { FirebasePrincipal } from './firebase-principal';
import { PasswordAuthService } from './password-auth.service';
import {
  PasswordCredentialsDto,
  PasswordMigrationDto,
  PasswordResetConfirmDto,
  PasswordResetRequestDto,
  EmailVerificationDto,
} from './password-auth.dto';

@Controller('auth/password')
export class PasswordAuthController {
  constructor(private readonly passwordAuth: PasswordAuthService) {}

  @Post('register')
  register(@Body() body: PasswordCredentialsDto) {
    return this.passwordAuth.register(body.email, body.password);
  }

  @Post('register/verify')
  verifyRegistration(@Body() body: EmailVerificationDto) {
    return this.passwordAuth.verifyEmailAddress(body.email, body.code);
  }

  @Post('register/resend-verification')
  resendVerification(@Body() body: PasswordResetRequestDto) {
    return this.passwordAuth.resendEmailVerification(body.email);
  }

  @Post('login')
  login(@Body() body: PasswordCredentialsDto) {
    return this.passwordAuth.login(body.email, body.password);
  }

  @Post('reset/request')
  requestReset(@Body() body: PasswordResetRequestDto) {
    return this.passwordAuth.requestPasswordReset(body.email);
  }

  @Post('reset/confirm')
  confirmReset(@Body() body: PasswordResetConfirmDto) {
    return this.passwordAuth.confirmPasswordReset(body.email, body.token, body.password);
  }

  @Post('migrate-legacy')
  @UseGuards(LegacyPasswordMigrationGuard)
  migrateLegacy(
    @CurrentUser() principal: FirebasePrincipal,
    @Body() body: PasswordMigrationDto,
  ) {
    return this.passwordAuth.migrateLegacyPassword(
      principal.uid,
      body.password,
      principal.email_verified === true,
    );
  }
}
