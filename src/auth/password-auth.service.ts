import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Inject,
  Injectable,
  Logger,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Auth } from 'firebase-admin/auth';
import { randomBytes, randomInt, createHmac, timingSafeEqual } from 'node:crypto';
import * as argon2 from 'argon2';
import nodemailer from 'nodemailer';
import { Pool } from 'pg';

@Injectable()
export class PasswordAuthService {
  private readonly logger = new Logger(PasswordAuthService.name);
  private readonly resetPepper: string;

  constructor(
    @Inject('PG_POOL') private readonly db: Pool,
    @Inject('FIREBASE_AUTH') private readonly firebaseAuth: Auth,
    private readonly config: ConfigService,
  ) {
    this.resetPepper = config.get<string>('PASSWORD_RESET_PEPPER', '');
  }

  async register(emailInput: string, password: string) {
    const email = this.normalizeEmail(emailInput);
    const existing = await this.db.query(
      `SELECT id, firebase_uid, role, password_hash
       FROM app_users WHERE lower(email) = lower($1)`,
      [email],
    );
    if (existing.rowCount) {
      const record = existing.rows[0];
      if (record.role === 'admin') {
        throw new ConflictException({
          code: 'admin_account_exists',
          message: 'This email is an administrator account. Use Admin sign-in.',
        });
      }
      if (record.firebase_uid || record.password_hash) {
        throw new ConflictException({ code: 'email_already_registered', message: 'An account already exists for this email.' });
      }
    }

    const passwordHash = await argon2.hash(password, { type: argon2.argon2id });
    let firebaseUser;
    try {
      firebaseUser = await this.firebaseAuth.createUser({
        email,
        emailVerified: false,
        disabled: false,
      });
    } catch (error) {
      if ((error as { code?: string })?.code === 'auth/email-already-exists') {
        throw new ConflictException({
          code: 'email_already_registered',
          message: 'An account already exists for this email. Sign in or reset its password.',
        });
      }
      throw error;
    }

    const client = await this.db.connect();
    let profile;
    try {
      await client.query('BEGIN');
      const invitation = await client.query(
        `SELECT id, firebase_uid, role, password_hash
         FROM app_users WHERE lower(email) = lower($1) FOR UPDATE`,
        [email],
      );
      if (invitation.rowCount) {
        const row = invitation.rows[0];
        if (row.role === 'admin' || row.firebase_uid || row.password_hash) {
          throw new ConflictException({
            code: row.role === 'admin' ? 'admin_account_exists' : 'email_already_registered',
            message: row.role === 'admin'
              ? 'This email is an administrator account. Use Admin sign-in.'
              : 'An account already exists for this email. Sign in or reset its password.',
          });
        }
        const updated = await client.query(
          `UPDATE app_users SET firebase_uid = $2, password_hash = $3,
             created_by_id = COALESCE(created_by_id, $2),
             email_verified = false, last_seen_at = now(), updated_at = now()
           WHERE id = $1 RETURNING id, firebase_uid, email, role`,
          [row.id, firebaseUser.uid, passwordHash],
        );
        profile = updated.rows[0];
      } else {
        const inserted = await client.query(
          `INSERT INTO app_users (firebase_uid, email, email_verified, role, password_hash, created_by_id)
           VALUES ($1, $2, false, 'user', $3, $1)
           RETURNING id, firebase_uid, email, role`,
          [firebaseUser.uid, email, passwordHash],
        );
        profile = inserted.rows[0];
      }
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      try {
        await this.firebaseAuth.deleteUser(firebaseUser.uid);
      } catch {
        this.logger.warn('Could not clean up the unlinked Firebase identity after signup failed.');
      }
      if ((error as { code?: string })?.code === '23505') {
        throw new ConflictException({ code: 'email_already_registered', message: 'An account already exists for this email.' });
      }
      throw error;
    } finally {
      client.release();
    }

    await this.sendEmailVerification(profile.id, email);
    return { verificationRequired: true, email };
  }

  async resendEmailVerification(emailInput: string) {
    const email = this.normalizeEmail(emailInput);
    const result = await this.db.query(
      `SELECT id, firebase_uid, email_verified FROM app_users WHERE lower(email) = lower($1)`, [email],
    );
    const account = result.rows[0];
    if (account?.firebase_uid && !account.email_verified) {
      const firebase = await this.firebaseAuth.getUser(account.firebase_uid).catch(() => null);
      if (firebase && !firebase.disabled && firebase.email?.toLowerCase() === email && !firebase.emailVerified) {
        await this.sendEmailVerification(account.id, email);
      }
    }
    return { message: 'If your account needs email verification, a new code has been sent.' };
  }

  async verifyEmailAddress(emailInput: string, code: string) {
    const email = this.normalizeEmail(emailInput);
    const client = await this.db.connect();
    let user: { id: string; firebase_uid: string; role: string } | undefined;
    try {
      await client.query('BEGIN');
      const result = await client.query(
        `SELECT c.id AS code_id, c.user_id, c.code_hmac, c.expires_at, c.attempts,
                u.firebase_uid, u.role, u.email
         FROM email_verification_codes c JOIN app_users u ON u.id = c.user_id
         WHERE lower(u.email) = lower($1) AND c.consumed_at IS NULL
         ORDER BY c.created_at DESC LIMIT 1 FOR UPDATE OF c`,
        [email],
      );
      const row = result.rows[0];
      if (!row || !row.firebase_uid || row.attempts >= 5 || new Date(row.expires_at).getTime() <= Date.now()) {
        if (row) await client.query('UPDATE email_verification_codes SET consumed_at = now() WHERE id = $1', [row.code_id]);
        await client.query('COMMIT');
        throw new BadRequestException({ code: 'verification_code_invalid', message: 'That code is invalid or expired. Request a new one.' });
      }
      const expected = Buffer.from(row.code_hmac);
      const supplied = this.verificationCodeHmac(row.user_id, code);
      if (expected.length !== supplied.length || !timingSafeEqual(expected, supplied)) {
        const attempts = Number(row.attempts) + 1;
        await client.query(
          `UPDATE email_verification_codes SET attempts = $2,
             consumed_at = CASE WHEN $2 >= 5 THEN now() ELSE consumed_at END WHERE id = $1`,
          [row.code_id, attempts],
        );
        await client.query('COMMIT');
        throw new BadRequestException({ code: 'verification_code_invalid', message: 'That code is invalid or expired. Request a new one.' });
      }
      user = { id: row.user_id, firebase_uid: row.firebase_uid, role: row.role };
      await this.firebaseAuth.updateUser(user.firebase_uid, { emailVerified: true });
      await client.query('UPDATE app_users SET email_verified = true, updated_at = now() WHERE id = $1', [user.id]);
      await client.query('UPDATE email_verification_codes SET consumed_at = now() WHERE user_id = $1 AND consumed_at IS NULL', [user.id]);
      await client.query('COMMIT');
    } catch (error) {
      try { await client.query('ROLLBACK'); } catch { /* transaction already committed */ }
      throw error;
    } finally {
      client.release();
    }
    return this.issueFirebaseSession(user!.firebase_uid, user!.role, email);
  }

  private async sendEmailVerification(userId: string, email: string) {
    this.assertVerificationEmailConfigured();
    const code = String(randomInt(100000, 1_000_000));
    const codeHmac = this.verificationCodeHmac(userId, code);
    const client = await this.db.connect();
    try {
      await client.query('BEGIN');
      await client.query('UPDATE email_verification_codes SET consumed_at = now() WHERE user_id = $1 AND consumed_at IS NULL', [userId]);
      await client.query(
        `INSERT INTO email_verification_codes (user_id, code_hmac, expires_at)
         VALUES ($1, $2, now() + interval '15 minutes')`,
        [userId, codeHmac],
      );
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
    const port = Number(this.config.get<string>('SMTP_PORT', '587'));
    const transporter = nodemailer.createTransport({
      host: this.config.getOrThrow<string>('SMTP_HOST'), port,
      secure: this.config.get<string>('SMTP_SECURE') === 'true' || port === 465,
      auth: { user: this.config.getOrThrow<string>('SMTP_USER'), pass: this.config.getOrThrow<string>('SMTP_PASSWORD') },
    });
    try {
      await transporter.sendMail({
        from: this.config.getOrThrow<string>('SMTP_FROM'), to: email,
        subject: 'Verify your Z8 email',
        text: `Your Z8 verification code is ${code}. It expires in 15 minutes. If you did not create an account, ignore this email.`,
        html: `<p>Your Z8 verification code is:</p><p style="font-size:24px;font-weight:700;letter-spacing:6px">${code}</p><p>It expires in 15 minutes. If you did not create an account, ignore this email.</p>`,
      });
    } catch {
      await this.db.query('UPDATE email_verification_codes SET consumed_at = now() WHERE user_id = $1 AND consumed_at IS NULL', [userId]);
      throw new ServiceUnavailableException({ code: 'email_verification_unavailable', message: 'We could not send a verification code. Try again shortly.' });
    }
  }

  private verificationCodeHmac(userId: string, code: string): Buffer {
    return createHmac('sha256', this.resetPepper).update(`verify:${userId}:${code}`).digest();
  }

  private assertVerificationEmailConfigured(): void {
    if (!this.resetPepper || this.resetPepper.length < 32) {
      throw new ServiceUnavailableException({
        code: 'email_verification_unavailable',
        message: 'Email verification is not configured. Contact Z8 support.',
      });
    }
    for (const name of ['SMTP_HOST', 'SMTP_USER', 'SMTP_PASSWORD', 'SMTP_FROM']) {
      if (!this.config.get<string>(name)) {
        throw new ServiceUnavailableException({
          code: 'email_verification_unavailable',
          message: 'Email verification is not configured. Contact Z8 support.',
        });
      }
    }
  }

  async login(emailInput: string, password: string) {
    const email = this.normalizeEmail(emailInput);
    const result = await this.db.query(
      `SELECT id, firebase_uid, email, role, password_hash, email_verified
       FROM app_users WHERE lower(email) = lower($1)`,
      [email],
    );
    const user = result.rows[0];
    if (!user) throw this.invalidCredentials();
    if (!user.password_hash) {
      const firebaseAccount = user.firebase_uid
        ? await this.firebaseAuth.getUser(user.firebase_uid)
        : null;
      if (!firebaseAccount?.providerData.some((provider) => provider.providerId === 'password')) {
        throw this.invalidCredentials();
      }
      throw new ConflictException({
        code: 'password_migration_required',
        message: 'This account needs a one-time password migration. Sign in again to continue.',
      });
    }
    let valid = false;
    try {
      valid = await argon2.verify(user.password_hash, password);
    } catch {
      this.logger.error('Stored Argon2id password hash could not be verified.');
    }
    if (!valid) throw this.invalidCredentials();
    if (!user.firebase_uid) throw this.invalidCredentials();

    const firebaseUser = await this.firebaseAuth.getUser(user.firebase_uid);
    if (firebaseUser.disabled || firebaseUser.email?.toLowerCase() !== email) {
      throw this.invalidCredentials();
    }
    if (!firebaseUser.emailVerified) {
      throw new ForbiddenException({
        code: 'email_not_verified',
        message: 'Verify your email using the link we sent before signing in.',
      });
    }
    if (!user.email_verified) {
      await this.db.query(
        'UPDATE app_users SET email_verified = true, updated_at = now() WHERE id = $1',
        [user.id],
      );
    }
    await this.db.query('UPDATE app_users SET last_seen_at = now(), updated_at = now() WHERE id = $1', [user.id]);
    return this.issueFirebaseSession(user.firebase_uid, user.role, email);
  }

  async migrateLegacyPassword(firebaseUid: string, password: string, emailVerified: boolean) {
    const hash = await argon2.hash(password, { type: argon2.argon2id });
    const result = await this.db.query(
      `UPDATE app_users SET password_hash = $2, email_verified = email_verified OR $3, updated_at = now()
       WHERE firebase_uid = $1 AND password_hash IS NULL
       RETURNING id`,
      [firebaseUid, hash, emailVerified],
    );
    if (!result.rowCount) {
      const existing = await this.db.query(
        'SELECT 1 FROM app_users WHERE firebase_uid = $1 AND password_hash IS NOT NULL',
        [firebaseUid],
      );
      if (!existing.rowCount) throw new ForbiddenException({ code: 'user_not_registered' });
    }
    await this.firebaseAuth.revokeRefreshTokens(firebaseUid);
    return { migrated: true };
  }

  async requestPasswordReset(emailInput: string) {
    const email = this.normalizeEmail(emailInput);
    this.assertResetEmailConfigured();
    const result = await this.db.query(
      `SELECT id, firebase_uid FROM app_users WHERE lower(email) = lower($1)`,
      [email],
    );
    const account = result.rows[0] as { id: string; firebase_uid: string | null } | undefined;
    if (!account?.firebase_uid) return { message: 'If an account exists for this email, a password reset link has been sent.' };
    let identity;
    try {
      identity = await this.firebaseAuth.getUser(account.firebase_uid);
    } catch {
      return { message: 'If an account exists for this email, a password reset link has been sent.' };
    }
    if (identity.disabled || !identity.emailVerified || identity.email?.toLowerCase() !== email) {
      return { message: 'If an account exists for this email, a password reset link has been sent.' };
    }
    const userId = account.id;

    const token = randomBytes(32).toString('base64url');
    const codeHmac = this.resetCodeHmac(userId, token);
    const client = await this.db.connect();
    try {
      await client.query('BEGIN');
      await client.query(
        'UPDATE password_reset_codes SET consumed_at = now() WHERE user_id = $1 AND consumed_at IS NULL',
        [userId],
      );
      await client.query(
        `INSERT INTO password_reset_codes (user_id, code_hmac, expires_at)
         VALUES ($1, $2, now() + interval '1 hour')`,
        [userId, codeHmac],
      );
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }

    try {
      const host = this.config.getOrThrow<string>('SMTP_HOST');
      const port = Number(this.config.get<string>('SMTP_PORT', '587'));
      const user = this.config.getOrThrow<string>('SMTP_USER');
      const pass = this.config.getOrThrow<string>('SMTP_PASSWORD');
      const from = this.config.getOrThrow<string>('SMTP_FROM');
      const resetUrl = this.config.getOrThrow<string>('PASSWORD_RESET_URL');
      const parsedResetUrl = new URL(resetUrl);
      if (parsedResetUrl.protocol !== 'https:') throw new Error('PASSWORD_RESET_URL must use HTTPS.');
      parsedResetUrl.searchParams.set('email', email);
      parsedResetUrl.searchParams.set('token', token);
      const transporter = nodemailer.createTransport({
        host,
        port,
        secure: this.config.get<string>('SMTP_SECURE') === 'true' || port === 465,
        auth: { user, pass },
      });
      await transporter.sendMail({
        from,
        to: email,
        subject: 'Reset your Z8 password',
        text: `Use this secure link to choose a new Z8 password:\n\n${parsedResetUrl.toString()}\n\nThis link expires in one hour and can only be used once. If you did not request this, ignore this email.`,
        html: `<p>Use this secure link to choose a new Z8 password:</p><p><a href="${parsedResetUrl.toString()}">Reset your Z8 password</a></p><p>This link expires in one hour and can only be used once. If you did not request this, ignore this email.</p>`,
      });
    } catch (error) {
      await this.db.query(
        'UPDATE password_reset_codes SET consumed_at = now() WHERE user_id = $1 AND consumed_at IS NULL',
        [userId],
      );
      this.logger.error('Password reset email delivery failed; reset code invalidated.');
      throw new ServiceUnavailableException({
        code: 'password_reset_unavailable',
        message: 'Password reset email is temporarily unavailable. Contact Z8 support.',
      });
    }
    return { message: 'If an account exists for this email, a password reset link has been sent.' };
  }

  async confirmPasswordReset(emailInput: string, token: string, password: string) {
    const email = this.normalizeEmail(emailInput);
    const passwordHash = await argon2.hash(password, { type: argon2.argon2id });
    const client = await this.db.connect();
    try {
      await client.query('BEGIN');
      const result = await client.query(
        `SELECT r.id, r.user_id, r.code_hmac, r.expires_at, r.attempts, u.firebase_uid
         FROM password_reset_codes r JOIN app_users u ON u.id = r.user_id
         WHERE lower(u.email) = lower($1) AND r.consumed_at IS NULL
         ORDER BY r.created_at DESC LIMIT 1 FOR UPDATE OF r`,
        [email],
      );
      const reset = result.rows[0];
      if (!reset || new Date(reset.expires_at).getTime() <= Date.now()) {
        if (reset) {
          await client.query('UPDATE password_reset_codes SET consumed_at = now() WHERE id = $1', [reset.id]);
        }
        await client.query('COMMIT');
        throw new BadRequestException({ code: 'reset_link_invalid', message: 'This reset link is invalid or expired. Request a new one.' });
      }
      const supplied = this.resetCodeHmac(reset.user_id, token);
      const expected = Buffer.from(reset.code_hmac);
      const actual = Buffer.from(supplied);
      if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
        await client.query('UPDATE password_reset_codes SET consumed_at = now() WHERE id = $1', [reset.id]);
        await client.query('COMMIT');
        throw new BadRequestException({ code: 'reset_link_invalid', message: 'This reset link is invalid or expired. Request a new one.' });
      }
      await client.query(
        'UPDATE app_users SET password_hash = $2, updated_at = now() WHERE id = $1',
        [reset.user_id, passwordHash],
      );
      await client.query('UPDATE password_reset_codes SET consumed_at = now() WHERE id = $1', [reset.id]);
      await client.query('UPDATE password_reset_codes SET consumed_at = now() WHERE user_id = $1 AND id <> $2 AND consumed_at IS NULL', [reset.user_id, reset.id]);
      await client.query('COMMIT');
      if (reset.firebase_uid) await this.firebaseAuth.revokeRefreshTokens(reset.firebase_uid);
      return { message: 'Your password has been reset. You can now sign in.' };
    } catch (error) {
      // A rollback after a commit is harmless; this also closes failed transactions.
      try { await client.query('ROLLBACK'); } catch { /* already committed */ }
      throw error;
    } finally {
      client.release();
    }
  }

  private async issueFirebaseSession(uid: string, role: string, email: string) {
    await this.firebaseAuth.setCustomUserClaims(uid, { admin: role === 'admin', role });
    const firebaseCustomToken = await this.firebaseAuth.createCustomToken(uid, { admin: role === 'admin', role });
    return { firebaseCustomToken, email, role };
  }

  private resetCodeHmac(userId: string, code: string): Buffer {
    return createHmac('sha256', this.resetPepper).update(`${userId}:${code}`).digest();
  }

  private assertResetEmailConfigured(): void {
    if (!this.resetPepper || this.resetPepper.length < 32) {
      throw new ServiceUnavailableException({
        code: 'password_reset_unavailable',
        message: 'Password reset is not configured. Contact Z8 support.',
      });
    }
    for (const name of ['SMTP_HOST', 'SMTP_USER', 'SMTP_PASSWORD', 'SMTP_FROM', 'PASSWORD_RESET_URL']) {
      const value = this.config.get<string>(name);
      if (!value || value.includes('your-hosted-z8-web-app')) {
        throw new ServiceUnavailableException({
          code: 'password_reset_unavailable',
          message: 'Password reset email is not configured. Contact Z8 support.',
        });
      }
    }
  }

  private normalizeEmail(email: string): string {
    return email.trim().toLowerCase();
  }

  private invalidCredentials(): UnauthorizedException {
    return new UnauthorizedException({
      code: 'invalid_credentials',
      message: 'The email or password is incorrect.',
    });
  }
}
