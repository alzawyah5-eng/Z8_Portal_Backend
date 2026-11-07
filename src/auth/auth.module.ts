import { Global, Logger, Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { DatabaseModule } from '../database/database.module';
import { applicationDefault, cert, getApps, initializeApp } from 'firebase-admin/app';
import { App } from 'firebase-admin/app';
import { getAuth } from 'firebase-admin/auth';
import { getMessaging } from 'firebase-admin/messaging';
import { FirebaseAuthGuard } from './firebase-auth.guard';
import { AdminGuard } from './admin.guard';
import { GoogleAuthController } from './google-auth.controller';
import { GoogleAuthService } from './google-auth.service';
import { PasswordAuthController } from './password-auth.controller';
import { PasswordAuthService } from './password-auth.service';
import { LegacyPasswordMigrationGuard } from './legacy-password-migration.guard';
import { NotificationsService } from '../notifications/notifications.service';
import * as fs from 'fs';
import * as path from 'path';

const logger = new Logger('AuthModule');

@Module({
  imports: [ConfigModule, DatabaseModule],
  controllers: [GoogleAuthController, PasswordAuthController],
  providers: [
    {
      provide: 'FIREBASE_APP',
      inject: [ConfigService],
      useFactory: (config: ConfigService) => {
        const projectId = config.getOrThrow<string>('FIREBASE_PROJECT_ID');
        if (getApps().length > 0) return getApps()[0];

        // Resolve potential service account credential paths
        const envCred = config.get<string>('GOOGLE_APPLICATION_CREDENTIALS');
        const candidatePaths = [
          envCred ? (path.isAbsolute(envCred) ? envCred : path.resolve(process.cwd(), envCred)) : null,
          path.resolve(process.cwd(), 'secrets/firebase-service-account.json'),
          path.resolve(process.cwd(), 'secrets/firebase-service-account.json.json'),
          path.resolve(process.cwd(), 'firebase-service-account.json'),
        ].filter((p): p is string => Boolean(p && fs.existsSync(p)));

        if (candidatePaths.length > 0) {
          const serviceAccountPath = candidatePaths[0];
          logger.log(`Initializing Firebase Admin SDK with service account credential: ${serviceAccountPath}`);
          return initializeApp({ credential: cert(serviceAccountPath), projectId });
        }

        logger.warn('No service account file found; falling back to applicationDefault(). Custom token signing requires a service account.');
        return initializeApp({ credential: applicationDefault(), projectId });
      },
    },
    { provide: 'FIREBASE_AUTH', inject: ['FIREBASE_APP'], useFactory: (app: App) => getAuth(app) },
    { provide: 'FIREBASE_MESSAGING', inject: ['FIREBASE_APP'], useFactory: (app: App) => getMessaging(app) },
    FirebaseAuthGuard,
    AdminGuard,
    GoogleAuthService,
    PasswordAuthService,
    LegacyPasswordMigrationGuard,
    NotificationsService,
  ],
  exports: ['FIREBASE_AUTH', 'FIREBASE_MESSAGING', FirebaseAuthGuard, AdminGuard, LegacyPasswordMigrationGuard, NotificationsService],
})
@Global()
export class AuthModule {}
