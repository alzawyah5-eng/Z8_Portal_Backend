import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AuthModule } from './auth/auth.module';
import { DatabaseModule } from './database/database.module';
import { HealthController } from './health.controller';
import { UsersModule } from './users/users.module';
import { PhotonPayModule } from './photonpay/photonpay.module';
import { NotificationsModule } from './notifications/notifications.module';
import { CardFlowModule } from './card-flow/card-flow.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
      validate: (env) => {
        for (const name of ['DATABASE_URL', 'FIREBASE_PROJECT_ID', 'FIREBASE_GOOGLE_SERVER_CLIENT_ID']) {
          if (!env[name] || env[name].startsWith('replace-with-')) {
            throw new Error(`${name} must be set in Backend_z8-card-flow/.env before starting the API.`);
          }
        }
        const piiKeyValue = String(env.RECORD_PII_ENCRYPTION_KEY ?? '').trim();
        const piiKey = Buffer.from(piiKeyValue, 'base64');
        if (piiKey.length !== 32 || piiKey.toString('base64') !== piiKeyValue) {
          throw new Error('RECORD_PII_ENCRYPTION_KEY must be a stable base64-encoded 32-byte key in Backend_z8-card-flow/.env.');
        }
        const lookupKeyValue = String(env.RECORD_LOOKUP_HMAC_KEY ?? '').trim();
        const lookupKey = Buffer.from(lookupKeyValue, 'base64');
        if (lookupKey.length !== 32 || lookupKey.toString('base64') !== lookupKeyValue) {
          throw new Error('RECORD_LOOKUP_HMAC_KEY must be a stable base64-encoded 32-byte key in Backend_z8-card-flow/.env.');
        }
        return env;
      },
    }),
    DatabaseModule,
    AuthModule,
    UsersModule,
    PhotonPayModule,
    NotificationsModule,
    CardFlowModule,
  ],
  controllers: [HealthController],
})
export class AppModule {}
