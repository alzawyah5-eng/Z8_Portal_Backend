import { Module } from '@nestjs/common';
import { AuthModule } from '../auth/auth.module';
import { DatabaseModule } from '../database/database.module';
import { PhotonPayAdminController } from './photonpay-admin.controller';
import { PhotonPayService } from './photonpay.service';

@Module({
  imports: [AuthModule, DatabaseModule],
  controllers: [PhotonPayAdminController],
  providers: [PhotonPayService],
})
export class PhotonPayModule {}
