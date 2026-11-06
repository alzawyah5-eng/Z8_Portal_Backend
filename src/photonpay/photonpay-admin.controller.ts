import { Controller, Get, ParseIntPipe, Query, UseGuards } from '@nestjs/common';
import { AdminGuard } from '../auth/admin.guard';
import { FirebaseAuthGuard } from '../auth/firebase-auth.guard';
import { PhotonPayService } from './photonpay.service';

@Controller('admin/photonpay')
@UseGuards(FirebaseAuthGuard, AdminGuard)
export class PhotonPayAdminController {
  constructor(private readonly photonPay: PhotonPayService) {}

  @Get('connection')
  connection() {
    return this.photonPay.connectionStatus();
  }

  @Get('balance')
  balance() {
    return this.photonPay.getUsdBalance();
  }

  @Get('cards')
  cards(
    @Query('pageIndex', new ParseIntPipe({ optional: true })) pageIndex?: number,
    @Query('pageSize', new ParseIntPipe({ optional: true })) pageSize?: number,
    @Query('status') status?: string,
    @Query('nickname') nickname?: string,
  ) {
    return this.photonPay.listVirtualCards({ pageIndex, pageSize, status, nickname });
  }
}
