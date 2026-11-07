import { Controller, Get, Param, Query, Res, UseGuards } from '@nestjs/common';
import { Response } from 'express';
import { AdminGuard } from '../auth/admin.guard';
import { FirebaseAuthGuard } from '../auth/firebase-auth.guard';
import { PrivateFileStorageService } from './private-file-storage.service';

@Controller('files/private')
export class PrivateFilesController {
  constructor(private readonly files: PrivateFileStorageService) {}

  @Get(':fileId/:fileName')
  @UseGuards(FirebaseAuthGuard, AdminGuard)
  async getFile(
    @Param('fileId') fileId: string,
    @Param('fileName') fileName: string,
    @Query('expires') expires: string,
    @Query('signature') signature: string,
    @Res() response: Response,
  ) {
    const result = await this.files.readSigned(fileId, fileName, expires, signature);
    response.set({
      'Content-Type': result.contentType,
      'Content-Length': String(result.bytes.length),
      'Cache-Control': 'private, no-store, max-age=0',
      'X-Content-Type-Options': 'nosniff',
      'Content-Disposition': 'inline',
    });
    return response.send(result.bytes);
  }
}
