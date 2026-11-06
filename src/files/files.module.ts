import { Module } from '@nestjs/common';
import { PrivateFilesController } from './private-files.controller';
import { PrivateFileStorageService } from './private-file-storage.service';

@Module({
  controllers: [PrivateFilesController],
  providers: [PrivateFileStorageService],
  exports: [PrivateFileStorageService],
})
export class FilesModule {}
