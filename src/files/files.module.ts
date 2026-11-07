import { Module } from '@nestjs/common';
import { AuthModule } from '../auth/auth.module';
import { DatabaseModule } from '../database/database.module';
import { PrivateFilesController } from './private-files.controller';
import { PrivateFileStorageService } from './private-file-storage.service';

@Module({
  imports: [AuthModule, DatabaseModule],
  controllers: [PrivateFilesController],
  providers: [PrivateFileStorageService],
  exports: [PrivateFileStorageService],
})
export class FilesModule {}
