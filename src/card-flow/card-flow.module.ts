import { Module } from '@nestjs/common';
import { AuthModule } from '../auth/auth.module';
import { DatabaseModule } from '../database/database.module';
import { NotificationsModule } from '../notifications/notifications.module';
import { CardFlowEntitiesController } from './card-flow-entities.controller';
import { CardFlowEntitiesService } from './card-flow-entities.service';
import { FilesModule } from '../files/files.module';
import { LocalWorkflowContextFactory } from './workflow-context.factory';
import { LegacyFunctionsController, PhotonPayWebhookController } from './legacy/legacy-functions.controller';
import { AssistantController } from './assistant/assistant.controller';
import { AssistantService } from './assistant/assistant.service';
import { WorkflowAutomationService } from './workflow-automation.service';
import { PhotonPayDailySyncService } from './photonpay-daily-sync.service';

@Module({
  imports: [AuthModule, DatabaseModule, NotificationsModule, FilesModule],
  controllers: [CardFlowEntitiesController, LegacyFunctionsController, PhotonPayWebhookController, AssistantController],
  providers: [CardFlowEntitiesService, LocalWorkflowContextFactory, AssistantService, WorkflowAutomationService, PhotonPayDailySyncService],
  exports: [CardFlowEntitiesService],
})
export class CardFlowModule {}
