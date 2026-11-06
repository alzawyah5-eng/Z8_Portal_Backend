import { BadRequestException, Body, Controller, Get, Param, Post, Query, UseGuards } from '@nestjs/common';
import { CurrentUser } from '../../auth/current-user.decorator';
import { FirebaseAuthGuard } from '../../auth/firebase-auth.guard';
import { FirebasePrincipal } from '../../auth/firebase-principal';
import { AssistantService } from './assistant.service';

@Controller('agents/conversations')
@UseGuards(FirebaseAuthGuard)
export class AssistantController {
  constructor(private readonly assistant: AssistantService) {}

  @Get()
  list(@CurrentUser() user: FirebasePrincipal, @Query('agent_name') agentName?: string) {
    return this.assistant.list(user, agentName);
  }

  @Post()
  create(@CurrentUser() user: FirebasePrincipal, @Body() body: { agent_name: string; metadata?: Record<string, unknown> }) {
    return this.assistant.create(user, body);
  }

  @Get(':id')
  get(@CurrentUser() user: FirebasePrincipal, @Param('id') id: string) {
    return this.assistant.get(user, id);
  }

  @Post(':id/messages')
  addMessage(@CurrentUser() user: FirebasePrincipal, @Param('id') id: string, @Body() body: { role?: string; content: string }) {
    if (body.role && body.role !== 'user') throw new BadRequestException('Only user messages can be submitted.');
    return this.assistant.addMessage(user, id, body.content);
  }
}
