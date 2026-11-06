import { Body, Controller, Delete, Get, Param, Post, Patch, UseGuards } from '@nestjs/common';
import { CurrentUser } from '../auth/current-user.decorator';
import { FirebaseAuthGuard } from '../auth/firebase-auth.guard';
import { FirebasePrincipal } from '../auth/firebase-principal';
import { CardFlowEntitiesService } from './card-flow-entities.service';
import { EntityDataDto, EntityQueryDto, EntityUpdateManyDto } from './entity-query.dto';

@Controller('entities/:entity')
@UseGuards(FirebaseAuthGuard)
export class CardFlowEntitiesController {
  constructor(private readonly entities: CardFlowEntitiesService) {}

  @Post('query')
  query(@Param('entity') entity: string, @Body() body: EntityQueryDto, @CurrentUser() principal: FirebasePrincipal) {
    return this.entities.filter(entity, body.filter ?? {}, body, principal);
  }

  @Post('count')
  count(@Param('entity') entity: string, @Body() body: EntityQueryDto, @CurrentUser() principal: FirebasePrincipal) {
    return this.entities.count(entity, body.filter ?? {}, principal);
  }

  @Get(':id')
  get(@Param('entity') entity: string, @Param('id') id: string, @CurrentUser() principal: FirebasePrincipal) {
    return this.entities.get(entity, id, principal);
  }

  @Post()
  create(@Param('entity') entity: string, @Body() body: EntityDataDto, @CurrentUser() principal: FirebasePrincipal) {
    return this.entities.create(entity, body.data, principal);
  }

  @Patch(':id')
  update(@Param('entity') entity: string, @Param('id') id: string, @Body() body: EntityDataDto, @CurrentUser() principal: FirebasePrincipal) {
    return this.entities.update(entity, id, body.data, principal);
  }

  @Post('update-many')
  updateMany(@Param('entity') entity: string, @Body() body: EntityUpdateManyDto, @CurrentUser() principal: FirebasePrincipal) {
    return this.entities.updateMany(entity, body.filter, body.update, principal);
  }

  @Delete(':id')
  remove(@Param('entity') entity: string, @Param('id') id: string, @CurrentUser() principal: FirebasePrincipal) {
    return this.entities.remove(entity, id, principal);
  }
}
