import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { Request } from 'express';
import { FirebasePrincipal } from './firebase-principal';

export const CurrentUser = createParamDecorator(
  (_data: unknown, context: ExecutionContext): FirebasePrincipal =>
    context.switchToHttp().getRequest<Request & { user: FirebasePrincipal }>().user,
);
