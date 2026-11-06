import { Controller, Post, Req, Res, UseGuards } from '@nestjs/common';
import { Request, Response } from 'express';
import { CurrentUser } from '../../auth/current-user.decorator';
import { FirebaseAuthGuard } from '../../auth/firebase-auth.guard';
import { FirebasePrincipal } from '../../auth/firebase-principal';
import { LocalWorkflowContextFactory } from '../workflow-context.factory';
import photonpayCards from './photonpay-cards';
import photonpayDiagnostics from './photonpay-diagnostics';
import photonpaySync from './photonpay-sync';
import sendProgrammeAlert from './send-programme-alert';
import deleteAccount from './delete-account';
import photonpayWebhook from './photonpay-webhook';

async function relay(result: globalThis.Response, response: Response) {
  response.status(result.status);
  result.headers.forEach((value, key) => response.setHeader(key, value));
  response.send(Buffer.from(await result.arrayBuffer()));
}

function makeRequest(req: Request, functionName: string) {
  const body = req.body ?? {};
  const headers = new Headers();
  for (const [key, value] of Object.entries(req.headers)) {
    const normalizedKey = key.toLowerCase();
    if (typeof value === 'string'
      && !normalizedKey.startsWith('x-forwarded-')
      && !normalizedKey.startsWith('cf-')
      && !['forwarded', 'true-client-ip', 'x-real-ip', 'x-client-ip', 'x-z8-client-ip'].includes(normalizedKey)) {
      headers.set(key, value);
    }
  }
  // req.ip honors forwarded headers only when the immediate peer matches the
  // explicitly configured TRUSTED_PROXY_CIDRS list. Caller-supplied proxy IPs
  // are stripped above and cannot be forwarded into the PhotonPay risk input.
  headers.set('x-z8-client-ip', req.ip || req.socket.remoteAddress || '');
  headers.set('content-type', 'application/json');
  return new globalThis.Request(`https://z8.local/v1/functions/${functionName}`, {
    method: req.method, headers, body: req.method === 'GET' || req.method === 'HEAD' ? undefined : JSON.stringify(body),
  });
}

@Controller('functions')
@UseGuards(FirebaseAuthGuard)
export class LegacyFunctionsController {
  constructor(private readonly contextFactory: LocalWorkflowContextFactory) {}

  @Post('photonpayCards')
  async cards(@Req() req: Request, @Res() res: Response, @CurrentUser() user: FirebasePrincipal) {
    return relay(await photonpayCards(makeRequest(req, 'photonpayCards'), this.contextFactory.create(user)), res);
  }
  @Post('photonpayDiagnostics')
  async diagnostics(@Req() req: Request, @Res() res: Response, @CurrentUser() user: FirebasePrincipal) {
    return relay(await photonpayDiagnostics(makeRequest(req, 'photonpayDiagnostics'), this.contextFactory.create(user)), res);
  }
  @Post('photonpayTransactionSync')
  async sync(@Req() req: Request, @Res() res: Response, @CurrentUser() user: FirebasePrincipal) {
    return relay(await photonpaySync(makeRequest(req, 'photonpayTransactionSync'), this.contextFactory.create(user)), res);
  }
  @Post('sendProgrammeAlert')
  async alert(@Req() req: Request, @Res() res: Response, @CurrentUser() user: FirebasePrincipal) {
    return relay(await sendProgrammeAlert(makeRequest(req, 'sendProgrammeAlert'), this.contextFactory.create(user)), res);
  }
  @Post('deleteAccount')
  async deleteUser(@Req() req: Request, @Res() res: Response, @CurrentUser() user: FirebasePrincipal) {
    return relay(await deleteAccount(makeRequest(req, 'deleteAccount'), this.contextFactory.create(user)), res);
  }
}

@Controller('webhooks/photonpay')
export class PhotonPayWebhookController {
  constructor(private readonly contextFactory: LocalWorkflowContextFactory) {}
  @Post()
  async handle(@Req() req: Request, @Res() res: Response) {
    const raw = (req as Request & { rawBody?: Buffer }).rawBody;
    const headers = new Headers();
    for (const [key, value] of Object.entries(req.headers)) if (typeof value === 'string') headers.set(key, value);
    const request = new globalThis.Request('https://z8.local/v1/webhooks/photonpay', {
      method: 'POST', headers, body: raw ? new Uint8Array(raw) : JSON.stringify(req.body ?? {}),
    });
    return relay(await photonpayWebhook(request, this.contextFactory.create()), res);
  }
}
