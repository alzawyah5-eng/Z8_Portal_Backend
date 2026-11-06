import 'reflect-metadata';
import { ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import helmet from 'helmet';
import { rateLimit } from 'express-rate-limit';
import express from 'express';
import { AppModule } from './app.module';

async function bootstrap(): Promise<void> {
  const app = await NestFactory.create(AppModule, { bufferLogs: true, bodyParser: false });
  const trustedProxyCidrs = (process.env.TRUSTED_PROXY_CIDRS ?? '')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);
  if (trustedProxyCidrs.length) app.getHttpAdapter().getInstance().set('trust proxy', trustedProxyCidrs);
  app.use(express.json({
    limit: '13mb',
    verify: (request, _response, buffer) => {
      (request as typeof request & { rawBody?: Buffer }).rawBody = Buffer.from(buffer);
    },
  }));
  app.use(express.urlencoded({ extended: true, limit: '13mb' }));
  const allowedOrigins = (process.env.CORS_ORIGINS ?? '')
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);

  app.use(helmet());
  app.use(
    rateLimit({
      windowMs: 60_000,
      limit: 120,
      standardHeaders: 'draft-8',
      legacyHeaders: false,
    }),
  );
  app.use('/v1/auth/password/login', rateLimit({ windowMs: 15 * 60_000, limit: 10 }));
  app.use('/v1/auth/password/register', rateLimit({ windowMs: 60 * 60_000, limit: 5 }));
  app.use('/v1/auth/password/reset/request', rateLimit({ windowMs: 60 * 60_000, limit: 3 }));
  app.use('/v1/auth/password/reset/confirm', rateLimit({ windowMs: 15 * 60_000, limit: 10 }));
  app.use('/v1/auth/password/register/resend-verification', rateLimit({ windowMs: 60 * 60_000, limit: 5 }));
  app.use('/v1/webhooks/photonpay', rateLimit({ windowMs: 60_000, limit: 300 }));
  app.use('/v1/agents/conversations', rateLimit({ windowMs: 60_000, limit: 30 }));
  app.enableCors({
    origin: allowedOrigins,
    methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Authorization', 'Content-Type', 'Idempotency-Key'],
  });
  app.setGlobalPrefix('v1');
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  const port = Number(process.env.PORT ?? 3000);
  const host = process.env.API_HOST ?? (process.env.NODE_ENV === 'production' ? '0.0.0.0' : '127.0.0.1');
  await app.listen(port, host);
  console.log(`Z8 API listening on port ${port}`);
}

void bootstrap();
