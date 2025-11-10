import { LogLevel, Logger, ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import helmet from 'helmet';

import { AppModule } from './modules/app/app.module';

async function bootstrap(): Promise<void> {
  const app = await NestFactory.create(AppModule);
  const debugFlag = (process.env.APP_DEBUG ?? '').trim().toLowerCase();
  const enableDebugLogs = debugFlag === 'true' || debugFlag === '1' || debugFlag === 'yes';

  if (enableDebugLogs) {
    const debugLogLevels: LogLevel[] = ['error', 'warn', 'log', 'debug', 'verbose'];
    app.useLogger(debugLogLevels);
    Logger.log('API debug logging enabled', 'Bootstrap');
  }

  const corsOrigins = (process.env.CORS_ORIGINS ?? 'http://localhost:3000')
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);

  app.enableCors({
    origin: corsOrigins,
    credentials: true
  });

  app.use(
    helmet({
      crossOriginResourcePolicy: { policy: 'same-site' }
    })
  );

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      transform: true
    })
  );

  await app.listen(process.env.PORT ?? 3001);
}

void bootstrap();
