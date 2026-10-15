import { NestFactory } from '@nestjs/core';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import { AppModule } from './app.module';
import { AllExceptionsFilter } from './common/filters';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, { bodyParser: true });
  app.use(helmet());
  app.use(cookieParser());
  const origins = (process.env.CORS_ORIGINS ?? 'http://localhost:5173').split(',').map((origin) => origin.trim());
  app.enableCors({ origin: origins, credentials: true });
  app.use((await import('express')).json({ limit: '1mb' }));
  app.setGlobalPrefix('api', { exclude: ['health', 'ready', 'metrics'] });
  app.useGlobalFilters(new AllExceptionsFilter());
  const config = new DocumentBuilder()
    .setTitle('Security Exposure & Attack Path Platform')
    .setDescription('API for asset exposure, vulnerability ingestion, risk, attack paths, and remediation.')
    .setVersion('1.0.0')
    .addBearerAuth()
    .build();
  SwaggerModule.setup('api/docs', app, SwaggerModule.createDocument(app, config));
  const port = Number(process.env.PORT ?? process.env.API_PORT ?? 4000);
  await app.listen(port, '::');
}

void bootstrap();
