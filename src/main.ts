import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) throw new Error('JWT_SECRET (>=32 chars) is required');
  const app = await NestFactory.create(AppModule.forRoot({
    type: 'postgres',
    url: process.env.DATABASE_URL ?? 'postgres://tenantforge:tenantforge@localhost:5432/tenantforge',
    synchronize: false,
    migrationsRun: true,
  }, process.env.JWT_SECRET));
  app.enableShutdownHooks();
  await app.listen(process.env.PORT ?? 3000);
}

bootstrap();
