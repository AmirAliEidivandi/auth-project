import {
  HttpException,
  HttpStatus,
  ValidationPipe,
  VersioningType,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NestFactory } from '@nestjs/core';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import * as cookieParser from 'cookie-parser';
import helmet from 'helmet';
import * as morgan from 'morgan';
import { AppModule } from './app.module';
import { HttpExceptionFilter } from './filters/http-exception.filter';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);
  const port = configService.get<number>('PORT') || 3000;
  app.use(morgan('dev'));
  app.enableVersioning({
    type: VersioningType.URI,
    prefix: 'api/v',
  });

  app.use(helmet());
  if (['local', 'development'].includes(process.env.NODE_ENV)) {
    const config = new DocumentBuilder()
      .setTitle('Auth API')
      .setDescription('API for authentication system - Version 1')
      .setVersion('1.0')
      .build();
    const document = SwaggerModule.createDocument(app, config);
    SwaggerModule.setup('api/v1/docs', app, document);
  }

  app.use(cookieParser());
  app.enableCors({
    origin: '*',
    credentials: true,
  });
  app.useGlobalFilters(new HttpExceptionFilter());
  app.useGlobalPipes(
    new ValidationPipe({
      transform: true,
      whitelist: true,
      forbidNonWhitelisted: true,
      exceptionFactory: (errors) => {
        return new HttpException(
          {
            message: 'Validation failed',
            errors: errors.map((error) => ({
              field: error.property,
              constraints: error.constraints,
            })),
          },
          HttpStatus.BAD_REQUEST,
        );
      },
    }),
  );
  await app.listen(port, () =>
    console.log(`Application is running on: http://localhost:${port}`),
  );
}
bootstrap();
