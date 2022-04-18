import { DynamicModule, Module, ValidationPipe } from '@nestjs/common';
import { APP_GUARD, APP_INTERCEPTOR, APP_PIPE } from '@nestjs/core';
import { JwtModule } from '@nestjs/jwt';
import { TypeOrmModule, TypeOrmModuleOptions } from '@nestjs/typeorm';
import { AuthGuard, TenantContextInterceptor } from './auth';
import { AuthController, TenantController } from './controllers';
import { ENTITIES } from './entities';
import { TenantRepositories } from './tenancy';

@Module({})
export class AppModule {
  static forRoot(db: TypeOrmModuleOptions, jwtSecret: string): DynamicModule {
    return {
      module: AppModule,
      imports: [
        TypeOrmModule.forRoot({ ...db, entities: ENTITIES } as TypeOrmModuleOptions),
        JwtModule.register({ secret: jwtSecret, signOptions: { expiresIn: '1h', issuer: 'tenantforge' }, verifyOptions: { issuer: 'tenantforge' } }),
      ],
      controllers: [AuthController, TenantController],
      providers: [
        TenantRepositories,
        { provide: APP_GUARD, useClass: AuthGuard },
        { provide: APP_INTERCEPTOR, useClass: TenantContextInterceptor },
        { provide: APP_PIPE, useValue: new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }) },
      ],
    };
  }
}
