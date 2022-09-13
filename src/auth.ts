import {
  CanActivate, ExecutionContext, Injectable, SetMetadata, UnauthorizedException, ForbiddenException,
  NestInterceptor, CallHandler,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import { Observable } from 'rxjs';
import { randomBytes, scrypt as scryptCb, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import { Role } from './entities';
import { Principal, tenantContext } from './tenancy';

const scrypt = promisify(scryptCb) as (pw: string, salt: Buffer, len: number) => Promise<Buffer>;

export async function hashPassword(pw: string): Promise<string> {
  const salt = randomBytes(16);
  const key = await scrypt(pw, salt, 32);
  return `scrypt$${salt.toString('base64')}$${key.toString('base64')}`;
}

export async function verifyPassword(pw: string, stored: string): Promise<boolean> {
  const [alg, salt, key] = stored.split('$');
  if (alg !== 'scrypt') return false;
  const expected = Buffer.from(key, 'base64');
  const actual = await scrypt(pw, Buffer.from(salt, 'base64'), expected.length);
  return timingSafeEqual(actual, expected);
}

const ROLE_RANK: Record<Role, number> = { viewer: 0, member: 1, admin: 2, owner: 3 };
export const MinRole = (role: Role) => SetMetadata('minRole', role);
export const Public = () => SetMetadata('public', true);

/**
 * Verifies the bearer token and checks the role requirement. The principal is stored on the request;
 * TenantContextInterceptor then runs the handler inside AsyncLocalStorage so services can read it.
 */
@Injectable()
export class AuthGuard implements CanActivate {
  constructor(private readonly jwt: JwtService, private readonly reflector: Reflector) {}

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const targets = [ctx.getHandler(), ctx.getClass()];
    if (this.reflector.getAllAndOverride<boolean>('public', targets)) return true;
    const req = ctx.switchToHttp().getRequest();
    const header: string = req.headers.authorization ?? '';
    if (!header.startsWith('Bearer ')) throw new UnauthorizedException();
    let claims: { sub: string; tid: string; role: Role };
    try {
      claims = await this.jwt.verifyAsync(header.slice(7));
    } catch {
      throw new UnauthorizedException('invalid token');
    }
    // A tenant slug in the URL must match the token, so a valid token for tenant A can't be replayed at /t/B.
    if (req.params?.tenant && req.params.tenant !== claims.tid) throw new ForbiddenException('token is for a different tenant');
    const min = this.reflector.getAllAndOverride<Role>('minRole', targets) ?? 'viewer';
    if (ROLE_RANK[claims.role] < ROLE_RANK[min]) throw new ForbiddenException(`requires ${min}`);
    req.principal = { userId: claims.sub, tenantId: claims.tid, role: claims.role } satisfies Principal;
    return true;
  }
}

@Injectable()
export class TenantContextInterceptor implements NestInterceptor {
  intercept(ctx: ExecutionContext, next: CallHandler): Observable<unknown> {
    const principal: Principal | undefined = ctx.switchToHttp().getRequest().principal;
    if (!principal) return next.handle();
    return new Observable((sub) => {
      tenantContext.run(principal, () => {
        next.handle().subscribe(sub);
      });
    });
  }
}
