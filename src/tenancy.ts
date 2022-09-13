import { AsyncLocalStorage } from 'node:async_hooks';
import { ForbiddenException, Injectable, InternalServerErrorException } from '@nestjs/common';
import { DataSource, EntityTarget, FindOptionsWhere, ObjectLiteral, Repository } from 'typeorm';
import { Role } from './entities';

export interface Principal { userId: string; tenantId: string; role: Role }

/** Request-scoped identity without request-scoped providers (which would rebuild the DI graph per request). */
export const tenantContext = new AsyncLocalStorage<Principal>();

export function currentPrincipal(): Principal {
  const p = tenantContext.getStore();
  if (!p) throw new InternalServerErrorException('no tenant context (route missing auth guard?)');
  return p;
}

/**
 * The only way services touch tenant-owned tables. Every read is filtered by the caller's tenantId and
 * every write is stamped with it, so a forgotten WHERE clause can't leak another tenant's rows.
 */
export class TenantRepository<T extends ObjectLiteral & { tenantId: string }> {
  constructor(private readonly repo: Repository<T>) {}

  private scope(where: FindOptionsWhere<T> = {}): FindOptionsWhere<T> {
    return { ...where, tenantId: currentPrincipal().tenantId } as FindOptionsWhere<T>;
  }

  find(where?: FindOptionsWhere<T>, order?: Record<string, 'ASC' | 'DESC'>) {
    return this.repo.find({ where: this.scope(where), order: order as any });
  }

  findOne(where: FindOptionsWhere<T>) {
    return this.repo.findOne({ where: this.scope(where) });
  }

  count(where?: FindOptionsWhere<T>) {
    return this.repo.count({ where: this.scope(where) });
  }

  async save(entity: Partial<T>): Promise<T> {
    const tenantId = currentPrincipal().tenantId;
    if (entity.tenantId && entity.tenantId !== tenantId) throw new ForbiddenException('cross-tenant write');
    return this.repo.save({ ...entity, tenantId } as any);
  }

  async delete(where: FindOptionsWhere<T>) {
    return this.repo.delete(this.scope(where) as any);
  }
}

@Injectable()
export class TenantRepositories {
  constructor(private readonly ds: DataSource) {}
  for<T extends ObjectLiteral & { tenantId: string }>(entity: EntityTarget<T>) {
    return new TenantRepository<T>(this.ds.getRepository(entity));
  }
}
