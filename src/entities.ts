import { Column, CreateDateColumn, Entity, Index, PrimaryGeneratedColumn } from 'typeorm';

export type Plan = 'free' | 'pro' | 'enterprise';
export type Role = 'owner' | 'admin' | 'member' | 'viewer';

export const PLAN_LIMITS: Record<Plan, { projects: number; seats: number }> = {
  free: { projects: 3, seats: 3 },
  pro: { projects: 50, seats: 25 },
  enterprise: { projects: Infinity, seats: Infinity },
};

@Entity('tenants')
export class Tenant {
  @PrimaryGeneratedColumn('uuid') id: string;
  @Index({ unique: true }) @Column({ length: 40 }) slug: string;
  @Column({ length: 120 }) name: string;
  @Column({ type: 'varchar', length: 16, default: 'free' }) plan: Plan;
  @CreateDateColumn() createdAt: Date;
}

/** Every tenant-owned table carries tenantId; the composite indexes lead with it. */
@Entity('users')
@Index(['tenantId', 'email'], { unique: true })
export class User {
  @PrimaryGeneratedColumn('uuid') id: string;
  @Column() tenantId: string;
  @Column({ length: 200 }) email: string;
  @Column({ select: false }) passwordHash: string;
  @Column({ type: 'varchar', length: 10 }) role: Role;
  @CreateDateColumn() createdAt: Date;
}

@Entity('projects')
@Index(['tenantId', 'name'], { unique: true })
export class Project {
  @PrimaryGeneratedColumn('uuid') id: string;
  @Column() tenantId: string;
  @Column({ length: 120 }) name: string;
  @Column({ default: false }) archived: boolean;
  @Column() createdBy: string;
  @CreateDateColumn() createdAt: Date;
}

@Entity('audit_log')
@Index(['tenantId', 'at'])
export class AuditEntry {
  @PrimaryGeneratedColumn() id: number;
  @Column() tenantId: string;
  @Column() actorId: string;
  @Column({ length: 60 }) action: string;
  @Column({ type: 'text', nullable: true }) detail: string | null;
  @CreateDateColumn() at: Date;
}

export const ENTITIES = [Tenant, User, Project, AuditEntry];
