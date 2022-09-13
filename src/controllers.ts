import { Body, ConflictException, Controller, Delete, Get, HttpCode, NotFoundException, Param, Patch, Post, UnauthorizedException } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { JwtService } from '@nestjs/jwt';
import { IsEmail, IsIn, IsOptional, IsString, Length, Matches } from 'class-validator';
import { DataSource } from 'typeorm';
import { AuditEntry, Plan, PLAN_LIMITS, Project, Role, Tenant, User } from './entities';
import { hashPassword, MinRole, Public, verifyPassword } from './auth';
import { currentPrincipal, TenantRepositories } from './tenancy';

class SignupDto {
  @Matches(/^[a-z][a-z0-9-]{2,39}$/) slug: string;
  @IsString() @Length(2, 120) name: string;
  @IsEmail() email: string;
  @IsString() @Length(10, 200) password: string;
}
class LoginDto {
  @IsString() tenant: string;
  @IsEmail() email: string;
  @IsString() password: string;
}
class InviteDto {
  @IsEmail() email: string;
  @IsIn(['admin', 'member', 'viewer']) role: Role;
  @IsString() @Length(10, 200) password: string;
}
class ProjectDto {
  @IsString() @Length(1, 120) name: string;
}
class ProjectPatch {
  @IsOptional() @IsString() @Length(1, 120) name?: string;
  @IsOptional() archived?: boolean;
}
class PlanDto {
  @IsIn(['free', 'pro', 'enterprise']) plan: Plan;
}

@Controller('auth')
export class AuthController {
  constructor(@InjectDataSource() private readonly ds: DataSource, private readonly jwt: JwtService) {}

  /** Creates the tenant and its owner in one transaction. */
  @Public() @Post('signup')
  async signup(@Body() dto: SignupDto) {
    return this.ds.transaction(async (m) => {
      if (await m.findOne(Tenant, { where: { slug: dto.slug } })) throw new ConflictException('slug taken');
      const tenant = await m.save(Tenant, { slug: dto.slug, name: dto.name, plan: 'free' });
      const user = await m.save(User, { tenantId: tenant.id, email: dto.email.toLowerCase(), passwordHash: await hashPassword(dto.password), role: 'owner' });
      await m.save(AuditEntry, { tenantId: tenant.id, actorId: user.id, action: 'tenant.created', detail: dto.slug });
      return { tenantId: tenant.id, token: await this.jwt.signAsync({ sub: user.id, tid: tenant.id, role: 'owner' }) };
    });
  }

  @Public() @Post('login') @HttpCode(200)
  async login(@Body() dto: LoginDto) {
    const tenant = await this.ds.getRepository(Tenant).findOne({ where: { slug: dto.tenant } });
    const user = tenant && await this.ds.getRepository(User).createQueryBuilder('u').addSelect('u.passwordHash')
      .where('u.tenantId = :t AND u.email = :e', { t: tenant.id, e: dto.email.toLowerCase() }).getOne();
    // Same error and similar timing whether tenant, user or password was wrong.
    const ok = user ? await verifyPassword(dto.password, user.passwordHash) : await verifyPassword(dto.password, 'scrypt$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=').then(() => false);
    if (!tenant || !user || !ok) throw new UnauthorizedException('invalid credentials');
    return { token: await this.jwt.signAsync({ sub: user.id, tid: tenant.id, role: user.role }) };
  }
}

@Controller('t/:tenant')
export class TenantController {
  constructor(private readonly repos: TenantRepositories, @InjectDataSource() private readonly ds: DataSource) {}

  private audit(action: string, detail?: string) {
    return this.repos.for(AuditEntry).save({ actorId: currentPrincipal().userId, action, detail: detail ?? null });
  }

  private async tenant() {
    return this.ds.getRepository(Tenant).findOneByOrFail({ id: currentPrincipal().tenantId });
  }

  @Get('projects')
  list() {
    return this.repos.for(Project).find({ archived: false }, { createdAt: 'ASC' });
  }

  @Post('projects') @MinRole('member')
  async create(@Body() dto: ProjectDto) {
    const projects = this.repos.for(Project);
    const limit = PLAN_LIMITS[(await this.tenant()).plan].projects;
    if (await projects.count() >= limit) throw new ConflictException(`plan limit reached (${limit} projects); upgrade to add more`);
    if (await projects.findOne({ name: dto.name })) throw new ConflictException('project name already used');
    const p = await projects.save({ name: dto.name, createdBy: currentPrincipal().userId });
    await this.audit('project.created', p.name);
    return p;
  }

  @Get('projects/:id')
  async get(@Param('id') id: string) {
    const p = await this.repos.for(Project).findOne({ id });
    if (!p) throw new NotFoundException(); // 404, not 403: don't confirm another tenant's ids exist
    return p;
  }

  @Patch('projects/:id') @MinRole('member')
  async update(@Param('id') id: string, @Body() dto: ProjectPatch) {
    const projects = this.repos.for(Project);
    const p = await projects.findOne({ id });
    if (!p) throw new NotFoundException();
    const saved = await projects.save({ ...p, ...dto });
    await this.audit('project.updated', id);
    return saved;
  }

  @Delete('projects/:id') @MinRole('admin') @HttpCode(204)
  async remove(@Param('id') id: string) {
    const r = await this.repos.for(Project).delete({ id });
    if (!r.affected) throw new NotFoundException();
    await this.audit('project.deleted', id);
  }

  @Post('users') @MinRole('admin')
  async invite(@Body() dto: InviteDto) {
    const users = this.repos.for(User);
    const limit = PLAN_LIMITS[(await this.tenant()).plan].seats;
    if (await users.count() >= limit) throw new ConflictException(`seat limit reached (${limit})`);
    if (await users.findOne({ email: dto.email.toLowerCase() })) throw new ConflictException('user exists');
    const u = await users.save({ email: dto.email.toLowerCase(), role: dto.role, passwordHash: await hashPassword(dto.password) });
    await this.audit('user.invited', `${u.email} as ${u.role}`);
    return { id: u.id, email: u.email, role: u.role };
  }

  @Get('users')
  listUsers() {
    return this.repos.for(User).find({}, { createdAt: 'ASC' });
  }

  @Patch('plan') @MinRole('owner')
  async changePlan(@Body() dto: PlanDto) {
    const t = await this.tenant();
    const projects = await this.repos.for(Project).count();
    if (projects > PLAN_LIMITS[dto.plan].projects) throw new ConflictException(`archive projects first: ${projects} > ${PLAN_LIMITS[dto.plan].projects}`);
    t.plan = dto.plan;
    await this.ds.getRepository(Tenant).save(t);
    await this.audit('plan.changed', dto.plan);
    return t;
  }

  @Get('audit') @MinRole('admin')
  auditLog() {
    return this.repos.for(AuditEntry).find({}, { id: 'DESC' });
  }
}
