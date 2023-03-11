# TenantForge

Portfolio reference implementation of a 2022 project, built to show a multi-tenant SaaS API foundation: tenant signup, JWT auth, role-based access, plan limits, and an audit log, with tenant isolation enforced structurally rather than by convention.

**Stack:** NestJS 9, TypeORM 0.3, PostgreSQL (sql.js in tests), `@nestjs/jwt`, class-validator, Node `AsyncLocalStorage`.

## Tenant isolation
Missing a `WHERE tenant_id = ?` in one query is how multi-tenant apps leak data. Here:
- **`TenantRepository`** is the only way services reach tenant-owned tables.
  - Every read is filtered by the caller's tenant.
  - Every write is stamped with it.
  - A write that names a different tenant throws.
- **The tenant comes from the verified JWT** (`tid` claim), propagated with `AsyncLocalStorage`. It never comes from the request body.
  - The ValidationPipe whitelist rejects unknown body fields such as `tenantId`.
  - A token for tenant A used on a `/t/B/...` URL gets 403.
- **No existence leaks:** another tenant's resource ids return **404**, not 403.
- **Composite indexes lead with `tenantId`**, e.g. a unique `(tenantId, email)`.

## Features
- `POST /auth/signup` creates the tenant, its owner and an audit entry in one transaction.
- `POST /auth/login`:
  - Passwords are hashed with scrypt and compared in constant time.
  - The error and timing are the same whether the tenant, the user or the password was wrong.
- **Roles:** `viewer < member < admin < owner`, set per route with `@MinRole()`. A global guard denies by default, and routes opt out with `@Public()`.
- **Plan limits** (free: 3 projects / 3 seats; pro: 50 / 25; enterprise: unlimited):
  - Creating past the limit returns 409 with an upgrade hint.
  - A downgrade is blocked while the tenant is over the new limit.
- **Audit log** of tenant, project, user and plan changes, readable by admins.

## Run and test
```bash
npm install
npm test                 # tsc + 5 e2e suites over HTTP (supertest) against sql.js
docker compose up -d && JWT_SECRET=$(openssl rand -hex 32) npm run build && npm start
```
