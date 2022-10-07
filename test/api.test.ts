import 'reflect-metadata';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { AppModule } from '../src/app.module';

let app: INestApplication;
let http: any;

before(async () => {
  const mod = await Test.createTestingModule({
    imports: [AppModule.forRoot({ type: 'sqljs', synchronize: true }, 'test-secret-test-secret-test-secret!')],
  }).compile();
  app = mod.createNestApplication();
  await app.init();
  http = app.getHttpServer();
});

after(async () => app.close());

async function signup(slug: string) {
  const r = await request(http).post('/auth/signup').send({ slug, name: slug.toUpperCase(), email: `owner@${slug}.com`, password: 'correct horse battery' });
  assert.equal(r.status, 201, JSON.stringify(r.body));
  return { tenantId: r.body.tenantId as string, token: r.body.token as string };
}
const auth = (t: string) => ({ Authorization: `Bearer ${t}` });

test('signup, login and per-tenant project isolation', async () => {
  const acme = await signup('acme');
  const globex = await signup('globex');

  const p = await request(http).post(`/t/${acme.tenantId}/projects`).set(auth(acme.token)).send({ name: 'Website' });
  assert.equal(p.status, 201);
  assert.equal(p.body.tenantId, acme.tenantId);

  // globex can't list, read, or even confirm acme's project exists
  assert.deepEqual((await request(http).get(`/t/${globex.tenantId}/projects`).set(auth(globex.token))).body, []);
  assert.equal((await request(http).get(`/t/${globex.tenantId}/projects/${p.body.id}`).set(auth(globex.token))).status, 404);
  // a valid token replayed against another tenant's URL is rejected
  assert.equal((await request(http).get(`/t/${acme.tenantId}/projects`).set(auth(globex.token))).status, 403);

  const login = await request(http).post('/auth/login').send({ tenant: 'acme', email: 'OWNER@acme.com', password: 'correct horse battery' });
  assert.equal(login.status, 200);
  const bad = await request(http).post('/auth/login').send({ tenant: 'acme', email: 'owner@acme.com', password: 'wrong password!!' });
  assert.equal(bad.status, 401);
  const noTenant = await request(http).post('/auth/login').send({ tenant: 'nope', email: 'owner@acme.com', password: 'whatever12345' });
  assert.equal(noTenant.status, 401);
  assert.equal(noTenant.body.message, bad.body.message);
});

test('tenantId in the body cannot redirect a write', async () => {
  const a = await signup('initech');
  const b = await signup('hooli');
  const r = await request(http).post(`/t/${a.tenantId}/projects`).set(auth(a.token)).send({ name: 'Sneaky', tenantId: b.tenantId });
  assert.equal(r.status, 400, 'unknown fields rejected by whitelist validation');
});

test('roles gate actions', async () => {
  const t = await signup('umbrella');
  const base = `/t/${t.tenantId}`;
  const invite = await request(http).post(`${base}/users`).set(auth(t.token)).send({ email: 'v@umbrella.com', role: 'viewer', password: 'viewer-password' });
  assert.equal(invite.status, 201);
  const viewer = (await request(http).post('/auth/login').send({ tenant: 'umbrella', email: 'v@umbrella.com', password: 'viewer-password' })).body.token;

  assert.equal((await request(http).get(`${base}/projects`).set(auth(viewer))).status, 200);
  assert.equal((await request(http).post(`${base}/projects`).set(auth(viewer)).send({ name: 'X' })).status, 403);
  assert.equal((await request(http).get(`${base}/audit`).set(auth(viewer))).status, 403);
  assert.equal((await request(http).patch(`${base}/plan`).set(auth(viewer)).send({ plan: 'pro' })).status, 403);
  assert.equal((await request(http).get(`${base}/projects`)).status, 401);
  assert.equal((await request(http).get(`${base}/projects`).set(auth('garbage'))).status, 401);
});

test('plan limits and upgrades, with an audit trail', async () => {
  const t = await signup('wayne');
  const base = `/t/${t.tenantId}`;
  for (const name of ['a', 'b', 'c']) assert.equal((await request(http).post(`${base}/projects`).set(auth(t.token)).send({ name })).status, 201);
  const fourth = await request(http).post(`${base}/projects`).set(auth(t.token)).send({ name: 'd' });
  assert.equal(fourth.status, 409);
  assert.match(fourth.body.message, /plan limit/);
  assert.equal((await request(http).post(`${base}/projects`).set(auth(t.token)).send({ name: 'a' })).status, 409);

  assert.equal((await request(http).patch(`${base}/plan`).set(auth(t.token)).send({ plan: 'pro' })).status, 200);
  assert.equal((await request(http).post(`${base}/projects`).set(auth(t.token)).send({ name: 'd' })).status, 201);
  // downgrade blocked while over the free limit
  assert.equal((await request(http).patch(`${base}/plan`).set(auth(t.token)).send({ plan: 'free' })).status, 409);

  const audit = (await request(http).get(`${base}/audit`).set(auth(t.token))).body.map((e: any) => e.action);
  assert.deepEqual(audit.slice(0, 2), ['project.created', 'plan.changed']);
  assert.ok(audit.includes('tenant.created'));
});

test('validation and duplicate slugs', async () => {
  assert.equal((await request(http).post('/auth/signup').send({ slug: 'Bad Slug', name: 'x', email: 'a@b.com', password: 'longenough1' })).status, 400);
  await signup('stark');
  assert.equal((await request(http).post('/auth/signup').send({ slug: 'stark', name: 'Stark', email: 'x@y.com', password: 'longenough1' })).status, 409);
});
