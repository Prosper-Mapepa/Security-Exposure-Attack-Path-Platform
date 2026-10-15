import { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { AppModule } from '../src/app.module';

const password = 'Correct-Horse-Battery-1!';

async function register(app: INestApplication, email: string, organizationName: string) {
  const response = await request(app.getHttpServer()).post('/api/auth/register').send({
    email,
    password,
    name: 'Analyst',
    organizationName,
  });
  return response;
}

describe('authentication, tenant isolation, and security controls', () => {
  let app: INestApplication;

  beforeAll(async () => {
    process.env.JWT_ACCESS_SECRET ||= 'test-access-secret-value';
    process.env.MFA_ENCRYPTION_KEY ||= 'test-mfa-key';
    process.env.SCAN_PATH_ALLOWLIST ||= process.cwd();
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] }).compile();
    app = moduleRef.createNestApplication();
    app.setGlobalPrefix('api');
    await app.init();
  });

  afterAll(async () => {
    if (app) await app.close();
  });

  it('registers, logs in, and rejects a bad password', async () => {
    const email = `admin-${Date.now()}@example.com`;
    const created = await register(app, email, `Org ${Date.now()}`);
    expect(created.status).toBe(201);
    expect(created.body.accessToken).toBeTruthy();
    const bad = await request(app.getHttpServer()).post('/api/auth/login').send({ email, password: 'wrong-password-1!' });
    expect(bad.status).toBe(401);
  });

  it('prevents organization A from reading organization B assets', async () => {
    const stamp = Date.now();
    const orgA = await register(app, `a-${stamp}@example.com`, `Alpha ${stamp}`);
    const orgB = await register(app, `b-${stamp}@example.com`, `Beta ${stamp}`);
    const asset = await request(app.getHttpServer())
      .post('/api/assets')
      .set('Authorization', `Bearer ${orgA.body.accessToken}`)
      .send({ name: 'Customer API', type: 'API', environment: 'PRODUCTION', criticality: 'CRITICAL', exposure: 'PUBLIC' });
    expect(asset.status).toBe(201);
    const cross = await request(app.getHttpServer())
      .get(`/api/assets/${asset.body.id}`)
      .set('Authorization', `Bearer ${orgB.body.accessToken}`);
    expect(cross.status).toBe(404);
    const list = await request(app.getHttpServer()).get('/api/assets').set('Authorization', `Bearer ${orgB.body.accessToken}`);
    expect(list.body.data.find((item: { id: string }) => item.id === asset.body.id)).toBeUndefined();
  });

  it('blocks viewers from launching scans and rejects metadata scan targets', async () => {
    const stamp = Date.now();
    const admin = await register(app, `sec-${stamp}@example.com`, `Sec ${stamp}`);
    const token = admin.body.accessToken as string;
    const viewer = await request(app.getHttpServer())
      .post('/api/users')
      .set('Authorization', `Bearer ${token}`)
      .send({ email: `view-${stamp}@example.com`, name: 'Viewer', password, role: 'VIEWER' });
    expect(viewer.status).toBe(201);
    const login = await request(app.getHttpServer()).post('/api/auth/login').send({ email: `view-${stamp}@example.com`, password });
    const asset = await request(app.getHttpServer())
      .post('/api/assets')
      .set('Authorization', `Bearer ${token}`)
      .send({ name: 'Repo', type: 'REPOSITORY' });
    const denied = await request(app.getHttpServer())
      .post('/api/scans')
      .set('Authorization', `Bearer ${login.body.accessToken}`)
      .send({ name: 'scan', scanner: 'SEMGREP', assetId: asset.body.id, targetType: 'PATH', location: process.cwd() });
    expect(denied.status).toBe(403);
    const ssrf = await request(app.getHttpServer())
      .post('/api/scans')
      .set('Authorization', `Bearer ${token}`)
      .send({ name: 'metadata', scanner: 'ZAP', assetId: asset.body.id, targetType: 'URL', location: 'http://169.254.169.254/latest/meta-data' });
    expect(ssrf.status).toBe(400);
  });

  it('treats search input as data and refuses client-side resolution', async () => {
    const stamp = Date.now();
    const admin = await register(app, `find-${stamp}@example.com`, `Find ${stamp}`);
    const token = admin.body.accessToken as string;
    const search = await request(app.getHttpServer())
      .get('/api/assets')
      .query({ q: "' OR 1=1 -- <script>alert(1)</script>" })
      .set('Authorization', `Bearer ${token}`);
    expect(search.status).toBe(200);
    const created = await request(app.getHttpServer())
      .post('/api/assets')
      .set('Authorization', `Bearer ${token}`)
      .send({ name: '<script>alert(1)</script>', type: 'APPLICATION' });
    expect(created.status).toBe(201);
    expect(created.body.name).toBe('<script>alert(1)</script>');
    const resolved = await request(app.getHttpServer())
      .patch('/api/vulnerabilities/does-not-exist/status')
      .set('Authorization', `Bearer ${token}`)
      .send({ status: 'RESOLVED' });
    expect(resolved.status).toBe(400);
  });

  it('returns an empty dashboard instead of placeholder metrics', async () => {
    const stamp = Date.now();
    const admin = await register(app, `dash-${stamp}@example.com`, `Dash ${stamp}`);
    const dashboard = await request(app.getHttpServer()).get('/api/dashboard').set('Authorization', `Bearer ${admin.body.accessToken}`);
    expect(dashboard.status).toBe(200);
    expect(dashboard.body.empty).toBe(true);
    expect(dashboard.body.message).toBe('No security data available');
  });
});
