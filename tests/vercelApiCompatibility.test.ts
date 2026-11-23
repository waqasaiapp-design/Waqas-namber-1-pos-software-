import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import http from 'node:http';

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'waqas-vercel-compat-'));
const tempDataDir = path.join(tempRoot, 'data');
fs.mkdirSync(tempDataDir, { recursive: true });

// Copy repository seed data into isolated temp dir BEFORE importing api/index.ts
fs.cpSync(path.join(process.cwd(), 'data'), tempDataDir, { recursive: true });

// Seed deterministic test Super Admin credentials inside isolated test env ONLY
const testSaSalt = crypto.randomBytes(16).toString('hex');
const testSaPassword = `TestSa#${Date.now()}!`;
const testSaHash = `scrypt:${crypto.scryptSync(testSaPassword, testSaSalt, 64).toString('hex')}`;
const testSaEmail = 'muhammedsaad255251@gmail.com';

process.env.VERCEL = '1';
process.env.VERCEL_ENV = 'production';
process.env.WAQAS_DATA_DIR = tempDataDir;
process.env.SESSION_SECRET = 'test-vercel-hmac-secret-key-2026';
process.env.SUPER_ADMIN_EMAIL = testSaEmail;
process.env.SUPER_ADMIN_PASSWORD_SALT = testSaSalt;
process.env.SUPER_ADMIN_PASSWORD_HASH = testSaHash;

async function startVercelSimulatedServer() {
  const { default: vercelHandler } = await import('../api/index');
  const server = http.createServer((req, res) => {
    void vercelHandler(req as any, res);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address() as { port: number };
  return { server, baseUrl: `http://127.0.0.1:${addr.port}` };
}

async function invokePreParsedVercelHandler(
  method: string,
  url: string,
  bodyObj: any,
  headers: Record<string, string> = {}
): Promise<{ status: number; headers: http.OutgoingHttpHeaders; json: any; text: string }> {
  const { default: vercelHandler } = await import('../api/index');
  const srv = http.createServer((req, res) => {
    // Simulate @vercel/node pre-parsing request body and finishing the stream
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      if (raw) {
        try {
          (req as any).body = JSON.parse(raw);
        } catch {
          (req as any).body = raw;
        }
      } else if (bodyObj !== undefined) {
        (req as any).body = bodyObj;
      }
      void vercelHandler(req as any, res);
    });
  });

  await new Promise<void>((resolve) => srv.listen(0, '127.0.0.1', resolve));
  const port = (srv.address() as { port: number }).port;
  try {
    const res = await fetch(`http://127.0.0.1:${port}${url}`, {
      method,
      headers: {
        'Content-Type': 'application/json',
        ...headers,
      },
      body: method === 'GET' || method === 'HEAD' || method === 'OPTIONS' ? undefined : JSON.stringify(bodyObj ?? {}),
    });
    const text = await res.text();
    let json: any = null;
    try {
      json = text ? JSON.parse(text) : {};
    } catch {}
    return { status: res.status, headers: Object.fromEntries(res.headers.entries()), json, text };
  } finally {
    await new Promise<void>((resolve) => srv.close(() => resolve()));
  }
}

async function runTests() {
  let server: http.Server | null = null;
  try {
    console.log('1. Checking vercel.json rewrites & serverless function configuration...');
    const vercelCfg = JSON.parse(fs.readFileSync(path.join(process.cwd(), 'vercel.json'), 'utf8'));
    assert.ok(vercelCfg.functions?.['api/index.ts'], 'vercel.json must configure functions["api/index.ts"]');
    assert.equal(vercelCfg.functions['api/index.ts'].includeFiles, 'data/**', 'vercel.json must include data/**');
    const hasApiWildcardRewrite = (vercelCfg.rewrites || []).some(
      (r: any) => r.source === '/api/(.*)' && r.destination === '/api/index?__api_path=$1'
    );
    assert.equal(hasApiWildcardRewrite, true, 'vercel.json must rewrite /api/(.*) to /api/index?__api_path=$1');

    console.log('2. Starting simulated Vercel serverless server...');
    const started = await startVercelSimulatedServer();
    server = started.server;
    const baseUrl = started.baseUrl;

    console.log('3. Testing /api/health via Vercel rewrite query param...');
    const healthRes = await fetch(`${baseUrl}/api/index?__api_path=health`);
    assert.equal(healthRes.status, 200);
    const healthJson = await healthRes.json();
    assert.equal(healthJson.status, 'healthy');
    assert.equal(healthJson.version, '3.2.8');
    assert.equal(healthJson.runtime.serverless, true);
    assert.equal(healthJson.runtime.storageMode, 'serverless-tmp');

    console.log('4. Testing CORS OPTIONS preflight (Origin echo, no wildcard, x-session-token allowed)...');
    const preflightRes = await fetch(`${baseUrl}/api/index?__api_path=devices/pairing-session`, {
      method: 'OPTIONS',
      headers: { Origin: 'https://waqas-pos.vercel.app' },
    });
    assert.equal(preflightRes.status, 204);
    assert.equal(preflightRes.headers.get('access-control-allow-origin'), 'https://waqas-pos.vercel.app');
    assert.equal(preflightRes.headers.get('access-control-allow-credentials'), 'true');
    const allowHeaders = (preflightRes.headers.get('access-control-allow-headers') || '').toLowerCase();
    assert.ok(allowHeaders.includes('x-session-token'), 'x-session-token header must be allowed in CORS');
    assert.ok(allowHeaders.includes('x-shop-id'), 'x-shop-id header must be allowed in CORS');

    console.log('5. Verifying Super Admin Login works (NOT HTTP 405) with pre-parsed Vercel body...');
    const saLoginPreParsed = await invokePreParsedVercelHandler(
      'POST',
      '/api/index?__api_path=auth/super-admin/login',
      { gmail: testSaEmail, password: testSaPassword },
      { Origin: 'https://waqas-pos.vercel.app' }
    );
    assert.equal(saLoginPreParsed.status, 200, `Expected 200 for Super Admin login, got ${saLoginPreParsed.status}: ${saLoginPreParsed.text}`);
    assert.equal(saLoginPreParsed.json?.success, true);
    assert.ok(saLoginPreParsed.json?.token?.startsWith('SA.'), 'Super Admin token must use HMAC-signed SA.* format');

    console.log('6. Verifying Mart Login works (NOT HTTP 405) via Vercel rewrite...');
    const martRes = await fetch(`${baseUrl}/api/index?__api_path=auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ portal: 'shop', identifier: 'waqasmart', password: 'ShopOwner@123' }),
    });
    assert.equal(martRes.status, 200, `Expected 200 for Mart login, got ${martRes.status}`);
    const martJson = await martRes.json();
    assert.equal(martJson.success, true);
    assert.ok(martJson.token?.startsWith('SO.'), 'Mart Owner token must use HMAC-signed SO.* format');
    const shopToken = martJson.token as string;

    console.log('7. Testing Multi Connect QR pairing-session & full approval flow (NO HTTP 403 HTML)...');
    // Unauthenticated call must return JSON 401 (never HTML 403)
    const unauthQrRes = await fetch(`${baseUrl}/api/index?__api_path=devices/pairing-session`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    });
    assert.equal(unauthQrRes.status, 401);
    const unauthQrJson = await unauthQrRes.json();
    assert.equal(unauthQrJson.error, 'AUTH_REQUIRED');

    // Authenticated call with pre-parsed body (exactly how @vercel/node delivers requests)
    const qrRes = await invokePreParsedVercelHandler(
      'POST',
      '/api/index?__api_path=devices/pairing-session',
      {},
      { Authorization: `Bearer ${shopToken}` }
    );
    assert.equal(qrRes.status, 200, `Expected 200 for /api/devices/pairing-session, got ${qrRes.status}: ${qrRes.text}`);
    assert.equal(qrRes.json?.success, true);
    assert.ok(qrRes.json?.pairingToken && qrRes.json?.manualCode);

    const { pairingToken } = qrRes.json;

    const pairRes = await fetch(`${baseUrl}/api/index?__api_path=devices/pair`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tokenOrCode: pairingToken,
        device: {
          deviceId: 'DEV-VERCEL-TEST-1',
          deviceName: 'Vercel Cashier Phone',
          deviceType: 'Android Mobile',
          browser: 'Chrome',
          os: 'Android',
        },
      }),
    });
    assert.equal(pairRes.status, 200);
    const pairJson = await pairRes.json();
    assert.equal(pairJson.success, true);

    const approveRes = await fetch(`${baseUrl}/api/index?__api_path=devices/approve-pairing`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${shopToken}`,
      },
      body: JSON.stringify({ pairingToken, approve: true }),
    });
    assert.equal(approveRes.status, 200);
    const approveJson = await approveRes.json();
    assert.equal(approveJson.success, true);
    assert.ok(approveJson.device?.deviceId === 'DEV-VERCEL-TEST-1');

    const statusRes = await fetch(`${baseUrl}/api/index?__api_path=devices/pairing-status/${pairingToken}`);
    assert.equal(statusRes.status, 200);
    const statusJson = await statusRes.json();
    assert.equal(statusJson.session?.status, 'approved');
    assert.ok(statusJson.auth?.sessionToken, 'Approved pairing status must deliver paired device sessionToken');

    console.log('8. Verifying serverless SSE endpoint emits serverless ping and closes cleanly...');
    const sseRes = await fetch(
      `${baseUrl}/api/index?__api_path=sync/events&deviceId=DEV-VERCEL-TEST-1&token=${encodeURIComponent(shopToken)}`
    );
    assert.equal(sseRes.status, 200);
    const sseText = await sseRes.text();
    assert.ok(sseText.includes('"mode":"serverless"'), 'Serverless SSE must signal mode:"serverless"');

    console.log('9. Verifying unmatched /api/* and malformed JSON return JSON (never HTML)...');
    const notFoundRes = await fetch(`${baseUrl}/api/index?__api_path=nonexistent/endpoint`);
    assert.equal(notFoundRes.status, 404);
    assert.ok((notFoundRes.headers.get('content-type') || '').includes('application/json'));
    const notFoundJson = await notFoundRes.json();
    assert.equal(notFoundJson.error, 'API_ENDPOINT_NOT_FOUND');

    const badJsonRes = await fetch(`${baseUrl}/api/index?__api_path=auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{"broken": ',
    });
    assert.equal(badJsonRes.status, 400);
    const badJson = await badJsonRes.json();
    assert.equal(badJson.error, 'INVALID_JSON_BODY');

    console.log('10. Testing frontend apiClient URL guard & 403/405 HTML protection...');
    const memStorage = new Map<string, string>();
    (globalThis as any).localStorage = {
      getItem: (k: string) => memStorage.get(k) ?? null,
      setItem: (k: string, v: string) => memStorage.set(k, String(v)),
      removeItem: (k: string) => memStorage.delete(k),
    };
    (globalThis as any).window = {
      location: { protocol: 'https:', hostname: 'waqas-pos.vercel.app', origin: 'https://waqas-pos.vercel.app' },
      dispatchEvent() {},
    };
    (globalThis as any).CustomEvent = class { constructor(public type: string) {} };

    const { getApiBaseUrl, safeFetchJson } = await import('../src/utils/apiClient');
    // Stale localhost saved from local dev must be ignored on HTTPS Vercel domain!
    memStorage.set('waqas_mart_server_url', 'http://localhost:3000');
    assert.equal(getApiBaseUrl(), '', 'HTTPS production page must ignore stale http://localhost:3000 override');

    // Same-origin / valid HTTPS URL is preserved
    memStorage.set('waqas_mart_server_url', 'https://api.waqasmart.com/');
    assert.equal(getApiBaseUrl(), 'https://api.waqasmart.com');
    memStorage.delete('waqas_mart_server_url');

    // Simulate HTML 403 Forbidden from misconfigured proxy
    const origFetch = globalThis.fetch;
    try {
      (globalThis as any).fetch = async () =>
        new Response('<html><title>403 Forbidden</title><body>403 Forbidden</body></html>', {
          status: 403,
          headers: { 'content-type': 'text/html' },
        });
      await assert.rejects(
        () => safeFetchJson('/api/devices/pairing-session', { method: 'POST', body: '{}' }),
        (err: any) => err?.status === 403 && err?.isHtmlResponse === true && String(err?.message).includes('HTTP 403')
      );

      (globalThis as any).fetch = async () =>
        new Response('Method Not Allowed', { status: 405, headers: { 'content-type': 'text/plain' } });
      await assert.rejects(
        () => safeFetchJson('/api/auth/super-admin/login', { method: 'POST', body: '{}' }),
        (err: any) => err?.status === 405 && String(err?.message).includes('405')
      );
    } finally {
      globalThis.fetch = origFetch;
    }

    console.log('✅ ALL VERCEL PRODUCTION COMPATIBILITY TESTS PASSED!');
  } finally {
    if (server) {
      await new Promise<void>((resolve) => server!.close(() => resolve()));
    }
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
}

runTests().catch((err) => {
  console.error('❌ Test failed:', err);
  process.exit(1);
});
