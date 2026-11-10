import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createProxyServer } from '../server.js';

const seen = [];
let retryAttempts = 0;

const upstream = http.createServer((req, res) => {
  const chunks = [];
  req.on('data', (chunk) => chunks.push(chunk));
  req.on('end', () => {
    seen.push({
      method: req.method,
      url: req.url,
      headers: req.headers,
      body: Buffer.concat(chunks).toString('utf8'),
    });

    if (req.url.startsWith('/v2/retry')) {
      retryAttempts += 1;
      if (retryAttempts === 1) {
        res.writeHead(401, { 'content-type': 'application/json' });
        res.end('{"error":"expired token"}');
        return;
      }
    }

    res.writeHead(200, { 'content-type': 'application/json', 'x-upstream': 'yes' });
    res.end(JSON.stringify({ ok: true, path: req.url }));
  });
});

let tokenCalls = 0;
let invalidations = 0;
const tokens = {
  async getToken() {
    tokenCalls += 1;
    return `token-${tokenCalls}`;
  },
  invalidate() {
    invalidations += 1;
  },
};

const logger = { info() {}, error() {} };
let proxy;
let proxyPort;
let baseUrl;

function rawRequest({ path, method = 'GET' }) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { hostname: '127.0.0.1', port: proxyPort, method, path },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () =>
          resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }),
        );
      },
    );
    req.on('error', reject);
    req.end();
  });
}

before(async () => {
  await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  proxy = createProxyServer({
    target: `http://127.0.0.1:${upstream.address().port}`,
    tokens,
    logger,
  });
  await new Promise((resolve) => proxy.listen(0, '127.0.0.1', resolve));
  proxyPort = proxy.address().port;
  baseUrl = `http://127.0.0.1:${proxyPort}`;
});

after(async () => {
  proxy.closeAllConnections?.();
  upstream.closeAllConnections?.();
  await new Promise((resolve) => proxy.close(resolve));
  await new Promise((resolve) => upstream.close(resolve));
});

test('proxies GET requests with a service account bearer token', async () => {
  const response = await fetch(`${baseUrl}/v2/projects/demo/logs?pageSize=5`);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('x-upstream'), 'yes');

  const forwarded = seen.at(-1);
  assert.equal(forwarded.method, 'GET');
  assert.equal(forwarded.url, '/v2/projects/demo/logs?pageSize=5');
  assert.match(forwarded.headers.authorization, /^Bearer token-\d+$/);
  assert.equal(forwarded.headers.host, `127.0.0.1:${upstream.address().port}`);
});

test('forwards read-only POST bodies', async () => {
  const payload = { resourceNames: ['projects/demo'], filter: 'severity>=ERROR' };
  const response = await fetch(`${baseUrl}/v2/entries:list`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  });
  assert.equal(response.status, 200);

  const forwarded = seen.at(-1);
  assert.equal(forwarded.method, 'POST');
  assert.equal(forwarded.url, '/v2/entries:list');
  assert.equal(forwarded.body, JSON.stringify(payload));
  assert.match(forwarded.headers.authorization, /^Bearer token-\d+$/);
});

test('rejects write requests without contacting the upstream', async () => {
  const before = seen.length;
  const response = await fetch(`${baseUrl}/v2/entries:write`, { method: 'POST', body: '{}' });
  assert.equal(response.status, 403);
  const body = await response.json();
  assert.equal(body.error.status, 'PERMISSION_DENIED');
  assert.equal(seen.length, before);
});

test('rejects non-read-only methods', async () => {
  for (const method of ['PUT', 'PATCH', 'DELETE']) {
    const response = await fetch(`${baseUrl}/v2/entries`, { method });
    assert.equal(response.status, 403, method);
  }
});

test('rejects non-origin-form request targets', async () => {
  const response = await rawRequest({ path: '//evil.example/v2/entries' });
  assert.equal(response.status, 400);
  assert.equal(JSON.parse(response.body).error.status, 'INVALID_ARGUMENT');
});

test('refreshes the token once when the upstream returns 401', async () => {
  invalidations = 0;
  const response = await fetch(`${baseUrl}/v2/retry`);
  assert.equal(response.status, 200);

  assert.equal(retryAttempts, 2);
  assert.equal(invalidations, 1);
  const attempts = seen.filter((entry) => entry.url === '/v2/retry');
  assert.equal(attempts.length, 2);
  assert.notEqual(attempts[0].headers.authorization, attempts[1].headers.authorization);
});

test('returns 502 when no token can be obtained', async () => {
  const failing = createProxyServer({
    target: `http://127.0.0.1:${upstream.address().port}`,
    tokens: {
      getToken: async () => {
        throw new Error('invalid_grant');
      },
    },
    logger,
  });
  await new Promise((resolve) => failing.listen(0, '127.0.0.1', resolve));
  try {
    const response = await fetch(`http://127.0.0.1:${failing.address().port}/v2/entries`);
    assert.equal(response.status, 502);
    assert.equal((await response.json()).error.status, 'UNAVAILABLE');
  } finally {
    failing.closeAllConnections?.();
    await new Promise((resolve) => failing.close(resolve));
  }
});
