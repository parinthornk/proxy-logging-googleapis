import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, verify } from 'node:crypto';
import { TokenProvider } from '../lib/google-auth.js';

function createServiceAccount() {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return {
    serviceAccount: {
      type: 'service_account',
      client_email: 'proxy@example-project.iam.gserviceaccount.com',
      private_key: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
      token_uri: 'https://oauth2.example.com/token',
    },
    publicKey,
  };
}

function decodeSegment(segment) {
  return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
}

test('exchanges a signed JWT assertion for an access token', async () => {
  const { serviceAccount, publicKey } = createServiceAccount();
  const calls = [];

  const provider = new TokenProvider(serviceAccount, {
    scope: 'https://www.googleapis.com/auth/logging.read',
    fetchImpl: async (url, init) => {
      calls.push({ url, init });
      return new Response(JSON.stringify({ access_token: 'ya29.test', expires_in: 3600 }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    },
  });

  const token = await provider.getToken(1_700_000_000_000);
  assert.equal(token, 'ya29.test');
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, serviceAccount.token_uri);
  assert.equal(calls[0].init.method, 'POST');

  const params = new URLSearchParams(calls[0].init.body);
  assert.equal(params.get('grant_type'), 'urn:ietf:params:oauth:grant-type:jwt-bearer');

  const [header, claims, signature] = params.get('assertion').split('.');
  assert.deepEqual(decodeSegment(header), { alg: 'RS256', typ: 'JWT' });

  const payload = decodeSegment(claims);
  assert.equal(payload.iss, serviceAccount.client_email);
  assert.equal(payload.scope, 'https://www.googleapis.com/auth/logging.read');
  assert.equal(payload.aud, serviceAccount.token_uri);
  assert.equal(payload.iat, 1_700_000_000);
  assert.equal(payload.exp, 1_700_003_600);

  const valid = verify(
    'RSA-SHA256',
    Buffer.from(`${header}.${claims}`),
    publicKey,
    Buffer.from(signature, 'base64url'),
  );
  assert.equal(valid, true);
});

test('caches the token until it is close to expiry', async () => {
  let calls = 0;
  const provider = new TokenProvider(createServiceAccount().serviceAccount, {
    fetchImpl: async () => {
      calls += 1;
      return new Response(JSON.stringify({ access_token: `token-${calls}`, expires_in: 3600 }), { status: 200 });
    },
  });

  const now = 1_700_000_000_000;
  assert.equal(await provider.getToken(now), 'token-1');
  assert.equal(await provider.getToken(now + 1_000), 'token-1');
  assert.equal(calls, 1);

  assert.equal(await provider.getToken(now + 3_600_000), 'token-2');
  assert.equal(calls, 2);
});

test('invalidate forces a new token', async () => {
  let calls = 0;
  const provider = new TokenProvider(createServiceAccount().serviceAccount, {
    fetchImpl: async () => {
      calls += 1;
      return new Response(JSON.stringify({ access_token: `token-${calls}`, expires_in: 3600 }), { status: 200 });
    },
  });

  const now = 1_700_000_000_000;
  await provider.getToken(now);
  provider.invalidate();
  assert.equal(await provider.getToken(now), 'token-2');
  assert.equal(calls, 2);
});

test('deduplicates concurrent token requests', async () => {
  let calls = 0;
  const provider = new TokenProvider(createServiceAccount().serviceAccount, {
    fetchImpl: async () => {
      calls += 1;
      await new Promise((resolve) => setTimeout(resolve, 10));
      return new Response(JSON.stringify({ access_token: 'token-1', expires_in: 3600 }), { status: 200 });
    },
  });

  const results = await Promise.all([provider.getToken(), provider.getToken(), provider.getToken()]);
  assert.deepEqual(results, ['token-1', 'token-1', 'token-1']);
  assert.equal(calls, 1);
});

test('surfaces token exchange failures without exposing the key', async () => {
  const provider = new TokenProvider(createServiceAccount().serviceAccount, {
    fetchImpl: async () => new Response('{"error":"invalid_grant"}', { status: 400 }),
  });

  await assert.rejects(provider.getToken(), (error) => {
    assert.match(error.message, /Token exchange failed \(400\)/);
    assert.match(error.message, /invalid_grant/);
    return true;
  });
});
