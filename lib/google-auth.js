import { readFile } from 'node:fs/promises';
import { createSign } from 'node:crypto';

const DEFAULT_TOKEN_URI = 'https://oauth2.googleapis.com/token';
const DEFAULT_SCOPE = 'https://www.googleapis.com/auth/logging.read';
const TOKEN_REFRESH_SKEW_MS = 60_000;

function base64url(value) {
  return Buffer.from(value).toString('base64url');
}

export async function loadServiceAccount(file) {
  let raw;
  try {
    raw = await readFile(file, 'utf8');
  } catch (error) {
    throw new Error(`Cannot read service account file "${file}": ${error.message}`);
  }

  let serviceAccount;
  try {
    serviceAccount = JSON.parse(raw);
  } catch (error) {
    throw new Error(`Service account file "${file}" is not valid JSON: ${error.message}`);
  }

  if (serviceAccount?.type !== 'service_account') {
    throw new Error(`Service account file "${file}" is missing "type": "service_account"`);
  }
  if (!serviceAccount.client_email || !serviceAccount.private_key) {
    throw new Error(`Service account file "${file}" is missing client_email or private_key`);
  }

  return serviceAccount;
}

export class TokenProvider {
  constructor(serviceAccount, { scope = DEFAULT_SCOPE, tokenUrl, fetchImpl = fetch } = {}) {
    this.serviceAccount = serviceAccount;
    this.scope = scope;
    this.tokenUrl = tokenUrl ?? serviceAccount.token_uri ?? DEFAULT_TOKEN_URI;
    this.fetchImpl = fetchImpl;
    this.token = null;
    this.expiresAt = 0;
    this.pending = null;
    this.invalidationCount = 0;
  }

  invalidate() {
    this.token = null;
    this.expiresAt = 0;
    this.invalidationCount += 1;
  }

  async getToken(now = Date.now()) {
    if (this.token && now < this.expiresAt - TOKEN_REFRESH_SKEW_MS) {
      return this.token;
    }
    if (!this.pending) {
      this.pending = this.#fetchToken(now).finally(() => {
        this.pending = null;
      });
    }
    return this.pending;
  }

  #assertion(now) {
    const issuedAt = Math.floor(now / 1000);
    const header = { alg: 'RS256', typ: 'JWT' };
    const claims = {
      iss: this.serviceAccount.client_email,
      scope: this.scope,
      aud: this.tokenUrl,
      iat: issuedAt,
      exp: issuedAt + 3600,
    };
    const unsigned = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(claims))}`;
    const signer = createSign('RSA-SHA256');
    signer.update(unsigned);
    return `${unsigned}.${signer.sign(this.serviceAccount.private_key).toString('base64url')}`;
  }

  async #fetchToken(now) {
    const body = new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: this.#assertion(now),
    });
    const response = await this.fetchImpl(this.tokenUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body,
    });

    if (!response.ok) {
      const detail = await response.text();
      throw new Error(`Token exchange failed (${response.status}): ${detail.slice(0, 500)}`);
    }

    const tokens = await response.json();
    if (!tokens.access_token) {
      throw new Error('Token exchange response did not contain an access_token');
    }

    this.token = tokens.access_token;
    this.expiresAt = now + Number(tokens.expires_in ?? 3600) * 1000;
    return this.token;
  }
}
