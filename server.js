import http from 'node:http';
import https from 'node:https';
import { pathToFileURL } from 'node:url';
import { loadServiceAccount, TokenProvider } from './lib/google-auth.js';
import { evaluate, DEFAULT_POST_SUFFIXES } from './lib/policy.js';

const DEFAULT_PORT = 8081;
const DEFAULT_HOST = '127.0.0.1';
const DEFAULT_TARGET = 'https://logging.googleapis.com';
const MAX_BODY_BYTES = 10 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 60_000;

const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'host',
  'authorization',
  'content-length',
]);

function stripHopByHop(headers) {
  const result = {};
  for (const [name, value] of Object.entries(headers)) {
    if (!HOP_BY_HOP.has(name.toLowerCase()) && value !== undefined) {
      result[name] = value;
    }
  }
  return result;
}

function sendJson(res, statusCode, payload) {
  const body = Buffer.from(JSON.stringify(payload));
  res.writeHead(statusCode, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': body.length,
  });
  res.end(body);
}

function apiError(code, status, message) {
  return { error: { code, status, message } };
}

async function readBody(req, limit = MAX_BODY_BYTES) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limit) {
      throw Object.assign(new Error('Request body is too large'), { statusCode: 413 });
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

function parseTarget(target) {
  const raw = /^https?:\/\//i.test(target) ? target : `https://${target}`;
  const url = new URL(raw);
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new Error(`Unsupported target protocol: ${url.protocol}`);
  }
  if (url.pathname !== '/' || url.search || url.hash) {
    throw new Error(`Target must be an origin without a path: ${target}`);
  }
  return url;
}

export function createProxyServer({
  target = DEFAULT_TARGET,
  tokens,
  postSuffixes = DEFAULT_POST_SUFFIXES,
  logger = console,
  requestTimeoutMs = DEFAULT_TIMEOUT_MS,
} = {}) {
  if (!tokens) {
    throw new Error('createProxyServer requires a token provider');
  }

  const targetUrl = parseTarget(target);
  const transport = targetUrl.protocol === 'https:' ? https : http;
  const targetPort = targetUrl.port ? Number(targetUrl.port) : transport === https ? 443 : 80;

  function forward({ method, path, headers, body }) {
    return new Promise((resolve, reject) => {
      const upstream = transport.request(
        {
          hostname: targetUrl.hostname,
          port: targetPort,
          method,
          path,
          headers,
        },
        resolve,
      );
      upstream.setTimeout(requestTimeoutMs, () => {
        upstream.destroy(new Error('Upstream request timed out'));
      });
      upstream.on('error', reject);
      upstream.end(body);
    });
  }

  async function obtainToken() {
    try {
      return await tokens.getToken();
    } catch (error) {
      logger.error?.(`service account token error: ${error.message}`);
      return null;
    }
  }

  const server = http.createServer(async (req, res) => {
    const startedAt = Date.now();
    let pathname = '/';
    let search = '';
    const rawTarget = req.url ?? '';

    res.on('finish', () => {
      logger.info?.(`${req.method} ${pathname} -> ${res.statusCode} (${Date.now() - startedAt}ms)`);
    });

    const unsafePath =
      !rawTarget.startsWith('/') ||
      rawTarget.startsWith('//') ||
      /[\\\u0000-\u001f\u007f]/.test(rawTarget);
    if (unsafePath) {
      sendJson(res, 400, apiError(400, 'INVALID_ARGUMENT', 'Proxy only accepts origin-form request paths'));
      return;
    }

    try {
      const url = new URL(rawTarget, 'http://proxy.local');
      pathname = url.pathname;
      search = url.search;
    } catch {
      sendJson(res, 400, apiError(400, 'INVALID_ARGUMENT', 'Malformed request URL'));
      return;
    }

    const decision = evaluate(req.method, pathname, { postSuffixes });
    if (!decision.allowed) {
      sendJson(
        res,
        403,
        apiError(
          403,
          'PERMISSION_DENIED',
          `Read-only proxy rejected ${req.method} ${pathname}: ${decision.reason}`,
        ),
      );
      return;
    }

    let body;
    if (req.method === 'POST') {
      try {
        body = await readBody(req);
      } catch (error) {
        sendJson(res, error.statusCode ?? 400, apiError(error.statusCode ?? 400, 'INVALID_ARGUMENT', error.message));
        return;
      }
    }

    const headers = stripHopByHop(req.headers);
    headers.accept ??= 'application/json';
    if (body) {
      headers['content-length'] = String(body.length);
    }

    let token = await obtainToken();
    if (!token) {
      sendJson(
        res,
        502,
        apiError(502, 'UNAVAILABLE', 'Proxy could not obtain a Google access token; check the service account configuration'),
      );
      return;
    }

    const sendUpstream = (accessToken) =>
      forward({
        method: req.method,
        path: pathname + search,
        headers: { ...headers, authorization: `Bearer ${accessToken}` },
        body,
      });

    try {
      let upstream = await sendUpstream(token);

      if (upstream.statusCode === 401 && typeof tokens.invalidate === 'function') {
        upstream.resume();
        tokens.invalidate();
        token = await obtainToken();
        if (!token) {
          sendJson(
            res,
            502,
            apiError(502, 'UNAVAILABLE', 'Proxy could not obtain a Google access token; check the service account configuration'),
          );
          return;
        }
        upstream = await sendUpstream(token);
      }

      const responseHeaders = stripHopByHop(upstream.headers);
      res.writeHead(upstream.statusCode ?? 502, upstream.statusMessage, responseHeaders);
      upstream.pipe(res);
      upstream.on('error', (error) => res.destroy(error));
      res.on('close', () => {
        if (!upstream.complete) {
          upstream.destroy();
        }
      });
    } catch (error) {
      logger.error?.(`upstream request error: ${error.message}`);
      if (!res.headersSent) {
        sendJson(res, 502, apiError(502, 'UNAVAILABLE', 'Proxy could not reach logging.googleapis.com'));
      } else {
        res.destroy(error);
      }
    }
  });

  return server;
}

function usage() {
  return `Read-only local proxy for logging.googleapis.com

Usage:
  node server.js --service-account <file> [options]

Options:
  --service-account <file>  Service account JSON key file
                            (default: GOOGLE_APPLICATION_CREDENTIALS)
  --port <number>           Local listening port (default: ${DEFAULT_PORT})
  --host <address>          Local listening address (default: ${DEFAULT_HOST})
  --target <origin>         Upstream origin (default: ${DEFAULT_TARGET})
  --scope <scope>           OAuth scope (default: https://www.googleapis.com/auth/logging.read)
  --allow-post <suffixes>   Comma-separated read-only POST suffixes
                            (default: ${DEFAULT_POST_SUFFIXES.join(',')})
  -h, --help                Show this help

Then call the proxy, for example:
  curl "http://${DEFAULT_HOST}:${DEFAULT_PORT}/v2/entries:list?resourceNames=projects/my-project" \\
    -H "content-type: application/json" \\
    --data '{"resourceNames":["projects/my-project"],"filter":"severity>=ERROR"}'

Environment: PORT, HOST, TARGET_HOST, GOOGLE_APPLICATION_CREDENTIALS,
GOOGLE_SCOPE, PROXY_ALLOW_POST.
`;
}

export function parseArgs(argv) {
  const options = {
    port: Number(process.env.PORT ?? DEFAULT_PORT),
    host: process.env.HOST ?? DEFAULT_HOST,
    target: process.env.TARGET_HOST ?? DEFAULT_TARGET,
    serviceAccount: process.env.GOOGLE_APPLICATION_CREDENTIALS ?? process.env.SERVICE_ACCOUNT_FILE,
    scope: process.env.GOOGLE_SCOPE,
    postSuffixes: process.env.PROXY_ALLOW_POST
      ? process.env.PROXY_ALLOW_POST.split(',').map((suffix) => suffix.trim()).filter(Boolean)
      : DEFAULT_POST_SUFFIXES,
    help: false,
  };

  const args = [...argv];
  while (args.length > 0) {
    const arg = args.shift();
    if (arg === '-h' || arg === '--help') {
      options.help = true;
      continue;
    }

    const [name, inlineValue] = arg.split('=', 2);
    const value = inlineValue ?? args.shift();

    switch (name) {
      case '--port':
        options.port = Number(value);
        break;
      case '--host':
        options.host = value;
        break;
      case '--target':
        options.target = value;
        break;
      case '--service-account':
        options.serviceAccount = value;
        break;
      case '--scope':
        options.scope = value;
        break;
      case '--allow-post':
        options.postSuffixes = String(value).split(',').map((suffix) => suffix.trim()).filter(Boolean);
        break;
      default:
        throw new Error(`Unknown argument: ${arg}`);
    }
  }

  if (!Number.isInteger(options.port) || options.port < 1 || options.port > 65535) {
    throw new Error(`Invalid port: ${options.port}`);
  }
  if (options.postSuffixes.length === 0) {
    throw new Error('At least one read-only POST suffix is required');
  }

  return options;
}

async function main(argv) {
  const options = parseArgs(argv);
  if (options.help) {
    process.stdout.write(usage());
    return;
  }
  if (!options.serviceAccount) {
    process.stderr.write(
      'Missing service account file. Use --service-account <file> or set GOOGLE_APPLICATION_CREDENTIALS.\n\n' +
        usage(),
    );
    process.exitCode = 2;
    return;
  }

  const serviceAccount = await loadServiceAccount(options.serviceAccount);
  const tokens = new TokenProvider(serviceAccount, options.scope ? { scope: options.scope } : {});
  const server = createProxyServer({
    target: options.target,
    tokens,
    postSuffixes: options.postSuffixes,
  });

  server.listen(options.port, options.host, () => {
    const address = server.address();
    process.stdout.write(
      `Read-only logging proxy listening on http://${address.address}:${address.port} -> ${options.target}\n` +
        `Authenticating as ${serviceAccount.client_email}\n`,
    );
  });

  const shutdown = () => {
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 5_000).unref();
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

const entryPoint = process.argv[1] ? pathToFileURL(process.argv[1]).href : '';
if (import.meta.url === entryPoint) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
