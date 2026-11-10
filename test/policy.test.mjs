import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluate, isReadOnlyPost } from '../lib/policy.js';

test('allows GET and HEAD', () => {
  assert.equal(evaluate('GET', '/v2/entries').allowed, true);
  assert.equal(evaluate('HEAD', '/v2/entries').allowed, true);
  assert.equal(evaluate('get', '/v2/entries').allowed, true);
});

test('allows read-only POST methods', () => {
  assert.equal(evaluate('POST', '/v2/entries:list').allowed, true);
  assert.equal(evaluate('POST', '/v2/entries:tail').allowed, true);
  assert.equal(evaluate('POST', '/v2/projects/p/locations/global/buckets:list').allowed, true);
});

test('rejects write and mutating methods', () => {
  for (const method of ['POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']) {
    assert.equal(evaluate(method, '/v2/entries:write').allowed, false, method);
  }
  assert.equal(evaluate('POST', '/v2/entries:copy').allowed, false);
  assert.equal(evaluate('POST', '/v2/entries').allowed, false);
  assert.equal(evaluate('POST', '/v2/entries:list/extra').allowed, false);
});

test('reports a reason for rejected requests', () => {
  const decision = evaluate('DELETE', '/v2/entries');
  assert.equal(decision.allowed, false);
  assert.match(decision.reason, /DELETE/);

  const postDecision = evaluate('POST', '/v2/entries:write');
  assert.match(postDecision.reason, /read-only/i);
});

test('supports custom allowed POST suffixes', () => {
  assert.equal(evaluate('POST', '/v2/entries:list', { postSuffixes: [':search'] }).allowed, false);
  assert.equal(evaluate('POST', '/v2/entries:search', { postSuffixes: [':search'] }).allowed, true);
});

test('matches the last path segment only', () => {
  assert.equal(isReadOnlyPost('/v2/entries:list'), true);
  assert.equal(isReadOnlyPost('/v2/entries:list/'), true);
  assert.equal(isReadOnlyPost('/v2/:list/entries'), false);
});
