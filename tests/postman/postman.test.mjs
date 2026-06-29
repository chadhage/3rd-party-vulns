// Behavioral unit tests + coverage for the Postman JavaScript embedded in the
// collection. The scripts are the source of truth inside the collection JSON;
// this harness extracts each one into tests/postman/generated/*.mjs, then
// executes them against mock `pm` / `console` objects to exercise every branch.
//
// Run (from the repository root) with coverage thresholds:
//   node --test --experimental-test-coverage \
//        --test-coverage-include='**/generated/**' \
//        --test-coverage-lines=0.8 --test-coverage-branches=0.8 \
//        --test-coverage-functions=0.8 tests/postman/postman.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const genDir = path.join(here, 'generated');
const collPath = path.join(here, '..', '..', 'postman', 'third-party-vulnerabilities.postman_collection.json');

// --- Extract the real Postman scripts into importable modules ------------------
const collection = JSON.parse(readFileSync(collPath, 'utf8'));
rmSync(genDir, { recursive: true, force: true });
mkdirSync(genDir, { recursive: true });

function writeWrapper(name, execLines) {
  const body = execLines.join('\n');
  writeFileSync(
    path.join(genDir, `${name}.mjs`),
    `export default function run(pm, console) {\n${body}\n}\n`,
    'utf8'
  );
}

const preEvent = collection.event.find((e) => e.listen === 'prerequest');
writeWrapper('prerequest', preEvent.script.exec);

const testModuleNames = [];
collection.item.forEach((item, i) => {
  const ev = (item.event || []).find((e) => e.listen === 'test');
  if (ev) {
    const name = `test_${i}`;
    writeWrapper(name, ev.script.exec);
    testModuleNames.push(name);
  }
});

const load = async (name) =>
  (await import(pathToFileURL(path.join(genDir, `${name}.mjs`)).href)).default;

// --- Mocks --------------------------------------------------------------------
function makeEnv(initial = {}) {
  const m = new Map(Object.entries(initial));
  return {
    get: (k) => (m.has(k) ? m.get(k) : undefined),
    set: (k, v) => m.set(k, v),
    unset: (k) => m.delete(k),
    has: (k) => m.has(k),
    _map: m,
  };
}

function makeConsole() {
  const calls = { log: [], warn: [], error: [] };
  return {
    log: (...a) => calls.log.push(a),
    warn: (...a) => calls.warn.push(a),
    error: (...a) => calls.error.push(a),
    _calls: calls,
  };
}

function expectMock(actual) {
  return {
    to: {
      be: {
        get true() {
          if (actual !== true) throw new Error(`Expected true but got ${actual}`);
          return true;
        },
      },
    },
  };
}

// Builds a pm mock for the test scripts (response + test recorder).
function makeResponsePm(env, { code = 200, body = { value: [] }, headers = {} }) {
  const testResults = [];
  const pm = {
    environment: env,
    response: {
      code,
      json: () => body,
      headers: { get: (k) => headers[k] },
      to: {
        have: {
          status: (s) => {
            if (code !== s) throw new Error(`Expected status ${s} but got ${code}`);
          },
        },
      },
    },
    expect: expectMock,
    test: (name, fn) => {
      try {
        fn();
        testResults.push({ name, passed: true });
      } catch (e) {
        testResults.push({ name, passed: false, error: e.message });
      }
    },
    _testResults: testResults,
  };
  return pm;
}

// --- Pre-request (token acquisition) tests ------------------------------------
test('prerequest: returns early when a non-expired token is cached', async () => {
  const run = await load('prerequest');
  let sent = false;
  const env = makeEnv({ access_token: 'cached', token_expires_at: String(Date.now() + 60_000) });
  const pm = { environment: env, sendRequest: () => { sent = true; } };
  run(pm, makeConsole());
  assert.equal(sent, false, 'should not request a new token when one is cached');
});

test('prerequest: throws when credentials are missing', async () => {
  const run = await load('prerequest');
  const env = makeEnv({}); // no token, no creds
  const pm = { environment: env, sendRequest: () => {} };
  assert.throws(() => run(pm, makeConsole()), /tenantId, clientId and clientSecret/);
});

test('prerequest: caches token on a successful response', async () => {
  const run = await load('prerequest');
  const env = makeEnv({ tenantId: 't', clientId: 'c', clientSecret: 's' });
  const pm = {
    environment: env,
    sendRequest: (opts, cb) => {
      assert.match(opts.url, /login\.microsoftonline\.com\/t\/oauth2\/v2\.0\/token/);
      assert.equal(opts.method, 'POST');
      cb(null, { json: () => ({ access_token: 'new-token', expires_in: 3600 }) });
    },
  };
  run(pm, makeConsole());
  assert.equal(env.get('access_token'), 'new-token');
  assert.ok(Number(env.get('token_expires_at')) > Date.now());
});

test('prerequest: logs and aborts on a transport error', async () => {
  const run = await load('prerequest');
  const env = makeEnv({ tenantId: 't', clientId: 'c', clientSecret: 's' });
  const con = makeConsole();
  const pm = { environment: env, sendRequest: (opts, cb) => cb(new Error('network down')) };
  run(pm, con);
  assert.equal(env.has('access_token'), false);
  assert.equal(con._calls.error.length, 1);
});

test('prerequest: logs when the response has no access_token', async () => {
  const run = await load('prerequest');
  const env = makeEnv({ tenantId: 't', clientId: 'c', clientSecret: 's' });
  const con = makeConsole();
  const pm = { environment: env, sendRequest: (opts, cb) => cb(null, { json: () => ({ error: 'invalid_client' }) }) };
  run(pm, con);
  assert.equal(env.has('access_token'), false);
  assert.equal(con._calls.error.length, 1);
});

// --- Per-request test scripts -------------------------------------------------
test('test scripts: store nextLink and pass the array assertion on 200', async () => {
  for (const name of testModuleNames) {
    const run = await load(name);
    const env = makeEnv({});
    const pm = makeResponsePm(env, {
      code: 200,
      body: { value: [1, 2, 3], '@odata.nextLink': 'https://graph.microsoft.com/next' },
    });
    run(pm, makeConsole());
    assert.equal(env.get('nextLink'), 'https://graph.microsoft.com/next');
    assert.ok(pm._testResults.find((r) => r.name === 'value is an array')?.passed);
  }
});

test('test scripts: clear nextLink on the last page', async () => {
  for (const name of testModuleNames) {
    const run = await load(name);
    const env = makeEnv({ nextLink: 'https://stale' });
    const pm = makeResponsePm(env, { code: 200, body: { value: [] } });
    run(pm, makeConsole());
    assert.equal(env.has('nextLink'), false);
  }
});

test('test scripts: warn and surface Retry-After on HTTP 429', async () => {
  for (const name of testModuleNames) {
    const run = await load(name);
    const env = makeEnv({});
    const con = makeConsole();
    const pm = makeResponsePm(env, {
      code: 429,
      body: { value: [] },
      headers: { 'Retry-After': '30' },
    });
    run(pm, con);
    assert.equal(con._calls.warn.length, 1, 'should warn on 429');
    assert.match(String(con._calls.warn[0]), /30/);
  }
});
