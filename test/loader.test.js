'use strict';
const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { createRanvia } = require('..');

test('checkIssue handles non-ASCII Ranvia-Engine-Tag without throwing RangeError', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rnv-node-'));
  const keySecret = Buffer.alloc(32, 7).toString('base64url');
  const key = 'rnv_s1.' + keySecret;
  const wasmPath = path.resolve(__dirname, '../../../dist/ranvia-core.wasm');
  if (!fs.existsSync(wasmPath)) return;

  // Serve an invalid 64-character UTF-8 tag alongside 200 to verify no uncaught RangeError.
  const srv = http.createServer((req, res) => {
    if (req.url === '/v1/engine') {
      res.writeHead(200, {
        'Ranvia-Engine-Issued': '1700000000',
        'Ranvia-Engine-Tag': '\u00e9'.repeat(64),
      });
      res.end(Buffer.alloc(32));
      return;
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const logs = [];
  const ranvia = createRanvia({
    key,
    serviceUrl: 'http://127.0.0.1:' + srv.address().port,
    cacheDir: dir,
    log: (m) => logs.push(m),
  });
  await new Promise((r) => setTimeout(r, 150));
  await ranvia.close();
  srv.close();
  assert.ok(!logs.some((l) => /timingSafeEqual|ERR_CRYPTO/i.test(l)), 'unexpected crypto throw: ' + logs.join('; '));
});

test('writeHead merges es_assets with site Set-Cookie, handles array headers, 1xx, and bodyless HTML', async (t) => {
  const wasmPath = path.resolve(__dirname, '../../../dist/ranvia-core.wasm');
  if (!fs.existsSync(wasmPath)) return;

  // Test array-form writeHead, object Set-Cookie merge, 1xx, and implicit end('<!doctype html>')
  // against CoreConfirm using a quick helper that signs key-sealed wasm locally.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rnv-wh-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const secretRaw = Buffer.alloc(32, 9);
  const id = 's1';
  const sealKey = crypto.createHmac('sha256', secretRaw).update('ranvia engine key').digest();
  const wasm = fs.readFileSync(wasmPath);
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', sealKey, nonce);
  cipher.setAAD(Buffer.from(id));
  const sealed = Buffer.concat([nonce, cipher.update(wasm), cipher.final(), cipher.getAuthTag()]);
  const issued = '1700000000';
  const sum = crypto.createHash('sha256').update(sealed).digest('hex');
  const tag = crypto.createHmac('sha256', sealKey).update('ranvia engine tag|' + id + '|' + issued + '|' + sum).digest('hex');

  const svc = http.createServer((req, res) => {
    if (req.url === '/v1/engine') {
      res.writeHead(200, { 'Ranvia-Engine-Issued': issued, 'Ranvia-Engine-Tag': tag, ETag: '"t1"' });
      res.end(sealed);
      return;
    }
    res.writeHead(304);
    res.end();
  });
  await new Promise((r) => svc.listen(0, '127.0.0.1', r));
  t.after(() => { svc.close(); svc.closeAllConnections(); });

  const ranvia = createRanvia({
    key: 'rnv_s1.' + secretRaw.toString('base64url'),
    serviceUrl: 'http://127.0.0.1:' + svc.address().port,
    cacheDir: dir,
  });
  t.after(() => ranvia.close());
  let readyTimer;
  await Promise.race([
    ranvia.ready(),
    new Promise((r) => { readyTimer = setTimeout(r, 15000); readyTimer.unref(); }),
  ]);
  clearTimeout(readyTimer);
  assert.strictEqual(ranvia.isReady(), true);

  const app = http.createServer(ranvia.wrap((req, res) => {
    if (req.url === '/cookie.css') {
      res.writeHead(200, { 'Content-Type': 'text/css', 'Set-Cookie': 'app=1' });
      res.end('body{}');
      return;
    }
    if (req.url === '/arr-html.css') {
      res.writeHead(200, [['Content-Type', 'text/html']]);
      res.end('<p>html</p>');
      return;
    }
    if (req.url === '/early.css') {
      if (typeof res.writeEarlyHints === 'function') {
        res.writeEarlyHints({ link: '</a.css>; rel=preload' });
      }
      res.writeHead(200, { 'Content-Type': 'text/css' });
      res.end('body{}');
      return;
    }
    if (req.url === '/noct.css') {
      res.end('<!doctype html><html><p>hi</p></html>');
      return;
    }
    res.end('ok');
  }));
  await new Promise((r) => app.listen(0, '127.0.0.1', r));
  t.after(() => { app.close(); app.closeAllConnections(); });
  const port = app.address().port;

  const get = (p, lang) => new Promise((resolve, reject) => {
    http.get({
      port,
      agent: false,
      path: p,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36',
        'Accept-Language': lang,
        'Sec-Ch-Ua': '"Chromium";v="153"',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'no-cors',
        'Sec-Fetch-Dest': 'style',
      },
    }, (r) => { r.resume(); r.on('end', () => resolve(r.headers)); }).on('error', reject);
  });

  const hCookie = await get('/cookie.css', 'en-cookie');
  const sc = hCookie['set-cookie'] || [];
  assert.ok(sc.some((v) => v.startsWith('app=1')), 'site cookie preserved: ' + JSON.stringify(sc));
  assert.ok(sc.some((v) => v.startsWith('es_assets=')), 'es_assets preserved: ' + JSON.stringify(sc));

  const hArr = await get('/arr-html.css', 'en-arr');
  assert.strictEqual((hArr['set-cookie'] || []).length, 0, 'array-header HTML must not mint pass');

  const hEarly = await get('/early.css', 'en-early');
  assert.ok((hEarly['set-cookie'] || []).some((v) => v.startsWith('es_assets=')), '1xx kept hook for 200 confirm');

  const hNoCT = await get('/noct.css', 'en-noct');
  assert.strictEqual((hNoCT['set-cookie'] || []).length, 0, 'body-sniffed HTML must not mint pass');

  assert.ok(typeof execFileSync === 'function');
});

// A 402 on /v1/rules, signed by the service for that request or not.
async function lapsedPlan(t, signed) {
  const wasmPath = path.resolve(__dirname, '../../../dist/ranvia-core.wasm');
  if (!fs.existsSync(wasmPath)) return null;

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rnv-402-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const secretRaw = Buffer.alloc(32, 11);
  const id = 's1';
  const sealKey = crypto.createHmac('sha256', secretRaw).update('ranvia engine key').digest();
  const wasm = fs.readFileSync(wasmPath);
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', sealKey, nonce);
  cipher.setAAD(Buffer.from(id));
  const sealed = Buffer.concat([nonce, cipher.update(wasm), cipher.final(), cipher.getAuthTag()]);
  const issued = '1700000000';
  const sum = crypto.createHash('sha256').update(sealed).digest('hex');
  const tag = crypto.createHmac('sha256', sealKey).update('ranvia engine tag|' + id + '|' + issued + '|' + sum).digest('hex');
  const shutdownKey = crypto.createHmac('sha256', secretRaw).update('ranvia shutdown key').digest();

  let rulesCalls = 0;
  const svc = http.createServer((req, res) => {
    if (req.url === '/v1/engine') {
      res.writeHead(200, { 'Ranvia-Engine-Issued': issued, 'Ranvia-Engine-Tag': tag, ETag: '"t1"' });
      res.end(sealed);
      return;
    }
    if (req.url === '/v1/rules') {
      rulesCalls++;
      const h = { 'Content-Type': 'text/plain' };
      if (signed) {
        h['Ranvia-Shutdown'] = crypto.createHmac('sha256', shutdownKey)
          .update('ranvia shutdown|' + id + '|402|' + req.headers['ranvia-nonce']).digest('hex');
      }
      res.writeHead(402, h);
      res.end('this account has reached its 2.5M trial request allowance');
      return;
    }
    res.writeHead(204);
    res.end();
  });
  await new Promise((r) => svc.listen(0, '127.0.0.1', r));
  t.after(() => { svc.close(); svc.closeAllConnections(); });

  const ranvia = createRanvia({
    key: 'rnv_s1.' + secretRaw.toString('base64url'),
    serviceUrl: 'http://127.0.0.1:' + svc.address().port,
    cacheDir: dir,
  });
  t.after(() => ranvia.close());

  const deadline = Date.now() + 15000;
  while (rulesCalls === 0 && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 40));
  }
  await new Promise((r) => setTimeout(r, 80));
  return { ready: ranvia.isReady(), cached: fs.existsSync(path.join(dir, 'engine-s1.bin')) };
}

test('a 402 the service signed unloads the engine and wipes the cached engine file', async (t) => {
  const out = await lapsedPlan(t, true);
  if (!out) return;
  assert.strictEqual(out.ready, false, 'engine must be unloaded after a signed 402');
  assert.strictEqual(out.cached, false, 'cached engine binary must be deleted after a signed 402');
});

test('a 402 without the service signature leaves the engine running', async (t) => {
  const out = await lapsedPlan(t, false);
  if (!out) return;
  assert.strictEqual(out.ready, true, 'engine must stay loaded after an unsigned 402');
  assert.strictEqual(out.cached, true, 'cached engine binary must stay after an unsigned 402');
});
