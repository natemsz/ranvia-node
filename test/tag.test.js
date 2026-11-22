'use strict';
const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const { _tagResponse: tagResponse } = require('..');

async function serve(handler, opts) {
  const finished = [];
  const srv = http.createServer((req, res) => {
    tagResponse(res, { ...opts, finish(body, html) { finished.push({ body, html }); return body; } });
    handler(req, res);
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  return { srv, finished, url: 'http://127.0.0.1:' + srv.address().port + '/' };
}

test('an HTML page streams and its tag lands before the last </body>', async () => {
  let release;
  const gate = new Promise((r) => { release = r; });
  const { srv, finished, url } = await serve(async (req, res) => {
    res.setHeader('content-type', 'text/html; charset=utf-8');
    res.setHeader('content-length', '999');
    res.write('<!doctype html><head></head><body>' + 'a'.repeat(100));
    await gate;
    res.write("<script>let s = '</body>';</script><p>end</p></bo");
    res.end('dy></html>');
  }, { tag: '<i>t</i>', whole: false });
  const res = await fetch(url);
  const reader = res.body.getReader();
  const first = await reader.read();
  assert.ok(first.value.length >= 100, 'the head arrived before the handler finished');
  release();
  let text = Buffer.from(first.value).toString();
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    text += Buffer.from(value).toString();
  }
  srv.close();
  assert.strictEqual(res.headers.get('content-length'), null);
  assert.strictEqual(text, '<!doctype html><head></head><body>' + 'a'.repeat(100) + "<script>let s = '</body>';</script><p>end</p><i>t</i></body></html>");
  assert.deepStrictEqual(finished.map((f) => [f.body, f.html]), [[null, true]]);
});

test('a page read whole is handed to finish; one too large goes out in order', async () => {
  const big = 'x'.repeat(5 * 1024 * 1024);
  const { srv, finished, url } = await serve((req, res) => {
    res.setHeader('content-type', 'text/plain');
    if (req.url === '/big') {
      res.write('A' + big);
      res.write('B' + big);
      res.end('C');
      return;
    }
    res.write('User-agent: *\n');
    res.end('Disallow: /x\n');
  }, { tag: '', whole: true });
  const small = await (await fetch(url)).text();
  assert.strictEqual(small, 'User-agent: *\nDisallow: /x\n');
  assert.strictEqual(String(finished[0].body), small);
  const text = await (await fetch(url + 'big')).text();
  srv.close();
  assert.strictEqual(text.length, 2 * big.length + 3);
  assert.ok(text.startsWith('A') && text[big.length + 1] === 'B' && text.endsWith('C'), 'out of order');
});

test('flushHeaders does not send a whole-read body with its old length', async () => {
  const srv = http.createServer((req, res) => {
    tagResponse(res, {
      tag: '',
      whole: true,
      finish(body) {
        const out = Buffer.concat([body, Buffer.from('-more')]);
        res.setHeader('content-length', String(out.length));
        return out;
      },
    });
    res.writeHead(200, { 'Content-Type': 'application/xml', 'Content-Length': 4 });
    res.flushHeaders();
    res.end('<x/>');
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  try {
    const r = await fetch('http://127.0.0.1:' + srv.address().port + '/');
    assert.strictEqual(await r.text(), '<x/>-more');
    assert.strictEqual(r.headers.get('content-length'), '9');
  } finally {
    srv.closeAllConnections();
    srv.close();
  }
});

test('a body read whole keeps its new length after the handler calls writeHead', async () => {
  const srv = http.createServer((req, res) => {
    tagResponse(res, {
      tag: '',
      whole: true,
      finish(body) {
        const out = Buffer.concat([body, Buffer.from('-and-more')]);
        res.setHeader('content-length', String(out.length));
        return out;
      },
    });
    const buf = Buffer.from('<urlset></urlset>');
    res.writeHead(200, { 'Content-Type': 'application/xml', 'Content-Length': buf.length, 'X-Kept': 'yes' });
    res.end(buf);
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  try {
    const r = await fetch('http://127.0.0.1:' + srv.address().port + '/');
    assert.strictEqual(await r.text(), '<urlset></urlset>-and-more');
    assert.strictEqual(r.headers.get('content-length'), '26');
    assert.strictEqual(r.headers.get('x-kept'), 'yes');
    assert.strictEqual(r.headers.get('content-type'), 'application/xml');
  } finally {
    srv.closeAllConnections();
    srv.close();
  }
});
