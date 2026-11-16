'use strict';
// node --test test/crawlers.test.js
const test = require('node:test');
const assert = require('node:assert');
const { createCrawlerVerifier, remoteIp } = require('../crawlers');

const rdns = {
  '66.249.66.1': ['crawl-66-249-66-1.googlebot.com.'],
  '203.0.113.9': ['crawl.googlebot.com.evil.example.'],
  '198.51.100.7': ['crawl-1.googlebot.com.'],
};
const fwd = {
  'crawl-66-249-66-1.googlebot.com': ['66.249.66.1'],
  'crawl-1.googlebot.com': ['192.0.2.1'],
};
const resolver = {
  calls: 0,
  async reverse(a) { this.calls++; if (rdns[a]) return rdns[a]; throw new Error('no PTR'); },
  async lookup(h) { if (fwd[h]) return fwd[h].map((address) => ({ address })); throw new Error('no A'); },
};
const google = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
const req = (ua, addr, headers = {}) => ({ headers: { 'user-agent': ua, ...headers }, socket: { remoteAddress: addr } });

test('crawler verification accepts only matching reverse and forward DNS', async () => {
  const verified = createCrawlerVerifier(remoteIp, resolver);
  assert.strictEqual(await verified(req(google, '66.249.66.1')), true);
  assert.strictEqual(await verified(req(google, '::ffff:66.249.66.1')), true);
  assert.strictEqual(await verified(req(google, '203.0.113.9')), false);
  assert.strictEqual(await verified(req(google, '198.51.100.7')), false);
  assert.strictEqual(await verified(req(google, '192.0.2.50')), false);
  assert.strictEqual(await verified(req('Mozilla/5.0 Chrome/132.0', '66.249.66.1')), false);
  const before = resolver.calls;
  await verified(req(google, '66.249.66.1'));
  assert.strictEqual(resolver.calls, before, 'a cached verdict answers without DNS');
});

test('remoteIp trusts X-Forwarded-For only from loopback', () => {
  const h = { 'x-forwarded-for': '10.0.0.1, 66.249.66.1' };
  assert.strictEqual(remoteIp(req('', '127.0.0.1', h)), '66.249.66.1');
  assert.strictEqual(remoteIp(req('', '::ffff:127.0.0.1', h)), '66.249.66.1');
  assert.strictEqual(remoteIp(req('', '203.0.113.9', h)), '203.0.113.9');
});
