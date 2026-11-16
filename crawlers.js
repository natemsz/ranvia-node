'use strict';
// Search engine crawlers fetch pages with no browser headers and no
// assets, which is what the guard counts. A request whose User-Agent
// names a search crawler is checked the way the search engines document:
// the address's reverse DNS name must sit under the engine's domain, and
// that name must resolve back to the address. A verified crawler is never
// counted; a request that only claims to be one goes through the guard.

const dns = require('node:dns').promises;
// c-ares queries with their own timeout: dns.lookup would run in the
// libuv thread pool, where slow answers to attacker-chosen names hold
// up the application's file and crypto work too.
const defaultResolver = () => new dns.Resolver({ timeout: 2000, tries: 1 });
const net = require('node:net');

const SEARCH_CRAWLERS = [
  ['googlebot', ['.googlebot.com', '.google.com']],
  ['google-inspectiontool', ['.googlebot.com', '.google.com']],
  ['bingbot', ['.search.msn.com']],
  ['applebot', ['.applebot.apple.com']],
  ['yandexbot', ['.yandex.ru', '.yandex.net', '.yandex.com']],
];

const CACHE_MAX = 4096;
const OK_FOR = 24 * 3600e3;
const FAIL_FOR = 3600e3;
const LOOKUP_MAX = 4; // concurrent DNS checks; past it a claim waits for the next request
const NAMES_MAX = 4; // reverse names followed per address
const TIMEOUT = 2000;

function claimedCrawler(ua) {
  if (!ua) return null;
  ua = String(ua).toLowerCase();
  for (const [token, suffixes] of SEARCH_CRAWLERS) if (ua.includes(token)) return suffixes;
  return null;
}

const bare = (a) => (a && a.startsWith('::ffff:') && net.isIPv4(a.slice(7)) ? a.slice(7) : a || '');

// remoteIp is the default clientIp: the connection's address, or the last
// X-Forwarded-For entry when the connection comes from this machine.
function remoteIp(req) {
  const peer = bare(req.socket && req.socket.remoteAddress);
  const loopback = peer === '::1' || peer.startsWith('127.');
  if (!loopback) return peer;
  const fwd = req.headers['x-forwarded-for'];
  if (!fwd) return peer;
  const parts = String(Array.isArray(fwd) ? fwd[fwd.length - 1] : fwd).split(',');
  const last = parts[parts.length - 1].trim();
  return net.isIP(last) ? last : peer;
}

const sameIp = (a, b) => net.isIP(a) && net.isIP(b) && bare(a).toLowerCase() === bare(b).toLowerCase();

function createCrawlerVerifier(clientIp, resolver = defaultResolver()) {
  const seen = new Map(); // address -> { ok, at }
  let inFlight = 0;

  async function check(addr, suffixes) {
    if (!net.isIP(addr)) return false;
    let names;
    try { names = await resolver.reverse(addr); } catch { return false; }
    for (let name of names.slice(0, NAMES_MAX)) {
      name = name.toLowerCase().replace(/\.$/, '');
      if (!suffixes.some((s) => name.endsWith(s))) continue;
      let addrs = [];
      try {
        addrs = net.isIPv4(bare(addr)) ? await resolver.resolve4(name) : await resolver.resolve6(name);
      } catch { continue; }
      if (addrs.some((a) => sameIp(a, addr))) return true;
    }
    return false;
  }

  return async function verified(req) {
    const suffixes = claimedCrawler(req.headers['user-agent']);
    if (!suffixes) return false;
    const addr = clientIp(req);
    const now = Date.now();
    const got = seen.get(addr);
    if (got && now - got.at < (got.ok ? OK_FOR : FAIL_FOR)) return got.ok;
    if (inFlight >= LOOKUP_MAX) return false;
    inFlight++;
    let ok = false;
    try {
      let timer;
      ok = await Promise.race([
        check(addr, suffixes),
        new Promise((r) => { timer = setTimeout(() => r(false), TIMEOUT); }),
      ]);
      clearTimeout(timer);
    } finally {
      inFlight--;
    }
    if (seen.size >= CACHE_MAX) seen.delete(seen.keys().next().value);
    seen.set(addr, { ok, at: now });
    return ok;
  };
}

module.exports = { createCrawlerVerifier, remoteIp, claimedCrawler };
