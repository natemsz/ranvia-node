'use strict';
// Ranvia for Node.js: bot and AI scraper protection that runs on your
// own server (https://ranvia.io).
//
//   const { createRanvia } = require('ranvia');
//   const ranvia = createRanvia({ key: process.env.RANVIA_KEY });
//   app.use(ranvia.middleware);                       // Express, Connect
//   http.createServer(ranvia.wrap(handler));          // plain node:http
//
// This package is a loader. The engine that decides is downloaded from
// ranvia.io for your site key, kept on disk encrypted for your site, and
// run in memory as WebAssembly. Your traffic never leaves your server:
// the service only sends rules and receives counts.
//
// Until the engine is running (first start with ranvia.io out of reach,
// a revoked key), every request passes and the reason is logged: Ranvia
// never takes your site down.

const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const zlib = require('node:zlib');
const { wasiImports } = require('./wasi');
const { encodeRequest, decodeDecision } = require('./wire');
const { createCrawlerVerifier, remoteIp } = require('./crawlers');

const DEFAULT_SERVICE_URL = 'https://ranvia.io';
const LOADER_VERSION = '0.2.2';
const RULES_EVERY = 5 * 60e3;
const USAGE_EVERY = 60e3;
const ENGINE_EVERY = 5 * 60e3; // a conditional fetch: "not modified" unless a new engine is out

function parseSiteKey(key) {
  const m = /^rnv_([a-z0-9]+)\.([A-Za-z0-9_-]+)$/.exec(String(key || '').trim());
  const secret = m && Buffer.from(m[2], 'base64url');
  if (!m || secret.length < 32) throw new Error('ranvia: a site key looks like rnv_<site>.<secret>');
  return { id: m[1], secret };
}

const jitter = (ms) => ms * (0.8 + Math.random() * 0.4);

// Engine is one running copy of the WebAssembly engine.
class Engine {
  static async start(wasm, config, log) {
    let memory;
    const module = await WebAssembly.compile(wasm);
    const instance = await WebAssembly.instantiate(module, {
      wasi_snapshot_preview1: wasiImports(() => memory, log),
    });
    memory = instance.exports.memory;
    instance.exports._initialize();
    const e = new Engine(instance.exports);
    const err = JSON.parse(e.call('ranvia_init', Buffer.from(JSON.stringify(config))).toString() || '{}').error;
    if (err) throw new Error('ranvia: ' + err);
    return e;
  }

  constructor(exports) {
    this.x = exports;
  }

  // call runs an export with input copied into the engine's memory and
  // returns its output, copied out.
  call(name, input, ...extra) {
    const x = this.x;
    let args = extra;
    let ptr = 0;
    if (input) {
      ptr = x.ranvia_alloc(input.length);
      new Uint8Array(x.memory.buffer, ptr, input.length).set(input);
      args = [ptr, input.length, ...extra];
    }
    try {
      const res = BigInt.asUintN(64, BigInt(x[name](...args) ?? 0));
      if (res === 0n) return Buffer.alloc(0);
      const p = Number(res >> 32n);
      const n = Number(res & 0xffffffffn);
      return Buffer.from(new Uint8Array(x.memory.buffer, p, n));
    } finally {
      if (ptr) x.ranvia_free(ptr);
    }
  }

  decide(req) {
    return decodeDecision(this.call('ranvia_decide', encodeRequest(req)));
  }

  served(id, html) {
    this.x.ranvia_served(id, html ? 1 : 0);
  }

  bundle(raw) {
    const err = JSON.parse(this.call('ranvia_bundle', raw).toString() || '{}').error;
    if (err) throw new Error('ranvia: ' + err);
  }

  rulesVersion() {
    return this.call('ranvia_rules_version').toString();
  }

  tick() {
    this.x.ranvia_tick();
  }

  usage() {
    return this.call('ranvia_usage');
  }

  usageBack(raw) {
    this.call('ranvia_usage_back', raw);
  }
}

function createRanvia(cfg = {}) {
  const key = parseSiteKey(cfg.key);
  const log = cfg.log || (() => {});
  const clientIp = cfg.clientIp || remoteIp;
  const verifiedCrawler = cfg.verifiedCrawler || createCrawlerVerifier(clientIp);
  const base = String(cfg.serviceUrl || DEFAULT_SERVICE_URL).replace(/\/+$/, '');
  const cacheDir = cfg.cacheDir ||
    path.join(process.env.XDG_CACHE_HOME || path.join(os.homedir(), '.cache'), 'ranvia');
  const cacheFile = path.join(cacheDir, 'engine-' + key.id + '.bin');
  let engine = null;
  let bundle = null;
  let closed = false;
  const timers = [];

  // sign sets the Ranvia request headers (PROTOCOL.md).
  function signedHeaders(method, urlPath, body) {
    const ts = String(Math.floor(Date.now() / 1000));
    const nonce = crypto.randomBytes(16).toString('hex');
    const sum = crypto.createHash('sha256').update(body || Buffer.alloc(0)).digest('hex');
    const sig = crypto.createHmac('sha256', key.secret)
      .update(method + '\n' + urlPath + '\n' + ts + '\n' + nonce + '\n' + sum).digest('hex');
    return {
      'Ranvia-Site': key.id, 'Ranvia-Time': ts, 'Ranvia-Nonce': nonce, 'Ranvia-Signature': sig,
      'User-Agent': 'ranvia-node/' + LOADER_VERSION,
    };
  }

  async function service(method, urlPath, body, etag) {
    const headers = signedHeaders(method, urlPath, body);
    if (body) headers['Content-Type'] = 'application/json';
    if (etag) headers['If-None-Match'] = etag;
    // The engine is megabytes: compressed before sealing, and given
    // minutes on a slow link where a rules check gets 30 seconds.
    const engine = urlPath === '/v1/engine';
    if (engine) headers['Ranvia-Engine-Encoding'] = 'gzip';
    const res = await fetch(base + urlPath, { method, headers, body, signal: AbortSignal.timeout(engine ? 600e3 : 30e3) });
    return { status: res.status, body: Buffer.from(await res.arrayBuffer()), etag: res.headers.get('etag') || '' };
  }

  // open unseals the site's engine copy, in memory only.
  function open(sealed) {
    const sealKey = crypto.createHmac('sha256', key.secret).update('ranvia engine key').digest();
    if (sealed.length < 12 + 16) throw new Error('ranvia: the engine copy is truncated');
    const d = crypto.createDecipheriv('aes-256-gcm', sealKey, sealed.subarray(0, 12));
    d.setAAD(Buffer.from(key.id));
    d.setAuthTag(sealed.subarray(sealed.length - 16));
    let plain;
    try {
      plain = Buffer.concat([d.update(sealed.subarray(12, sealed.length - 16)), d.final()]);
    } catch {
      throw new Error('ranvia: the engine copy does not open with this site key');
    }
    // Sent gzipped (WebAssembly itself starts "\0asm", gzip 1f 8b).
    if (plain[0] === 0x1f && plain[1] === 0x8b) return zlib.gunzipSync(plain, { maxOutputLength: 256 << 20 });
    return plain;
  }

  async function readCache() {
    try {
      const sealed = await fs.readFile(cacheFile);
      const etag = (await fs.readFile(cacheFile + '.etag', 'utf8').catch(() => '')).trim();
      return { sealed, etag };
    } catch {
      return { sealed: null, etag: '' };
    }
  }

  async function writeCache(sealed, etag) {
    try {
      await fs.mkdir(cacheDir, { recursive: true, mode: 0o700 });
      await fs.writeFile(cacheFile + '.tmp', sealed, { mode: 0o600 });
      await fs.rename(cacheFile + '.tmp', cacheFile);
      await fs.writeFile(cacheFile + '.etag', etag, { mode: 0o600 });
    } catch (err) {
      log('ranvia: cache: ' + err.message);
    }
  }

  // fetchEngine returns the sealed engine: the service's copy when it
  // answers, else the cache.
  async function fetchEngine() {
    const cached = await readCache();
    let res;
    try {
      res = await service('GET', '/v1/engine', null, cached.etag);
    } catch (err) {
      if (cached.sealed) {
        log('ranvia: engine check failed (' + err.message + '); using the cached copy');
        return { sealed: cached.sealed, changed: false };
      }
      throw new Error('ranvia: engine download: ' + err.message);
    }
    if (res.status === 200) {
      await writeCache(res.body, res.etag);
      return { sealed: res.body, changed: true };
    }
    if (cached.sealed) {
      if (res.status !== 304) log('ranvia: engine check: service answered ' + res.status + '; using the cached copy');
      return { sealed: cached.sealed, changed: false };
    }
    throw new Error('ranvia: engine download: service answered ' + res.status + ': ' + res.body.toString().trim());
  }

  async function load(sealed) {
    let rules;
    if (cfg.rulesFile) rules = JSON.parse(await fs.readFile(cfg.rulesFile, 'utf8'));
    const e = await Engine.start(open(sealed), { key: cfg.key, rules, service_keys: cfg.serviceKeys }, log);
    if (bundle) {
      try { e.bundle(bundle); } catch { /* the next refresh brings a fresh one */ }
    }
    return e;
  }

  async function refreshRules() {
    const v = engine.rulesVersion();
    const res = await service('GET', '/v1/rules', null, v ? '"' + v + '"' : '');
    if (res.status === 304) return;
    if (res.status !== 200) throw new Error('ranvia: rules: service answered ' + res.status);
    engine.bundle(res.body);
    bundle = res.body;
  }

  async function reportUsage(e = engine) {
    if (!e) return;
    const rep = e.usage();
    if (!rep.length) return;
    try {
      const res = await service('POST', '/v1/usage', rep);
      if (res.status >= 500) e.usageBack(rep);
    } catch {
      e.usageBack(rep);
    }
  }

  function every(ms, fn) {
    const run = async () => {
      if (closed) return;
      try { await fn(); } catch (err) { log(err.message); }
      if (!closed) timers.push(setTimeout(run, jitter(ms)).unref());
    };
    timers.push(setTimeout(run, jitter(ms)).unref());
  }

  const started = (async () => {
    let wait = 15e3;
    while (!closed && !engine) {
      try {
        const { sealed } = await fetchEngine();
        engine = await load(sealed);
        log('ranvia: engine running');
      } catch (err) {
        log(err.message + '; passing requests until the engine loads');
        await new Promise((r) => setTimeout(r, jitter(wait)).unref());
        wait = Math.min(wait * 2, 5 * 60e3);
      }
    }
    if (closed) return;
    try { await refreshRules(); } catch (err) { log(err.message); }
    every(RULES_EVERY, refreshRules);
    every(USAGE_EVERY, async () => { engine.tick(); await reportUsage(); });
    every(ENGINE_EVERY, async () => {
      const { sealed, changed } = await fetchEngine();
      if (!changed) return;
      const next = await load(sealed);
      const old = engine;
      engine = next;
      await reportUsage(old);
      log('ranvia: engine updated');
    });
  })();

  function readBody(req) {
    return new Promise((resolve) => {
      const chunks = [];
      let size = 0;
      req.on('data', (c) => { if (size < 1024) { chunks.push(c); size += c.length; } });
      req.on('end', () => resolve(Buffer.concat(chunks).subarray(0, 1024).toString('utf8')));
      req.on('error', () => resolve(''));
    });
  }

  // handle decides one request: true when the site should serve it.
  async function handle(req, res) {
    const e = engine;
    if (!e) return true;
    const r = {
      method: req.method, uri: req.originalUrl || req.url, host: req.headers.host || '',
      header: req.headers, proto: req.httpVersion ? 'HTTP/' + req.httpVersion : '',
    };
    if (req.method === 'POST' && (req.url || '').split('?')[0] === '/guard/verify') r.body = await readBody(req);
    if (cfg.network) r.network = cfg.network(req) || '';
    r.bind = addressBlock(clientIp(req));
    r.crawler = !!(await verifiedCrawler(req));
    if (cfg.signedIn && req.headers.cookie) r.signedIn = !!(await cfg.signedIn(req));
    let d;
    try {
      d = e.decide(r);
    } catch (err) {
      log(err.message + '; passing the request');
      return true;
    }
    for (const [k, v] of d.header) res.appendHeader(k, v);
    if (!d.serve) {
      if (cfg.logRefusals && d.reason) {
        log(`ranvia: ${d.reason} ${req.method} ${(req.originalUrl || req.url || '').split('?')[0]} ${JSON.stringify(req.headers['user-agent'] || '')}`);
      }
      res.statusCode = d.status || 200;
      res.end(d.body);
      return false;
    }
    if (d.sniff) {
      res.once('finish', () => {
        const ct = String(res.getHeader('content-type') || '');
        try { e.served(d.sniff, /^text\/html/i.test(ct)); } catch { /* engine replaced */ }
      });
    }
    return true;
  }

  return {
    // middleware is Express / Connect middleware.
    middleware(req, res, next) {
      handle(req, res).then((serve) => { if (serve) next(); }, (err) => { log(err.message); next(); });
    },
    // wrap guards a plain node:http request handler.
    wrap(handler) {
      return (req, res) => {
        handle(req, res).then((serve) => { if (serve) handler(req, res); }, (err) => { log(err.message); handler(req, res); });
      };
    },
    // ready resolves once the engine is running (or close is called).
    ready: () => started,
    isReady: () => engine !== null,
    // close stops background work, sending a last usage report.
    async close() {
      closed = true;
      for (const t of timers) clearTimeout(t);
      await reportUsage();
    },
  };
}

// addressBlock is an address's /24 (IPv4) or /48 (IPv6), which the
// engine ties passes to when the site names no network; '' for a
// loopback, private or unreadable one. It stays on this server.
function addressBlock(addr) {
  if (!addr) return '';
  let ip = String(addr).trim().replace(/^\[|\]$/g, '');
  if (ip.startsWith('::ffff:') && net.isIPv4(ip.slice(7))) ip = ip.slice(7);
  if (net.isIPv4(ip)) {
    const [a, b, c] = ip.split('.').map(Number);
    if (a === 10 || a === 127 || a === 0 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254)) return '';
    return `${a}.${b}.${c}.0/24`;
  }
  if (!net.isIPv6(ip)) return '';
  const lower = ip.toLowerCase();
  if (lower === '::1' || lower === '::' || /^f[cd]/.test(lower) || /^fe[89ab]/.test(lower)) return '';
  // Expand to eight groups, keep the first three.
  const [head, tail = ''] = lower.split('::');
  const h = head ? head.split(':') : [];
  const t = lower.includes('::') ? (tail ? tail.split(':') : []) : [];
  const groups = lower.includes('::') ? [...h, ...Array(8 - h.length - t.length).fill('0'), ...t] : h;
  if (groups.length !== 8) return '';
  const first = groups.slice(0, 3).map((g) => parseInt(g, 16).toString(16));
  // Shortest form, as Go writes it: trailing zero groups fold into '::'.
  while (first.length && first[first.length - 1] === '0') first.pop();
  return first.join(':') + '::/48';
}

module.exports = { createRanvia, LOADER_VERSION, addressBlock };
