'use strict';
// Ranvia for Node.js: bot and AI scraper protection that runs on your
// own server (https://ranvia.io).
//
//   const { createRanvia } = require('ranvia');
//   const ranvia = createRanvia({ key: process.env.RANVIA_KEY });
//   app.use(ranvia.middleware);                       // Express, Connect
//   http.createServer(ranvia.wrap(handler));          // plain node:http

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
const LOADER_VERSION = '0.5.0';
const RULES_EVERY = 5 * 60e3;
const USAGE_EVERY = 60e3;
const ENGINE_EVERY = 5 * 60e3;
const HARD_TIMEOUT = 2500;

function isTerminalAuthStatus(status) {
  return status === 401 || status === 402 || status === 403;
}

function parseSiteKey(key) {
  const m = /^rnv_([a-z0-9]+)\.([A-Za-z0-9_-]+)$/.exec(String(key || '').trim());
  const secret = m && Buffer.from(m[2], 'base64url');
  if (!m || secret.length < 32) throw new Error('ranvia: a site key looks like rnv_<site>.<secret>');
  return { id: m[1], secret };
}

const jitter = (ms) => ms * (0.8 + Math.random() * 0.4);

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
    if (instance.exports.ranvia_confirm) config = { ...config, confirm_assets: true };
    if (instance.exports.ranvia_rewrite) config = { ...config, rewrite_responses: true };
    if (instance.exports.ranvia_hard_verdict && instance.exports.ranvia_hard_fallback) {
      config = { ...config, remote_hard: true };
    }
    config = { ...config, hold_responses: true };
    const cfgBuf = Buffer.from(JSON.stringify(config));
    let err;
    try {
      err = JSON.parse(e.call('ranvia_init', cfgBuf).toString() || '{}').error;
    } finally {
      cfgBuf.fill(0);
    }
    if (err) throw new Error('ranvia: ' + err);
    if (instance.exports.ranvia_box) {
      e.boxToken = e.call('ranvia_box').toString('utf8');
    }
    return e;
  }

  constructor(exports) {
    this.x = exports;
    this.boxToken = '';
  }

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

  markdown(page) {
    if (!this.x.ranvia_markdown || !page.length) return Buffer.alloc(0);
    return this.call('ranvia_markdown', page);
  }

  rewrite(body) {
    if (!this.x.ranvia_rewrite || !body.length) return Buffer.alloc(0);
    return this.call('ranvia_rewrite', body);
  }

  robots(body) {
    if (this.x.ranvia_robots && body.length) this.call('ranvia_robots', body);
  }

  confirm(id, status, contentType) {
    const x = this.x;
    if (!x.ranvia_confirm) return '';
    const input = Buffer.from(contentType || ' ');
    const ptr = x.ranvia_alloc(input.length);
    try {
      new Uint8Array(x.memory.buffer, ptr, input.length).set(input);
      const res = BigInt.asUintN(64, BigInt(x.ranvia_confirm(BigInt(id), status, ptr, input.length) ?? 0));
      if (res === 0n) return '';
      return Buffer.from(new Uint8Array(x.memory.buffer, Number(res >> 32n), Number(res & 0xffffffffn))).toString('utf8');
    } finally {
      x.ranvia_free(ptr);
    }
  }

  bundle(raw) {
    const err = JSON.parse(this.call('ranvia_bundle', raw).toString() || '{}').error;
    if (err) throw new Error('ranvia: ' + err);
  }

  posture() {
    if (!this.x.ranvia_posture) return Buffer.alloc(0);
    return this.call('ranvia_posture');
  }

  applyPosture(raw) {
    if (!this.x.ranvia_posture_apply || !raw.length) return;
    const err = JSON.parse(this.call('ranvia_posture_apply', raw).toString() || '{}').error;
    if (err) throw new Error('ranvia: ' + err);
  }

  hardVerdict(raw) {
    if (!this.x.ranvia_hard_verdict || !raw.length) return [];
    const out = this.call('ranvia_hard_verdict', raw);
    if (!out.length) return [];
    try {
      return JSON.parse(out.toString('utf8')).cookies || [];
    } catch {
      return [];
    }
  }

  hardFallback(ctxTok) {
    if (!this.x.ranvia_hard_fallback) return { serve: true, header: [] };
    return decodeDecision(this.call('ranvia_hard_fallback', Buffer.from(ctxTok)));
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
  let running = null;
  let restarting = null;
  let bundle = null;
  let lastRobots = null;
  let closed = false;
  const timers = [];

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

  async function service(method, urlPath, body, etag, extra = null, timeoutMs = 0) {
    const headers = signedHeaders(method, urlPath, body);
    if (body) headers['Content-Type'] = 'application/json';
    if (etag) headers['If-None-Match'] = etag;
    const isEng = urlPath === '/v1/engine';
    if (isEng) headers['Ranvia-Engine-Encoding'] = 'gzip';
    if (extra) {
      for (const [k, v] of Object.entries(extra)) {
        if (v) headers[k] = v;
      }
    }
    const ms = timeoutMs || (isEng ? 600e3 : 30e3);
    const res = await fetch(base + urlPath, { method, headers, body, signal: AbortSignal.timeout(ms) });
    return { status: res.status, body: Buffer.from(await res.arrayBuffer()), etag: res.headers.get('etag') || '', headers: res.headers };
  }

  function open(sealed) {
    const sealKey = crypto.createHmac('sha256', key.secret).update('ranvia engine key').digest();
    if (sealed.length < 12 + 16) {
      sealKey.fill(0);
      throw new Error('ranvia: the engine copy is truncated');
    }
    const d = crypto.createDecipheriv('aes-256-gcm', sealKey, sealed.subarray(0, 12));
    sealKey.fill(0);
    d.setAAD(Buffer.from(key.id));
    d.setAuthTag(sealed.subarray(sealed.length - 16));
    let plain;
    try {
      plain = Buffer.concat([d.update(sealed.subarray(12, sealed.length - 16)), d.final()]);
    } catch {
      throw new Error('ranvia: the engine copy does not open with this site key');
    }
    if (plain[0] === 0x1f && plain[1] === 0x8b) {
      try {
        return zlib.gunzipSync(plain, { maxOutputLength: 256 << 20 });
      } finally {
        plain.fill(0);
      }
    }
    return plain;
  }

  async function wipeCache() {
    await fs.unlink(cacheFile).catch(() => {});
    await fs.unlink(cacheFile + '.etag').catch(() => {});
  }

  async function deactivate(status, detail) {
    engine = null;
    if (running) { running.fill(0); running = null; }
    bundle = null;
    await wipeCache();
    log(`ranvia: service answered ${status}${detail ? ' (' + detail + ')' : ''}; engine unloaded and passing requests through`);
  }

  async function readCache() {
    try {
      const sealed = await fs.readFile(cacheFile);
      const [etag = '', issued = '0'] = (await fs.readFile(cacheFile + '.etag', 'utf8').catch(() => '')).trim().split('\n');
      return { sealed, etag: etag.trim(), issued: Number(issued) || 0 };
    } catch {
      return { sealed: null, etag: '', issued: 0 };
    }
  }

  async function writeCache(sealed, etag, issued) {
    try {
      await fs.mkdir(cacheDir, { recursive: true, mode: 0o700 });
      await fs.writeFile(cacheFile + '.tmp', sealed, { mode: 0o600 });
      await fs.rename(cacheFile + '.tmp', cacheFile);
      await fs.writeFile(cacheFile + '.etag', etag + '\n' + String(issued || 0), { mode: 0o600 });
    } catch (err) {
      log('ranvia: cache: ' + err.message);
    }
  }

  function checkIssue(headers, sealed) {
    const issued = headers && headers.get('ranvia-engine-issued');
    const tag = headers && headers.get('ranvia-engine-tag');
    if (!issued || !/^[0-9]+$/.test(issued) || !tag) return null;
    const sealKey = crypto.createHmac('sha256', key.secret).update('ranvia engine key').digest();
    const sum = crypto.createHash('sha256').update(sealed).digest('hex');
    const want = crypto.createHmac('sha256', sealKey).update('ranvia engine tag|' + key.id + '|' + issued + '|' + sum).digest('hex');
    sealKey.fill(0);
    const a = Buffer.from(want, 'utf8');
    const b = Buffer.from(String(tag), 'utf8');
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    return Number(issued);
  }

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
    if (isTerminalAuthStatus(res.status)) {
      if (cached.sealed) cached.sealed.fill(0);
      await deactivate(res.status, res.body.toString('utf8').trim());
      const inactive = new Error('ranvia: site key or plan is inactive');
      inactive.inactive = true;
      throw inactive;
    }
    if (res.status === 200) {
      const issued = checkIssue(res.headers, res.body);
      if (issued !== null && issued >= cached.issued) {
        if (cached.sealed) cached.sealed.fill(0);
        await writeCache(res.body, res.etag, issued);
        return { sealed: res.body, changed: true };
      }
      log('ranvia: the service\'s engine copy has no valid issue tag, or is older than the cached one');
      if (cached.sealed) return { sealed: cached.sealed, changed: false };
      throw new Error('ranvia: engine download: no valid issue tag');
    }
    if (cached.sealed) {
      if (res.status !== 304) log('ranvia: engine check: service answered ' + res.status + '; using the cached copy');
      return { sealed: cached.sealed, changed: false };
    }
    throw new Error('ranvia: engine download: service answered ' + res.status + ': ' + res.body.toString().trim());
  }

  async function load(sealed, withBundle = bundle) {
    let rules;
    if (cfg.rulesFile) rules = JSON.parse(await fs.readFile(cfg.rulesFile, 'utf8'));
    const wasm = open(sealed);
    let e;
    try {
      e = await Engine.start(wasm, { key: cfg.key, rules, service_keys: cfg.serviceKeys }, log);
    } finally {
      wasm.fill(0);
    }
    if (withBundle) {
      try { e.bundle(withBundle); } catch { /* next refresh brings a box-sealed bundle */ }
    }
    if (lastRobots) {
      try { e.robots(lastRobots); } catch { /* next robots.txt fetch refreshes it */ }
    }
    return e;
  }

  async function refreshRules(target = engine) {
    if (!target) return;
    const v = target.rulesVersion();
    const extra = target.boxToken ? { 'Ranvia-Box': target.boxToken } : null;
    const res = await service('GET', '/v1/rules', null, v ? '"' + v + '"' : '', extra);
    if (isTerminalAuthStatus(res.status)) {
      await deactivate(res.status, res.body.toString('utf8').trim());
      return;
    }
    if (res.status === 304) return;
    if (res.status !== 200) throw new Error('ranvia: rules: service answered ' + res.status);
    target.bundle(res.body);
    bundle = res.body;
  }

  async function syncPosture(target = engine) {
    if (!target) return;
    const req = target.posture();
    if (!req.length) return;
    const extra = target.boxToken ? { 'Ranvia-Box': target.boxToken } : null;
    const res = await service('POST', '/v1/posture', req, '', extra);
    if (res.status === 200 && res.body.length) target.applyPosture(res.body);
  }

  async function proxyHard(res, target, hardCtx, payload) {
    const extra = { 'Ranvia-Hard-Ctx': hardCtx };
    if (target.boxToken) extra['Ranvia-Box'] = target.boxToken;
    let upstream;
    try {
      upstream = await service('POST', '/v1/hard', payload, '', extra, HARD_TIMEOUT);
    } catch {
      upstream = null;
    }
    if (!upstream || upstream.status >= 500) {
      const fb = target.hardFallback(hardCtx);
      if (fb.serve) {
        res.statusCode = 503;
        res.end();
        return;
      }
      for (const [k, v] of fb.header || []) res.appendHeader(k, v);
      res.statusCode = fb.status || 429;
      res.end(fb.body);
      return;
    }
    const verdict = upstream.headers.get('ranvia-hard-verdict');
    if (verdict) {
      for (const ck of target.hardVerdict(Buffer.from(verdict, 'utf8'))) {
        res.appendHeader('Set-Cookie', ck);
      }
    }
    const ct = upstream.headers.get('content-type');
    if (ct) res.setHeader('Content-Type', ct);
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.statusCode = upstream.status;
    res.end(upstream.body);
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
      try { await fn(); } catch (err) { if (!err.inactive) log(err.message); }
      if (!closed) timers.push(setTimeout(run, jitter(ms)).unref());
    };
    timers.push(setTimeout(run, jitter(ms)).unref());
  }

  const started = (async () => {
    let wait = 15e3;
    while (!closed && !engine) {
      try {
        const { sealed } = await fetchEngine();
        engine = await load(sealed, null);
        running = sealed;
        log('ranvia: engine running');
      } catch (err) {
        if (!err.inactive) log(err.message + '; passing requests until the engine loads');
        await new Promise((r) => setTimeout(r, jitter(wait)).unref());
        wait = Math.min(wait * 2, 5 * 60e3);
      }
    }
    if (closed) return;
    try { await refreshRules(); } catch (err) { if (!err.inactive) log(err.message); }
    every(RULES_EVERY, () => refreshRules());
    every(USAGE_EVERY, async () => {
      if (!engine) return;
      engine.tick();
      await syncPosture();
      await reportUsage();
    });
    every(ENGINE_EVERY, async () => {
      const { sealed, changed } = await fetchEngine();
      if (!changed && (engine || restarting)) return;
      const next = await load(sealed, null);
      try { await refreshRules(next); } catch { /* uses defaults until next rules tick */ }
      const old = engine;
      engine = next;
      running = sealed;
      await reportUsage(old);
      log('ranvia: engine updated');
    });
  })();

  function readBody(req) {
    if (req.body && typeof req.body === 'object' && !Buffer.isBuffer(req.body)) {
      return Promise.resolve(new URLSearchParams(req.body).toString().slice(0, 1024));
    }
    if (typeof req.body === 'string' || Buffer.isBuffer(req.body)) {
      return Promise.resolve(String(req.body).slice(0, 1024));
    }
    if (req.readableEnded || req.complete) return Promise.resolve('');
    return new Promise((resolve) => {
      const chunks = [];
      let size = 0;
      const done = (s) => { clearTimeout(timer); resolve(s); };
      const timer = setTimeout(() => done(''), 5000);
      req.on('data', (c) => { if (size < 1024) { chunks.push(c); size += c.length; } });
      req.on('end', () => done(Buffer.concat(chunks).subarray(0, 1024).toString('utf8')));
      req.on('error', () => done(''));
      req.on('close', () => done(''));
    });
  }

  function restart(broken) {
    if (engine !== broken || restarting || !running) return;
    engine = null;
    restarting = (async () => {
      try {
        const next = await load(running, null);
        try { await refreshRules(next); } catch { /* refreshed on next rules tick */ }
        engine = next;
        log('ranvia: engine restarted');
      } catch (err) {
        log(err.message + '; passing requests until the engine loads');
      } finally {
        restarting = null;
      }
    })();
  }

  async function handle(req, res) {
    const e = engine;
    if (!e) return true;
    let header = req.headers;
    const peer = String((req.socket && req.socket.remoteAddress) || '').replace(/^::ffff:/, '');
    if (!(peer === '::1' || peer.startsWith('127.'))) {
      header = { ...req.headers };
      delete header['x-forwarded-proto'];
      delete header['x-forwarded-for'];
    }
    if (header['ranvia-ja4'] !== undefined || cfg.ja4Header) {
      if (header === req.headers) header = { ...req.headers };
      delete header['ranvia-ja4'];
      const ja4 = cfg.ja4Header ? req.headers[String(cfg.ja4Header).toLowerCase()] : undefined;
      if (typeof ja4 === 'string' && ja4.length <= 64) header['ranvia-ja4'] = ja4;
    }
    if (header['ranvia-h2'] !== undefined || cfg.h2Header) {
      if (header === req.headers) header = { ...req.headers };
      delete header['ranvia-h2'];
      const h2 = cfg.h2Header ? req.headers[String(cfg.h2Header).toLowerCase()] : undefined;
      if (typeof h2 === 'string' && h2.length <= 512) header['ranvia-h2'] = h2;
    }
    const r = {
      method: req.method, uri: req.originalUrl || req.url, host: req.headers.host || '',
      header, proto: req.httpVersion ? 'HTTP/' + req.httpVersion : '',
      tls: !!(req.socket && req.socket.encrypted),
    };
    if (req.method === 'POST' && (req.url || '').split('?')[0].startsWith('/guard/')) r.body = await readBody(req);
    if (cfg.network) r.network = cfg.network(req) || '';
    const ip = clientIp(req);
    r.bind = addressBlock(ip);
    r.addr = (ip || '').replace(/^::ffff:(?=\d+\.\d+\.\d+\.\d+$)/, '');
    r.crawler = !!(await verifiedCrawler(req));
    if (cfg.signedIn && req.headers.cookie) r.signedIn = !!(await cfg.signedIn(req));
    let d;
    try {
      d = e.decide(r);
    } catch (err) {
      log(err.message + '; restarting the engine');
      restart(e);
      return true;
    }
    let markdown = false;
    let rewrite = false;
    let hold = 0;
    let hardCtx = '';
    for (const [k, v] of d.header) {
      const lk = k.toLowerCase();
      if (lk === 'ranvia-markdown') { markdown = true; continue; }
      if (lk === 'ranvia-rewrite') { rewrite = true; continue; }
      if (lk === 'ranvia-hold') { hold = parseInt(v, 10) || 0; continue; }
      if (lk === 'ranvia-hard') { hardCtx = v; continue; }
      res.appendHeader(k, v);
    }
    if (!d.serve && hardCtx) {
      await proxyHard(res, e, hardCtx, d.body);
      return false;
    }
    if (!d.serve) {
      if (cfg.logRefusals && d.reason) {
        log(`ranvia: ${d.reason} ${req.method} ${(req.originalUrl || req.url || '').split('?')[0]} ${JSON.stringify(req.headers['user-agent'] || '')}`);
      }
      if (hold > 0 && holding < 256) {
        holding++;
        try {
          await new Promise((resolve) => {
            const t = setTimeout(resolve, Math.min(hold, 15000));
            res.once('close', () => { clearTimeout(t); resolve(); });
          });
        } finally {
          holding--;
        }
        if (res.destroyed || res.writableEnded) return false;
      }
      res.statusCode = d.status || 200;
      res.end(d.body);
      return false;
    }
    if (d.sniff && d.confirm) {
      const origWriteHead = res.writeHead;
      const origWrite = res.write;
      const origEnd = res.end;
      let firstBody = '';
      const restore = () => {
        res.writeHead = origWriteHead;
        res.write = origWrite;
        res.end = origEnd;
      };
      const sniffChunk = (chunk) => {
        if (!firstBody && chunk != null && typeof chunk !== 'function') {
          firstBody = (Buffer.isBuffer(chunk) ? chunk.subarray(0, 512).toString('utf8') : String(chunk).slice(0, 512));
        }
      };
      res.write = function (chunk, ...args) {
        sniffChunk(chunk);
        return origWrite.call(this, chunk, ...args);
      };
      res.end = function (chunk, ...args) {
        if (typeof chunk !== 'function') sniffChunk(chunk);
        try {
          return origEnd.call(this, chunk, ...args);
        } finally {
          restore();
        }
      };
      res.writeHead = function (status, ...rest) {
        if (status >= 200) {
          restore();
          let ct = res.getHeader('content-type');
          let hdrIdx = -1;
          for (let i = 0; i < rest.length; i++) {
            const a = rest[i];
            if (a && typeof a === 'object') {
              hdrIdx = i;
              if (Array.isArray(a)) {
                if (Array.isArray(a[0])) {
                  for (const pair of a) {
                    if (Array.isArray(pair) && String(pair[0]).toLowerCase() === 'content-type') ct = pair[1];
                  }
                } else {
                  for (let j = 0; j + 1 < a.length; j += 2) {
                    if (String(a[j]).toLowerCase() === 'content-type') ct = a[j + 1];
                  }
                }
              } else {
                for (const k of Object.keys(a)) {
                  if (k.toLowerCase() === 'content-type') ct = a[k];
                }
              }
            }
          }
          if (!ct && firstBody && /^\s*(?:<!doctype\s+html|<html\b|<head\b|<body\b)/i.test(firstBody)) {
            ct = 'text/html';
          }
          try {
            const c = e.confirm(d.sniff, status, String(ct || ''));
            if (c) {
              if (hdrIdx >= 0) {
                const arg = rest[hdrIdx];
                if (Array.isArray(arg)) {
                  rest[hdrIdx] = Array.isArray(arg[0]) ? [...arg, ['Set-Cookie', c]] : [...arg, 'Set-Cookie', c];
                } else {
                  const copy = { ...arg };
                  const scKey = Object.keys(copy).find((k) => k.toLowerCase() === 'set-cookie');
                  if (scKey) {
                    copy[scKey] = Array.isArray(copy[scKey]) ? [...copy[scKey], c] : [copy[scKey], c];
                  } else {
                    copy['Set-Cookie'] = c;
                  }
                  rest[hdrIdx] = copy;
                }
              } else {
                res.appendHeader('Set-Cookie', c);
              }
            }
          } catch { /* engine replaced */ }
        }
        return origWriteHead.call(this, status, ...rest);
      };
      return true;
    }
    if (rewrite && !d.confirm) {
      tagResponse(res, {
        tag: '',
        whole: true,
        finish(body) {
          if (body && (!res.statusCode || res.statusCode === 200)) {
            try {
              const out = e.rewrite(body);
              if (out.length) {
                body = out;
                try {
                  res.setHeader('content-length', String(body.length));
                  res.setHeader('cache-control', 'private, no-store');
                  for (const h of ['etag', 'last-modified', 'expires', 'cdn-cache-control', 'cloudflare-cdn-cache-control', 'vercel-cdn-cache-control', 'surrogate-control']) res.removeHeader(h);
                } catch { /* headers already sent */ }
              }
            } catch { /* engine replaced */ }
          }
          try { if (d.sniff) e.served(d.sniff, false); } catch { /* engine replaced */ }
          return body;
        },
      });
      return true;
    }
    const robots = (req.url || '').split('?')[0] === '/robots.txt';
    if (d.prove || robots || (markdown && !d.confirm)) {
      const tag = d.prove || '';
      tagResponse(res, {
        tag,
        whole: robots || markdown,
        finish(body, html) {
          const ok = !res.statusCode || res.statusCode === 200;
          if (body) {
            const ct = String(res.getHeader('content-type') || '');
            if (html && tag) {
              const tagged = withTag(body, tag);
              if (tagged !== body) {
                body = tagged;
                try { res.setHeader('content-length', String(body.length)); } catch { /* headers already sent */ }
              }
            } else if (robots && tag && ok && /^text\/plain/i.test(ct)) {
              body = Buffer.concat([body, Buffer.from(tag)]);
              try { res.setHeader('content-length', String(body.length)); } catch { /* headers already sent */ }
            }
            if (markdown && html && ok) {
              try {
                const md = e.markdown(body);
                if (md.length) {
                  body = md;
                  res.setHeader('content-type', 'text/markdown; charset=utf-8');
                  res.setHeader('content-length', String(body.length));
                  res.appendHeader('vary', 'Accept');
                }
              } catch { /* engine replaced */ }
            }
            try {
              if (robots && ok) {
                lastRobots = body;
                e.robots(body);
              }
            } catch { /* engine replaced */ }
          }
          try { if (d.sniff) e.served(d.sniff, html); } catch { /* engine replaced */ }
          return body;
        },
      });
      return true;
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
    middleware(req, res, next) {
      handle(req, res).then((serve) => { if (serve) next(); }, (err) => { log(err.message); next(); });
    },
    wrap(handler) {
      return (req, res) => {
        handle(req, res).then((serve) => { if (serve) handler(req, res); }, (err) => { log(err.message); handler(req, res); });
      };
    },
    ready: () => started,
    isReady: () => engine !== null,
    async close() {
      closed = true;
      for (const t of timers) clearTimeout(t);
      await reportUsage();
    },
  };
}

const BODY_CLOSE = '</body>';
const BUFFER_MAX = 8 * 1024 * 1024;
const HOLD_MAX = 64 * 1024;

function lastBodyClose(b) {
  return b.toString('latin1').toLowerCase().lastIndexOf(BODY_CLOSE);
}

function withTag(b, tag) {
  const i = lastBodyClose(b);
  return i < 0 ? b : Buffer.concat([b.subarray(0, i), Buffer.from(tag), b.subarray(i)]);
}

function toBuffer(c) {
  if (Buffer.isBuffer(c)) return c;
  if (c instanceof Uint8Array) return Buffer.from(c);
  return Buffer.from(String(c));
}

function tagResponse(res, { tag, whole, finish }) {
  const origWrite = res.write;
  const origEnd = res.end;
  let mode = '';
  let html = false;
  let pending = Buffer.alloc(0);
  let chunks = [];
  let size = 0;
  const isHTML = () => /^text\/html/i.test(String(res.getHeader('content-type') || ''));
  const decide = () => {
    if (mode) return;
    html = isHTML();
    if (whole) {
      mode = 'buffer';
    } else if (html && tag) {
      mode = 'stream';
      try { if (!res.headersSent) res.removeHeader('content-length'); } catch { /* headers already sent */ }
    } else {
      mode = 'pass';
    }
  };
  const later = (cb) => { if (cb) process.nextTick(cb); };
  const origWriteHead = res.writeHead;
  const unhook = () => { if (whole) res.writeHead = origWriteHead; };
  if (whole) {
    const origFlush = res.flushHeaders;
    res.flushHeaders = function () { if (mode === 'pass') return origFlush.call(this); };
    res.writeHead = function (status, ...rest) {
      if (status < 200) return origWriteHead.call(this, status, ...rest);
      unhook();
      res.statusCode = status;
      const seen = new Set();
      const put = (k, v) => {
        const name = String(k).toLowerCase();
        if (seen.has(name)) res.appendHeader(k, v); else res.setHeader(k, v);
        seen.add(name);
      };
      for (const a of rest) {
        if (typeof a === 'string') res.statusMessage = a;
        else if (Array.isArray(a)) {
          if (Array.isArray(a[0])) for (const [k, v] of a) put(k, v);
          else for (let i = 0; i + 1 < a.length; i += 2) put(a[i], a[i + 1]);
        } else if (a) for (const k of Object.keys(a)) put(k, a[k]);
      }
      return this;
    };
  }
  res.write = function (chunk, ...args) {
    if (chunk == null || typeof chunk === 'function') return origWrite.call(this, chunk, ...args);
    decide();
    const cb = typeof args[args.length - 1] === 'function' ? args.pop() : null;
    const b = toBuffer(chunk);
    if (mode === 'stream') {
      pending = pending.length ? Buffer.concat([pending, b]) : b;
      let cut = pending.length - (BODY_CLOSE.length - 1);
      const i = lastBodyClose(pending);
      if (i >= 0 && pending.length - i <= HOLD_MAX) cut = i;
      if (cut <= 0) { later(cb); return true; }
      const out = pending.subarray(0, cut);
      pending = Buffer.from(pending.subarray(cut));
      return cb ? origWrite.call(this, out, cb) : origWrite.call(this, out);
    }
    if (mode === 'buffer') {
      size += b.length;
      if (size <= BUFFER_MAX) { chunks.push(b); later(cb); return true; }
      mode = 'pass';
      unhook();
      if (chunks.length) origWrite.call(this, Buffer.concat(chunks));
      chunks = [];
      return cb ? origWrite.call(this, b, cb) : origWrite.call(this, b);
    }
    return cb ? origWrite.call(this, chunk, ...args, cb) : origWrite.call(this, chunk, ...args);
  };
  res.end = function (chunk, ...args) {
    res.write = origWrite;
    res.end = origEnd;
    unhook();
    if (typeof chunk === 'function') { args = [chunk]; chunk = null; }
    const cb = typeof args[args.length - 1] === 'function' ? args[args.length - 1] : null;
    const b = chunk != null ? toBuffer(chunk) : null;
    if (!mode) mode = whole || (isHTML() && tag) ? 'buffer' : 'pass';
    if (mode === 'stream') {
      const rest = withTag(b ? Buffer.concat([pending, b]) : pending, tag);
      finish(null, html);
      return cb ? origEnd.call(this, rest, cb) : origEnd.call(this, rest);
    }
    if (mode === 'buffer' && b && size + b.length > BUFFER_MAX) {
      if (chunks.length) origWrite.call(this, Buffer.concat(chunks));
      finish(null, isHTML());
      return cb ? origEnd.call(this, b, cb) : origEnd.call(this, b);
    }
    if (mode === 'buffer') {
      if (b) chunks.push(b);
      html = isHTML();
      const body = finish(Buffer.concat(chunks), html);
      return cb ? origEnd.call(this, body, cb) : origEnd.call(this, body);
    }
    finish(null, html || isHTML());
    return origEnd.call(this, chunk, ...args);
  };
}

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
  const [head, tail = ''] = lower.split('::');
  const h = head ? head.split(':') : [];
  const t = lower.includes('::') ? (tail ? tail.split(':') : []) : [];
  const groups = lower.includes('::') ? [...h, ...Array(8 - h.length - t.length).fill('0'), ...t] : h;
  if (groups.length !== 8) return '';
  const first = groups.slice(0, 3).map((g) => parseInt(g, 16).toString(16));
  while (first.length && first[first.length - 1] === '0') first.pop();
  return first.join(':') + '::/48';
}

let holding = 0;

module.exports = { createRanvia, LOADER_VERSION, addressBlock };
Object.defineProperty(module.exports, '_tagResponse', { value: tagResponse });
