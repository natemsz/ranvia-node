'use strict';
// Driven by the service's end-to-end test (service/internal/e2e): a
// node:http site behind the loader, asked the same things as the Go
// loader's test. Prints one JSON line of results.
const http = require('node:http');
const { createRanvia } = require('..');

const chrome = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36';

function get(port, path, headers) {
  return new Promise((resolve, reject) => {
    const req = http.request({ port, path, headers }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }));
    });
    req.on('error', reject);
    req.end();
  });
}

const browser = (extra) => Object.assign({
  'User-Agent': chrome, Accept: 'text/html', 'Accept-Language': 'en',
  'Sec-Ch-Ua': '"Chromium";v="153"', 'Sec-Fetch-Site': 'same-origin',
  'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-Dest': 'document',
}, extra);

(async () => {
  const logs = [];
  const ranvia = createRanvia({
    key: process.env.RANVIA_KEY, serviceUrl: process.env.RANVIA_URL, cacheDir: process.env.RANVIA_CACHE,
    serviceKeys: JSON.parse(process.env.RANVIA_KEYS), rulesFile: process.env.RANVIA_RULES,
    log: (l) => logs.push(l),
  });
  const server = http.createServer(ranvia.wrap((req, res) => {
    res.setHeader('Content-Type', 'text/html');
    res.end('<p>the site');
  }));
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  const out = { logs };
  await Promise.race([ranvia.ready(), new Promise((r) => setTimeout(r, 20000))]);
  out.ready = ranvia.isReady();

  out.blocked = (await get(port, '/market/', browser({ 'User-Agent': 'SecretBot/1.0' }))).status;
  let last;
  for (let i = 0; i < 25; i++) last = await get(port, '/market/', browser({ 'Accept-Language': 'de' }));
  out.atBudget = last.status;
  out.checkPage = last.body.includes('id="guard"');
  const other = await get(port, '/market/', browser({ 'Accept-Language': 'fr' }));
  out.other = [other.status, other.body];

  const asset = await get(port, '/static/site.css', browser({ 'Accept-Language': 'pt', 'Sec-Fetch-Dest': 'style', 'Sec-Fetch-Mode': 'no-cors' }));
  const cookie = String((asset.headers['set-cookie'] || [''])[0]).split(';')[0];
  out.passCookie = cookie.startsWith('es_assets=');
  const n = 2000;
  const t0 = process.hrtime.bigint();
  let okCount = 0;
  for (let i = 0; i < n; i++) {
    const r = await get(port, '/market/', browser({ 'Accept-Language': 'pt', Cookie: cookie }));
    if (r.status === 200) okCount++;
  }
  out.passHolderOK = okCount;
  out.usPerRequest = Number(process.hrtime.bigint() - t0) / n / 1000;

  await ranvia.close();
  server.close();
  console.log(JSON.stringify(out));
})().catch((err) => { console.log(JSON.stringify({ error: String(err && err.stack || err) })); process.exit(1); });
