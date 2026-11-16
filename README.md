# Ranvia for Node.js

Bot and AI scraper protection that runs on your own server.
[ranvia.io](https://ranvia.io)

> **Early access.** The Ranvia service is opening soon. Until your site
> has a key, there is nothing to install.

```js
const { createRanvia } = require('ranvia');

const ranvia = createRanvia({ key: process.env.RANVIA_KEY });

app.use(ranvia.middleware);                 // Express, Connect
// or
http.createServer(ranvia.wrap(handler));    // plain node:http
```

## How it works

- **Your traffic never leaves your server.** Every decision is made
  locally, in about a tenth of a millisecond.
- **What the service sends and receives:** it sends your site's rules
  and what other sites learned; your site sends back counts and, for
  requests it turned away, keyed hashes of the browser's headers and
  family with the network's ASN. Visitor addresses, cookies, URLs and
  page content are never sent. See https://ranvia.io/privacy.
- **This package is a loader.** On first start it downloads the Ranvia
  engine for your site key, keeps it on disk encrypted for your site,
  and runs it in memory as WebAssembly.
- **Ranvia never takes your site down.** If the engine can't run (first
  start with ranvia.io out of reach, a revoked key), every request
  passes and the reason is logged.
- **What visitors see:** scrapers are refused. Clients that behave like
  scrapers get a short browser check, which a real browser passes in
  about a second with no clicks.

## Options

| Option | What it does |
|---|---|
| `key` | Your site key from the Ranvia dashboard. |
| `network(req)` | The visitor's network, if your edge provides it: an ASN (`as7922`) or a country code. |
| `signedIn(req)` | Return `true` for a visitor you've verified as signed in. They skip the page budget; by default they're asked for proof only past a pace no person browses at (about two pages a second), which you can turn off per site. |
| `verifiedCrawler(req)` | Search crawlers are checked for you: a request naming Googlebot, Bingbot, Applebot or YandexBot is verified by reverse and forward DNS, and verified crawlers are never counted. Pass your own function to replace the check, or `() => false` to turn it off. |
| `clientIp(req)` | The visitor's address. Defaults to the connection's address, or the last `X-Forwarded-For` entry when the connection comes from this machine. Behind a CDN, return the address it passes on (`CF-Connecting-IP` for Cloudflare). |
| `cacheDir` | Where the encrypted engine is kept. Defaults to `~/.cache/ranvia`. |
| `rulesFile` | A JSON file of your own rule overrides. |
| `logRefusals` | `true` logs each request Ranvia refuses, checks or rate-limits through `log`: method, path, User-Agent and why. The log stays on your server. |
| `log(line)` | Receives log lines. |

Requires Node.js 20 or later.

## License

Use of this package and of the engine it downloads is governed by the
Ranvia terms of service at https://ranvia.io. Copyright Synap6. All
rights reserved.
