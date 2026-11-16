import type { IncomingMessage, ServerResponse } from 'node:http';

export interface RanviaConfig {
  /** Your site key from the Ranvia dashboard (rnv_...). */
  key: string;
  /** The Ranvia service; defaults to https://ranvia.io. */
  serviceUrl?: string;
  /** Where the encrypted engine is cached between starts; defaults to ~/.cache/ranvia. */
  cacheDir?: string;
  /** The visitor's network (an ASN like "as7922", or a country code), when your edge tells you. */
  network?: (req: IncomingMessage) => string | undefined;
  /** A visitor you have verified as signed in: no page budget, but by default a human-pace limit. Runs only for requests with cookies. */
  signedIn?: (req: IncomingMessage) => boolean | Promise<boolean>;
  /**
   * A search crawler you have verified; never counted. Defaults to the built-in
   * check: a request naming Googlebot, Bingbot, Applebot or YandexBot is verified
   * by reverse and forward DNS of its address. Return false to turn it off.
   */
  verifiedCrawler?: (req: IncomingMessage) => boolean | Promise<boolean>;
  /**
   * The visitor's address. Defaults to the connection's address, or the last
   * X-Forwarded-For entry when the connection comes from this machine. Behind a
   * CDN, return the address it passes on (for Cloudflare, CF-Connecting-IP).
   */
  clientIp?: (req: IncomingMessage) => string;
  /**
   * Log every request Ranvia refuses, checks or rate-limits through `log`:
   * method, path, User-Agent and the reason. The log stays on your server.
   */
  logRefusals?: boolean;
  /** An optional JSON file of your own rule overrides. */
  rulesFile?: string;
  /** Receives one log line at a time. */
  log?: (line: string) => void;
  /** Public keys for rule bundles, for a service you run yourself. */
  serviceKeys?: Record<string, string>;
}

export interface Ranvia {
  /** Express / Connect middleware. */
  middleware(req: IncomingMessage, res: ServerResponse, next: () => void): void;
  /** Guards a plain node:http request handler. */
  wrap(handler: (req: IncomingMessage, res: ServerResponse) => void): (req: IncomingMessage, res: ServerResponse) => void;
  /** Resolves once the engine is running. Requests pass until then. */
  ready(): Promise<void>;
  isReady(): boolean;
  /** Stops background work and sends a last usage report. */
  close(): Promise<void>;
}

export function createRanvia(config: RanviaConfig): Ranvia;
export const LOADER_VERSION: string;
