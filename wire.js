'use strict';
// The binary form the engine takes and returns on every request (the
// engine's wire.go): little-endian, strings as a u32 length and bytes.

function encodeRequest(req) {
  const strs = [req.method, req.uri, req.host, req.network || '', req.body || ''];
  const lines = [];
  for (const [k, v] of Object.entries(req.header)) {
    if (v === undefined) continue;
    for (const one of Array.isArray(v) ? v : [String(v)]) lines.push([k, one]);
  }
  const n = Math.min(lines.length, 0xffff);
  const bufs = strs.map((s) => Buffer.from(s, 'utf8'));
  const pairs = lines.slice(0, n).map(([k, v]) => [Buffer.from(k, 'utf8'), Buffer.from(v, 'utf8')]);
  const proto = Buffer.from(req.proto || '', 'utf8');
  const bind = Buffer.from(req.bind || '', 'utf8');
  const addr = Buffer.from(req.addr || '', 'utf8');
  let size = 2 + 2 + 4 + proto.length + 4 + bind.length + 4 + addr.length;
  for (const b of bufs) size += 4 + b.length;
  for (const [k, v] of pairs) size += 8 + k.length + v.length;
  const out = Buffer.allocUnsafe(size);
  let o = 0;
  out[o++] = 1;
  out[o++] = (req.signedIn ? 1 : 0) | (req.crawler ? 2 : 0) | (req.tls ? 4 : 0);
  const put = (b) => { out.writeUInt32LE(b.length, o); o += 4; b.copy(out, o); o += b.length; };
  for (const b of bufs) put(b);
  out.writeUInt16LE(n, o); o += 2;
  for (const [k, v] of pairs) { put(k); put(v); }
  put(proto); // added after the first engines, which stop before it
  put(bind); // likewise, after proto
  put(addr); // likewise, after bind
  return out;
}

function decodeDecision(buf) {
  let o = 0;
  const need = (n) => { if (o + n > buf.length) throw new Error('ranvia: malformed answer from the engine'); };
  const str = () => {
    need(4);
    const n = buf.readUInt32LE(o); o += 4;
    need(n);
    const s = buf.subarray(o, o + n); o += n;
    return s;
  };
  need(13);
  const d = { serve: (buf[0] & 1) === 1, confirm: (buf[0] & 2) === 2, sniff: buf.readBigUInt64LE(1), status: buf.readUInt16LE(9), header: [] };
  const lines = buf.readUInt16LE(11); o = 13;
  for (let i = 0; i < lines; i++) d.header.push([str().toString('utf8'), str().toString('utf8')]);
  d.body = Buffer.from(str());
  // Engines from before the reason field end here.
  d.reason = o < buf.length ? str().toString('utf8') : '';
  // Engines before 0.4.1 end here: the tag a served page or robots.txt
  // carries (prove) comes last.
  d.prove = o < buf.length ? str().toString('utf8') : '';
  return d;
}

module.exports = { encodeRequest, decodeDecision };
