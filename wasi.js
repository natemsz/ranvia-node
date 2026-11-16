'use strict';
// The few system calls the Ranvia engine (Go, wasip1) makes, done
// here rather than through node:wasi, which is still experimental in
// Node. The engine reads no files, arguments or environment; it needs
// clocks, random bytes and somewhere to write its rare log lines.

const { getRandomValues } = require('node:crypto');

const SUCCESS = 0;
const EBADF = 8;
const ENOSYS = 52;
const ENOTCAPABLE = 76;

function wasiImports(getMemory, log) {
  const view = () => new DataView(getMemory().buffer);
  const bytes = () => new Uint8Array(getMemory().buffer);
  const zeroPair = (a, b) => {
    const v = view();
    v.setUint32(a, 0, true);
    v.setUint32(b, 0, true);
    return SUCCESS;
  };
  return {
    args_sizes_get: zeroPair,
    environ_sizes_get: zeroPair,
    args_get: () => SUCCESS,
    environ_get: () => SUCCESS,
    clock_time_get(id, _precision, out) {
      const ns = id === 0
        ? BigInt(Date.now()) * 1000000n
        : process.hrtime.bigint();
      view().setBigUint64(out, ns, true);
      return SUCCESS;
    },
    random_get(ptr, len) {
      const b = bytes();
      for (let off = 0; off < len; off += 65536) {
        getRandomValues(b.subarray(ptr + off, ptr + Math.min(len, off + 65536)));
      }
      return SUCCESS;
    },
    fd_write(fd, iovs, iovsLen, nwritten) {
      const v = view();
      const b = bytes();
      let total = 0;
      const parts = [];
      for (let i = 0; i < iovsLen; i++) {
        const p = v.getUint32(iovs + i * 8, true);
        const n = v.getUint32(iovs + i * 8 + 4, true);
        parts.push(Buffer.from(b.subarray(p, p + n)));
        total += n;
      }
      if (fd === 1 || fd === 2) {
        const text = Buffer.concat(parts).toString('utf8').trimEnd();
        if (text) log('ranvia engine: ' + text);
      }
      v.setUint32(nwritten, total, true);
      return fd === 1 || fd === 2 ? SUCCESS : EBADF;
    },
    fd_read: () => EBADF,
    fd_close: () => EBADF,
    fd_fdstat_get(fd, out) {
      if (fd > 2) return EBADF;
      const v = view();
      v.setUint8(out, 2); // character device
      v.setUint16(out + 2, 0, true);
      v.setBigUint64(out + 8, 0xffffffffffffffffn, true);
      v.setBigUint64(out + 16, 0xffffffffffffffffn, true);
      return SUCCESS;
    },
    fd_fdstat_set_flags: () => SUCCESS,
    fd_prestat_get: () => EBADF, // no preopened directories
    fd_prestat_dir_name: () => EBADF,
    path_open: () => ENOTCAPABLE,
    path_filestat_get: () => ENOTCAPABLE,
    poll_oneoff(inPtr, outPtr, nsubs, nevents) {
      // The engine never waits on anything real: report every
      // subscription as fired.
      const v = view();
      for (let i = 0; i < nsubs; i++) {
        const sub = inPtr + i * 48;
        const ev = outPtr + i * 32;
        v.setBigUint64(ev, v.getBigUint64(sub, true), true); // userdata
        v.setUint16(ev + 8, SUCCESS, true);
        v.setUint8(ev + 10, v.getUint8(sub + 8)); // event type
      }
      v.setUint32(nevents, nsubs, true);
      return SUCCESS;
    },
    sched_yield: () => SUCCESS,
    proc_exit(code) {
      throw new Error('ranvia: the engine exited (' + code + ')');
    },
    // Anything else the engine might ask for is refused.
    __proto__: new Proxy({}, { get: () => () => ENOSYS }),
  };
}

module.exports = { wasiImports };
