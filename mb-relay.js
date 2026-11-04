// MausBot relay over plain HTTPS requests (long-poll transport).
//
// Why not WebSocket: the public edge in front of this app terminates TLS,
// demotes Upgrade requests to plain requests and never answers a 101, so a
// WebSocket (or a raw TCP pipe) cannot cross it. Plain requests do cross.
//
//   phone --https--> edge --> this module --> (long-poll) --> agent --> 127.0.0.1:8810
//
// The agent polls for outbound messages and posts inbound ones; each phone
// connection is a stream of open/data/close messages, so the companion's SSE
// and ordinary HTTP both survive. WebSocket upgrades from the phone cannot.
'use strict';

const crypto = require('node:crypto');

const DEFAULT_PREFIX = '/__mb';
const HOLD_MS = 5000;           // short on purpose: an idle poll held longer gets silently dropped by the edge
const MSG_CAP = 6000;           // outbound messages kept for replay
const OPEN_TIMEOUT_MS = 12000;
const MAX_BODY = 64 * 1024 * 1024;

function timingSafeEqualStr(a, b) {
  const ab = Buffer.from(String(a || ''));
  const bb = Buffer.from(String(b || ''));
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

// The phone app only accepts a bare HTTPS origin as a host address — it refuses
// any address with a path ("That address doesn't look right"). So MausBot has to
// answer at the domain root, next to the host app that shares this domain.
//
// The phone is a client of the Mac's own server (the harness on 127.0.0.1:8799),
// not of the LAN companion sidecar: it pairs at POST /api/auth/pair and then
// sends that session as a bearer token. The harness enforces that itself as soon
// as a request is marked as proxied, so every /api path below can be tunnelled
// without this process having to police it.
//
// The only rule here is which /api families belong to the host app (jd-content-
// collab) and must keep answering locally. Nothing in that list overlaps the
// harness's routes.
const HOST_API_SEGMENTS = new Set([
  'action',
  'compose-insight-bfs',
  'content-insights',
  'corporate-worker',
  'cover-report',
  'generate',
  'generate-image',
  'history',
  'hotspot-board',
  'hotspot-refresh',
  'insight-hot',
  'insights-explore',
  'insights-live',
  'login',
  'logout',
  'parse-plan-link',
  'pipeline-feed',
  'post-audit-results',
  'project-post-audit',
  'review',
  'rival',
  'rival-focus',
  'sentiment-report-file',
  'service-insights',
  'state',
  'tianshu-report',
  'today-focus',
  'unified-insights',
  'uploads',
]);

function createRelay(options) {
  const token = options.token || '';
  const prefix = options.prefix || DEFAULT_PREFIX;
  const holdMs = options.holdMs || HOLD_MS;
  const rootOrigin = options.root === true;
  // The descriptor the phone reads before pairing, plus everything under /api
  // except the host app's own families.
  const isCompanionPath = (pathname) => {
    if (pathname === '/.well-known/openmausbot' || pathname.startsWith('/.well-known/openmausbot/')) return true;
    if (!pathname.startsWith('/api/')) return false;
    const segment = pathname.slice('/api/'.length).split('/')[0];
    return !HOST_API_SEGMENTS.has(segment);
  };

  // A redeploy restarts this process and both sequence counters start over. The
  // epoch tells the agent so it can reset instead of waiting for sequence
  // numbers it will never see again.
  const epoch = crypto.randomBytes(6).toString('hex');
  const outbox = [];            // [{seq, msg}] server -> agent
  let outSeq = 0;
  const pollers = new Set();
  const conns = new Map();      // id -> { socket, opened, timer }
  let connSeq = 0;
  let inExpected = 1;           // next batch seq expected from agent
  let agentSeen = 0;
  // No container stdout on this host, so the last few requests are kept in
  // memory and read back through /__mb/recent while pairing is being sorted out.
  const recent = [];
  function note(line) {
    recent.push({ at: new Date().toISOString(), line });
    if (recent.length > 200) recent.splice(0, recent.length - 200);
  }

  // Wake the phone's idle event stream often enough that neither the edge nor
  // the carrier's NAT can quietly forget the flow.
  const keepalive = setInterval(() => {
    const now = Date.now();
    for (const [id, conn] of conns) {
      if (!conn.sse || !conn.said || conn.socket.destroyed) continue;
      // 2.5s, not 20s: some edges (Render's included) reap a flow that has been
      // quiet for ten-odd seconds, and a reaped flow looks perfectly open to
      // both ends while every later byte vanishes.
      if (now - (conn.lastWrite || 0) < 2500) continue;
      try {
        conn.socket.write(': mb-keepalive\n\n');
        conn.lastWrite = now;
      } catch {
        conns.delete(id);
        try { conn.socket.destroy(); } catch { }
      }
    }
  }, 2500);
  if (keepalive.unref) keepalive.unref();

  // ---------------------------------------------------------------- outbound
  function push(msg) {
    outSeq += 1;
    outbox.push({ seq: outSeq, msg });
    if (outbox.length > MSG_CAP) outbox.splice(0, outbox.length - MSG_CAP);
    wakePollers();
  }

  function wakePollers() {
    for (const p of Array.from(pollers)) flushPoller(p);
  }

  function flushPoller(p) {
    if (p.closed) return;
    const msgs = [];
    for (const entry of outbox) {
      if (entry.seq >= p.since) msgs.push(entry.msg);
    }
    if (!msgs.length) return;
    p.closed = true;
    pollers.delete(p);
    clearTimeout(p.timer);
    p.done(msgs);
  }

  function nextSeqFor(since) {
    return outSeq + 1 > since ? outSeq + 1 : since;
  }

  // ----------------------------------------------------------------- inbound
  function applyFromAgent(batchSeq, msgs) {
    if (batchSeq < inExpected) return { ok: true, dup: true, expected: inExpected };
    if (batchSeq > inExpected) return { ok: false, expected: inExpected };
    for (const m of msgs) routeFromAgent(m);
    inExpected = batchSeq + 1;
    return { ok: true, expected: inExpected };
  }

  function routeFromAgent(m) {
    if (process.env.MB_DEBUG && m) console.log('[relay] from agent', m.t, m.id);
    if (!m || typeof m !== 'object') return;
    const conn = conns.get(m.id);
    if (!conn) return;
    if (m.t === 'opened') {
      conn.opened = true;
      clearTimeout(conn.timer);
      return;
    }
    if (m.t === 'data') {
      const buf = Buffer.from(String(m.d || ''), 'base64');
      if (!conn.said) {
        conn.said = true;
        const lead = buf.toString('latin1', 0, Math.min(buf.length, 4096));
        const line = buf.toString('latin1', 0, Math.min(buf.length, 80)).split('\r\n')[0];
        // The event stream is the one connection that can stay quiet for
        // minutes. If the edge silently drops an idle flow, both ends keep a
        // socket that looks open while every new message vanishes — which is
        // exactly how a reply goes missing on the phone. A comment line is
        // ignored by the client and keeps the flow demonstrably alive.
        conn.sse = /content-type:\s*text\/event-stream/i.test(lead);
        note(`<- #${m.id} ${line}`);
      }
      conn.lastWrite = Date.now();
      if (!conn.socket.destroyed) {
        try { conn.socket.write(buf); } catch { }
      }
      return;
    }
    if (m.t === 'close') {
      conns.delete(m.id);
      try { conn.socket.end(); } catch { }
      return;
    }
    if (m.t === 'fail') {
      conns.delete(m.id);
      try {
        conn.socket.end(
          'HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\n' +
          'Content-Length: 24\r\nConnection: close\r\n\r\nagent could not reach host'
        );
      } catch { }
    }
  }

  // ------------------------------------------------------------------ routes
  function readBody(req) {
    return new Promise((resolve, reject) => {
      const chunks = [];
      let size = 0;
      req.on('data', (c) => {
        size += c.length;
        if (size > MAX_BODY) { reject(new Error('body too large')); req.destroy(); return; }
        chunks.push(c);
      });
      req.on('end', () => resolve(Buffer.concat(chunks)));
      req.on('error', reject);
    });
  }

  function json(res, status, obj) {
    const body = JSON.stringify(obj);
    res.writeHead(status, {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'content-length': Buffer.byteLength(body),
    });
    res.end(body);
  }

  function authed(url) {
    if (!token) return true;
    const given = url.searchParams.get('token') || '';
    return timingSafeEqualStr(given, token);
  }

  function handlePoll(req, res, url) {
    if (!authed(url)) { json(res, 403, { ok: false, error: 'forbidden' }); return; }
    agentSeen = Date.now();
    const since = Number(url.searchParams.get('since') || '0') || 0;
    // The agent is waiting for messages this process never had: answer at once
    // with the reset, so it stops waiting and starts over from the beginning.
    if (since > outSeq + 1) {
      json(res, 200, { ok: true, msgs: [], next: outSeq + 1, reset: true, epoch });
      return;
    }
    const p = { since, done: null, timer: null, closed: false };
    p.done = (msgs) => {
      json(res, 200, { ok: true, msgs, next: nextSeqFor(since), epoch });
    };
    // Anything already pending goes out at once.
    const immediate = outbox.filter((e) => e.seq >= since);
    if (immediate.length) { p.done(immediate.map((e) => e.msg)); return; }
    pollers.add(p);
    p.timer = setTimeout(() => {
      if (p.closed) return;
      p.closed = true;
      pollers.delete(p);
      json(res, 200, { ok: true, msgs: [], next: nextSeqFor(since), epoch });
    }, holdMs);
    const end = () => {
      if (p.closed) return;
      p.closed = true;
      pollers.delete(p);
      clearTimeout(p.timer);
    };
    res.on('close', end);
    req.socket.on('close', end);
  }

  async function handleSend(req, res, url) {
    if (!authed(url)) { json(res, 403, { ok: false, error: 'forbidden' }); return; }
    agentSeen = Date.now();
    let payload;
    try {
      payload = JSON.parse((await readBody(req)).toString('utf8') || '{}');
    } catch {
      json(res, 400, { ok: false, error: 'bad json' });
      return;
    }
    const seq = Number(payload.seq || 0);
    const msgs = Array.isArray(payload.msgs) ? payload.msgs : [];
    const out = applyFromAgent(seq, msgs);
    json(res, 200, { ...out, epoch });
  }

  function handleTunnel(req, res, url, targetPath) {
    const dbg = (m) => { if (process.env.MB_DEBUG) console.log('[relay]', m); };
    let target = targetPath;
    if (!target) {
      const rest = req.url.slice(prefix.length + 2); // strip '/__mb/t'
      target = rest && rest.startsWith('/') ? rest : '/' + (rest || '');
    }
    if (!agentSeen || Date.now() - agentSeen > 40000) {
      const body = 'MausBot 机器端离线，请稍后重试';
      res.writeHead(503, {
        'content-type': 'text/plain; charset=utf-8',
        'content-length': Buffer.byteLength(body),
        connection: 'close',
      });
      res.end(body);
      return;
    }

    const id = ++connSeq;
    // Node hands us the decoded body, so a chunked request must be re-framed on
    // the way out (the forwarded head still says chunked) and an Expect:
    // 100-continue must not travel, since this side already answered it.
    const rechunk = String(req.headers['transfer-encoding'] || '').toLowerCase().includes('chunked');
    const frame = (chunk) => rechunk
      ? Buffer.concat([Buffer.from(chunk.length.toString(16) + '\r\n', 'latin1'), chunk, Buffer.from('\r\n', 'latin1')])
      : chunk;
    const headers = [];
    // What the edge knows about the caller; a missing one still has to be
    // forwarded, because "came through a proxy" is exactly what makes the
    // harness demand a paired device instead of trusting loopback.
    const clientIp = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || '198.18.0.1';
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      const name = req.rawHeaders[i];
      const value = req.rawHeaders[i + 1];
      const lower = name.toLowerCase();
      if (lower === 'connection' || lower === 'keep-alive' || lower === 'upgrade' || lower === 'expect') continue;
      if (lower === 'x-forwarded-for' || lower === 'x-forwarded-proto' || lower === 'x-forwarded-host') continue;
      headers.push(`${name}: ${value}`);
    }
    headers.push(`X-Forwarded-For: ${clientIp}`);
    headers.push('X-Forwarded-Proto: https');
    if (req.headers.host) headers.push(`X-Forwarded-Host: ${req.headers.host}`);
    headers.push('Connection: close');
    const head = `${req.method} ${target} HTTP/1.1\r\n${headers.join('\r\n')}\r\n\r\n`;

    const entry = { socket: req.socket, opened: false, timer: null, lastWrite: Date.now() };
    conns.set(id, entry);
    entry.timer = setTimeout(() => {
      if (!entry.opened) {
        conns.delete(id);
        // Tell the agent to let go of the upstream socket. Without this the
        // Mac side keeps streaming a response nobody is waiting for, the reply
        // queue never drains, and every later request dies behind it.
        push({ t: 'close', id });
        try {
          req.socket.end('HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');
        } catch { }
      }
    }, OPEN_TIMEOUT_MS);

    dbg(`tunnel open id=${id} ${req.method} ${target}`);
    if (!targetPath) note(`-> #${id} ${req.method} ${target}`);
    push({ t: 'open', id, head: Buffer.from(head).toString('base64') });

    req.on('data', (chunk) => {
      push({ t: 'data', id, d: frame(chunk).toString('base64') });
    });
    req.on('end', () => {
      if (rechunk) push({ t: 'data', id, d: Buffer.from('0\r\n\r\n', 'latin1').toString('base64') });
    });
    const finish = () => {
      clearTimeout(entry.timer);
      if (conns.delete(id)) push({ t: 'close', id });
    };
    res.on('close', finish);
    req.socket.on('close', finish);
    req.on('error', finish);
    // Never touch res.write/res.end: the companion's raw bytes go straight to
    // the socket so status line, headers and body arrive exactly as written.
  }

  function install(server) {
    const existing = server.listeners('request');
    server.removeAllListeners('request');
    server.on('request', (req, res) => {
      const pathname = String(req.url || '').split('?')[0];
      // Every request the phone makes is worth one line while pairing is being
      // sorted out: the user agent names the app, and the route says what
      // answered it.
      if (!pathname.startsWith(prefix)) {
        note(`${req.method} ${req.url} ua="${req.headers['user-agent'] || ''}" -> ${rootOrigin && isCompanionPath(pathname) ? 'companion' : 'host'}`);
      }
      if (!pathname.startsWith(prefix)) {
        // Root-origin mode: the phone addresses this domain with no path, so the
        // companion's own API families are tunneled straight through and every
        // other request stays with the host app.
        if (rootOrigin && isCompanionPath(pathname)) {
          handleTunnel(req, res, null, req.url);
          return;
        }
        for (const listener of existing) listener.call(server, req, res);
        return;
      }
      let url;
      try { url = new URL(req.url, 'http://relay.invalid'); } catch { url = new URL('http://relay.invalid/'); }
      if (pathname === `${prefix}/ping`) {
        json(res, 200, {
          ok: true,
          service: 'mausbot-relay',
          transport: 'long-poll',
          epoch,
          agentOnline: Boolean(agentSeen && Date.now() - agentSeen < 40000),
          heldPolls: pollers.size,
          conns: conns.size,
          outSeq,
          inExpected,
        });
        return;
      }
      if (pathname === `${prefix}/recent`) {
        if (!authed(url)) { json(res, 403, { ok: false, error: 'forbidden' }); return; }
        json(res, 200, { ok: true, epoch, recent });
        return;
      }
      if (pathname === `${prefix}/agent/poll`) {
        if (req.method !== 'GET') { json(res, 405, { ok: false }); return; }
        handlePoll(req, res, url);
        return;
      }
      if (pathname === `${prefix}/agent/send`) {
        if (req.method !== 'POST') { json(res, 405, { ok: false }); return; }
        handleSend(req, res, url).catch(() => { try { json(res, 500, { ok: false }); } catch { } });
        return;
      }
      if (pathname === `${prefix}/selftest/stream`) {
        if (!authed(url)) { json(res, 403, { ok: false }); return; }
        res.writeHead(200, {
          'content-type': 'text/event-stream',
          'cache-control': 'no-store',
          connection: 'close',
        });
        let n = 0;
        const timer = setInterval(() => {
          n += 1;
          try { res.write(`data: {"n":${n},"t":${Date.now()}}\n\n`); } catch { }
          if (n >= 5) { clearInterval(timer); try { res.end(); } catch { } }
        }, 400);
        res.on('close', () => clearInterval(timer));
        return;
      }
      if (pathname === `${prefix}/t` || pathname.startsWith(`${prefix}/t/`)) {
        handleTunnel(req, res, url);
        return;
      }
      json(res, 404, { ok: false, error: 'not found' });
    });
    return relay;
  }

  const relay = {
    install,
    stats: () => ({ outSeq, inExpected, conns: conns.size, pollers: pollers.size, agentSeen }),
  };
  return relay;
}

module.exports = { createRelay };
