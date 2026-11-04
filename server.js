// Standalone MausBot relay.
//
// This is the same long-poll tunnel the Mac agent already speaks, but with no
// business app in the process: it holds nothing but the tunnel, so if it wedges
// the only thing that breaks is the phone's remote access. Nothing else hangs
// off it.
//
//   phone --https--> this service --(long-poll)--> Mac agent --> 127.0.0.1:8799
//
// Deploy anywhere that keeps a Node process alive and accepts long-lived HTTP
// requests (Render free web service is fine: the agent polls every 5s, so the
// instance never goes idle).
'use strict';

const http = require('node:http');
const crypto = require('node:crypto');
const { createRelay } = require('./mb-relay.js');

const port = Number(process.env.PORT) || 8080;
// Shared secret between this service and the Mac agent. If it is unset the
// tunnel is open to anyone who finds the hostname, so generate one instead.
const token = process.env.MB_TOKEN || '';
if (!token) {
  console.error('MB_TOKEN is not set; refusing to start an open tunnel.');
  process.exit(1);
}

// Everything that is not a tunnel path lands here. There is no business app in
// this process, so say so plainly instead of leaving the request hanging.
const server = http.createServer((req, res) => {
  const body = 'mausbot relay: this host only carries the phone tunnel\n';
  res.writeHead(404, {
    'content-type': 'text/plain; charset=utf-8',
    'content-length': Buffer.byteLength(body),
  });
  res.end(body);
});

createRelay({ token, prefix: '/__mb', root: true }).install(server);

server.listen(port, '0.0.0.0', () => {
  console.log(`mausbot relay listening on 0.0.0.0:${port}`);
});

// A relay must never take its host down with it: log and keep serving.
process.on('uncaughtException', (err) => {
  console.error('[relay] uncaught', err && err.stack ? err.stack : err);
});
process.on('unhandledRejection', (err) => {
  console.error('[relay] unhandled rejection', err);
});

module.exports = { server, tokenHash: crypto.createHash('sha256').update(token).digest('hex').slice(0, 8) };
