# mausbot-relay

A standalone long-poll tunnel between the OpenMausBot phone app and a Mac.
It carries nothing but the tunnel, so it cannot affect any other service.

- `GET /__mb/ping` — health
- `GET /__mb/agent/poll` — Mac agent long-poll
- `POST /__mb/agent/send` — Mac agent replies
- `/__mb/t/*` — phone requests proxied to the Mac

Needs `MB_TOKEN` in the environment (shared secret with the Mac agent);
the service refuses to start without it.
