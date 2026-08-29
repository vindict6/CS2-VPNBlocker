# CS2-VPNBlocker

A lightweight [CounterStrikeSharp](https://github.com/roflmuffin/CounterStrikeSharp) plugin for CS2 that kicks players connecting from VPN, proxy, or datacenter IP addresses. Useful against spam bots (e.g. the "cs2commends" advertising bots) that join from hosting-provider ranges.

## How it works

- On every client connect, the player's IP is checked against [ip-api.com](https://ip-api.com) — a free, public, no-key lookup service that reports `proxy` (VPN/proxy) and `hosting` (datacenter) flags.
- Results are cached forever (in memory + `configs/plugins/CS2-VPNBlocker/ipcache.json`), so repeat offenders are kicked instantly without another lookup. Connection attempts per IP are counted and persisted too.
- When an IP is blocked, online admins (with the `@css/ban` flag by default) get a short chat notice with the IP and the attempt count.
- On load, the plugin announces in chat that VPNBlocker has been armed.
- Lookups run asynchronously off the game thread; kicks happen on the next server frame. No lists to maintain, no race conditions, and it fails open if the API is unreachable.

## Installation

1. Install [CounterStrikeSharp](https://docs.cssharp.dev/docs/guides/getting-started.html).
2. Download `CS2-VPNBlocker.zip` from the [latest release](../../releases/latest).
3. Extract it into your server's `game/csgo/` directory (it contains `addons/counterstrikesharp/plugins/CS2-VPNBlocker/`).
4. Restart the server or run `css_plugins load CS2-VPNBlocker`.

The plugin is hot-reloadable: `css_plugins reload CS2-VPNBlocker` re-checks everyone already connected.

## Configuration

Generated at `addons/counterstrikesharp/configs/plugins/CS2-VPNBlocker/CS2-VPNBlocker.json` on first load:

| Option | Default | Description |
|---|---|---|
| `block_proxies` | `true` | Kick IPs flagged as VPN/proxy |
| `block_hosting` | `true` | Kick IPs flagged as datacenter/hosting |
| `lookup_timeout_seconds` | `5` | HTTP timeout per lookup |
| `admin_notify_flag` | `@css/ban` | Admin flag that receives block notifications |
| `announce_on_load` | `true` | Announce in chat when the plugin loads |

The IP cache lives at `addons/counterstrikesharp/configs/plugins/CS2-VPNBlocker/ipcache.json` and is never expired — delete the file (or an entry) to force a re-check.

## Notes

- ip-api.com's free tier allows 45 requests/minute; the cache keeps a normal server far below that.
- Legitimate players connecting through a VPN will also be kicked — that's the point, but be aware.

## Building

```
dotnet publish -c Release
```

Releases are built automatically by GitHub Actions on every `v*` tag.
