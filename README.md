# CS2-VPNBlocker

A lightweight [CounterStrikeSharp](https://github.com/roflmuffin/CounterStrikeSharp) plugin for CS2 that kicks players connecting from VPN, proxy, or datacenter IP addresses. Useful against spam bots (e.g. the "cs2commends" advertising bots) that join from hosting-provider ranges.

## How it works

- On every client connect, the player's IP is checked against [ip-api.com](https://ip-api.com) — a free, public, no-key lookup service that reports `proxy` (VPN/proxy) and `hosting` (datacenter) flags.
- Results are cached in memory and persisted to `ipcache.json` next to the plugin, so repeat offenders are kicked instantly without another lookup.
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
| `blocked_cache_hours` | `168` | How long a blocked verdict is cached (7 days) |
| `clean_cache_hours` | `24` | How long a clean verdict is cached |
| `lookup_timeout_seconds` | `5` | HTTP timeout per lookup |

## Notes

- ip-api.com's free tier allows 45 requests/minute; the cache keeps a normal server far below that.
- Legitimate players connecting through a VPN will also be kicked — that's the point, but be aware.

## Building

```
dotnet publish -c Release
```

Releases are built automatically by GitHub Actions on every `v*` tag.
