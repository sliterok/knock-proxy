# knock-proxy

TCP gate in front of an upstream proxy (e.g. Dante). Connections are allowed by either:
- a temporary IP allow-list unlocked via HTTP (`/unlock`), and/or
- GeoIP country allow-list (local lookup via `geoip-lite`).

## Usage

Install deps:
- `pnpm install`

Build + run:
- `pnpm run build`
- `pnpm start`

Unlock (when enabled):
- `curl -X POST "http://127.0.0.1:3000/unlock?ttl=600"`

## Access modes

Set `ACCESS_MODE`:
- `allowlist` (default): TCP gate requires the IP to be unlocked via `/unlock`.
- `geoip`: TCP gate allows by GeoIP only; `/unlock` is disabled.
- `both`: TCP gate requires *both* an unlocked IP and an allowed GeoIP country. `/unlock` will only work from allowed countries.

For `geoip`/`both`, set `ALLOW_COUNTRIES` (ISO-3166-1 alpha-2, comma/space separated), or `*` to allow all:
- `ALLOW_COUNTRIES=US,CA`
- `ALLOW_COUNTRIES=*`

## Persistent allow-list (ring buffer per subnet)

When `ACCESS_MODE` is `allowlist` or `both`, unlocked IPs are persisted to disk:
- `ALLOWLIST_PATH` (default `data/allowList.json`)
- max `ALLOWLIST_MAX_PER_SUBNET` entries per subnet (default `100`)
- subnets idle for `ALLOWLIST_SUBNET_STALE_SEC` seconds are dropped (default `604800` / 7 days)

Subnets are bucketed as IPv4 `/24` and IPv6 `/64`. Entries behave like a ring buffer (recently used entries are kept, old ones evicted when full).

`data/` is `.gitignore`d; make sure the process can write to it.

## Bind addresses

By default:
- HTTP unlock server binds to `127.0.0.1` (intended to sit behind a reverse proxy): `HTTP_BIND_HOST`
- TCP gate binds to `0.0.0.0` (public): `TCP_BIND_HOST`

`BIND_HOST` is still supported as a legacy fallback for both.

## Environment variables

- `PROXY_PUBLIC_PORT` (default `1080`)
- `TCP_BIND_HOST` (default `0.0.0.0`)
- `DANTE_HOST` (default `127.0.0.1`)
- `DANTE_PORT` (default `1081`)
- `HTTP_PORT` (default `3000`)
- `HTTP_BIND_HOST` (default `127.0.0.1`)
- `TRUST_PROXY` (default `true`) – respects `X-Forwarded-For` for `/unlock`
- `DEFAULT_TTL_SEC` (default `1200`) – default unlock TTL (bounded to `10s..7d`)
- `ACCESS_MODE` (default `allowlist`)
- `ALLOW_COUNTRIES` (required for `geoip`/`both`)
- `ALLOWLIST_PATH` (default `data/allowList.json`)
- `ALLOWLIST_MAX_PER_SUBNET` (default `100`)
- `ALLOWLIST_SUBNET_STALE_SEC` (default `604800`)

