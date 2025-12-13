# knock-proxy

TCP gate in front of an upstream proxy (e.g. Dante).

## How access works

Clients are allowed if **either**:
- their IP was unlocked via `POST /unlock` (persistent allow-list), or
- their GeoIP country is in `ALLOW_COUNTRIES` (when GeoIP is enabled).

## Usage

- `pnpm install`
- `pnpm run build`
- `pnpm start`

Unlock your current IP:
- `curl -X POST "http://127.0.0.1:3000/unlock"`

## GeoIP

Enable GeoIP by setting `ALLOW_COUNTRIES` (ISO-3166-1 alpha-2, comma/space separated), or `*` to allow all:
- `ALLOW_COUNTRIES=US,CA`
- `ALLOW_COUNTRIES=*`

`ACCESS_MODE`:
- `allowlist` (default when `ALLOW_COUNTRIES` is empty): allow-list only.
- `geoip` or `both` (default when `ALLOW_COUNTRIES` is set): GeoIP **or** allow-list.

## Persistent allow-list (ring buffer per subnet)

Unlocked IPs are stored on disk and survive restarts:
- `ALLOWLIST_PATH` (default `data/allowList.json`)
- max `ALLOWLIST_MAX_PER_SUBNET` entries per subnet (default `100`)
- subnets idle for `ALLOWLIST_SUBNET_STALE_SEC` seconds are dropped (default `604800` / 7 days)

Subnets are bucketed as IPv4 `/24` and IPv6 `/64`. Entries behave like a ring buffer (recently used entries are kept, old ones evicted when full).

`data/` is `.gitignore`d; make sure the process can write to it.

## Bind addresses

By default:
- HTTP unlock server binds to `127.0.0.1` (intended to sit behind a reverse proxy): `HTTP_BIND_HOST`
- TCP gate binds to `0.0.0.0` (public): `TCP_BIND_HOST`

## Environment variables

- `PROXY_PUBLIC_PORT` (default `1080`)
- `TCP_BIND_HOST` (default `0.0.0.0`)
- `DANTE_HOST` (default `127.0.0.1`)
- `DANTE_PORT` (default `1081`)
- `HTTP_PORT` (default `3000`)
- `HTTP_BIND_HOST` (default `127.0.0.1`)
- `TRUST_PROXY` (default `true`) – respects `X-Forwarded-For` for `/unlock`
- `ACCESS_MODE` (default depends on `ALLOW_COUNTRIES`)
- `ALLOW_COUNTRIES` (enables GeoIP when set)
- `ALLOWLIST_PATH` (default `data/allowList.json`)
- `ALLOWLIST_MAX_PER_SUBNET` (default `100`)
- `ALLOWLIST_SUBNET_STALE_SEC` (default `604800`)

