export type AppConfig = {
    proxyPublicPort: number;
    danteHost: string;
    dantePort: number;
    defaultTtlSec: number;
    httpPort: number;
    bindHost: string;
    trustProxy: boolean;
    gcIntervalMs: number;
};

function parseIntOrFallback(raw: string | undefined, fallback: number) {
    const n = Number(raw);
    if (!Number.isFinite(n)) return fallback;
    if (!Number.isInteger(n)) return fallback;
    return n;
}

function parsePort(raw: string | undefined, fallback: number) {
    const n = parseIntOrFallback(raw, fallback);
    if (n <= 0 || n > 65535) return fallback;
    return n;
}

export function loadConfig(env = process.env): AppConfig {
    const proxyPublicPort = parsePort(env.PROXY_PUBLIC_PORT, 1080);
    const danteHost = env.DANTE_HOST ?? "127.0.0.1";
    const dantePort = parsePort(env.DANTE_PORT, 1081);
    const defaultTtlSec = parseIntOrFallback(env.DEFAULT_TTL_SEC, 20 * 60);
    const httpPort = parsePort(env.HTTP_PORT, 3000);
    const bindHost = env.BIND_HOST ?? "0.0.0.0";

    return {
        proxyPublicPort,
        danteHost,
        dantePort,
        defaultTtlSec,
        httpPort,
        bindHost,
        trustProxy: true,
        gcIntervalMs: 30_000,
    };
}

