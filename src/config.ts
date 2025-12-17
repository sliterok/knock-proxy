export type AppConfig = {
    proxyPublicPort: number;
    danteHost: string;
    dantePort: number;
    httpPort: number;
    httpBindHost: string;
    httpAllowedHosts: string[]; // empty = allow all (Host / X-Forwarded-Host)
    tcpBindHost: string;
    trustProxy: boolean;
    gcIntervalMs: number;
    accessMode: "allowlist" | "geoip" | "both";
    allowCountries: string[]; // ISO-3166-1 alpha-2, uppercased (or "*" to allow all)
    allowListPath: string;
    allowListMaxPerSubnet: number;
    allowListSubnetStaleMs: number;
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

function parseBool(raw: string | undefined, fallback: boolean) {
    if (raw === undefined) return fallback;
    const s = raw.trim().toLowerCase();
    if (["1", "true", "yes", "y", "on"].includes(s)) return true;
    if (["0", "false", "no", "n", "off"].includes(s)) return false;
    return fallback;
}

function parseAccessMode(raw: string | undefined): AppConfig["accessMode"] {
    const s = raw?.trim().toLowerCase();
    if (s === "allowlist") return "allowlist";
    if (s === "geoip") return "geoip";
    if (s === "both") return "both";
    return "allowlist";
}

function parseCountryList(raw: string | undefined): string[] {
    if (!raw) return [];
    return raw
        .split(/[,\s]+/g)
        .map((s) => s.trim().toUpperCase())
        .filter((s) => s !== "");
}

function normalizeHostPattern(raw: string): string {
    let s = raw.trim().toLowerCase();
    s = s.replace(/^https?:\/\//, "");
    const slashIdx = s.indexOf("/");
    if (slashIdx >= 0) s = s.slice(0, slashIdx);
    s = s.replace(/\.+$/, "");
    return s;
}

function parseHostList(raw: string | undefined): string[] {
    if (!raw) return [];
    const out = raw
        .split(/[,\s]+/g)
        .map((s) => normalizeHostPattern(s))
        .filter((s) => s !== "");
    if (out.includes("*")) return [];
    return out;
}

export function loadConfig(env = process.env): AppConfig {
    const proxyPublicPort = parsePort(env.PROXY_PUBLIC_PORT, 1080);
    const danteHost = env.DANTE_HOST ?? "127.0.0.1";
    const dantePort = parsePort(env.DANTE_PORT, 1081);
    const httpPort = parsePort(env.HTTP_PORT, 3000);
    const httpBindHost = env.HTTP_BIND_HOST ?? "127.0.0.1";
    const httpAllowedHosts = parseHostList(env.HTTP_ALLOWED_HOSTS);
    const tcpBindHost = env.TCP_BIND_HOST ?? "0.0.0.0";
    const trustProxy = parseBool(env.TRUST_PROXY, true);
    const allowCountries = parseCountryList(env.ALLOW_COUNTRIES);
    const accessMode =
        env.ACCESS_MODE !== undefined ? parseAccessMode(env.ACCESS_MODE) : allowCountries.length > 0 ? "both" : "allowlist";
    const allowListPath = env.ALLOWLIST_PATH ?? "data/allowList.json";
    const allowListMaxPerSubnet = parseIntOrFallback(env.ALLOWLIST_MAX_PER_SUBNET, 100);
    const allowListSubnetStaleMs = parseIntOrFallback(env.ALLOWLIST_SUBNET_STALE_SEC, 7 * 24 * 60 * 60) * 1000;

    return {
        proxyPublicPort,
        danteHost,
        dantePort,
        httpPort,
        httpBindHost,
        httpAllowedHosts,
        tcpBindHost,
        trustProxy,
        gcIntervalMs: 30_000,
        accessMode,
        allowCountries,
        allowListPath,
        allowListMaxPerSubnet: Math.max(1, Math.min(10_000, allowListMaxPerSubnet)),
        allowListSubnetStaleMs: Math.max(60_000, allowListSubnetStaleMs),
    };
}
