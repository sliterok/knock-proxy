import express from "express";
import type { Request } from "express";
import http from "node:http";
import path from "node:path";

import type { AppConfig } from "./config";
import type { AllowList } from "./allowList";
import type { GeoFence } from "./geoFence";
import { normalizeIp } from "./ip";

function headerValue(v: string | string[] | undefined) {
    if (!v) return null;
    if (Array.isArray(v)) return v[0] ?? null;
    return v;
}

function hostnameFromHostHeader(raw: string): string | null {
    let s = raw.trim().toLowerCase();
    if (s === "") return null;

    const commaIdx = s.indexOf(",");
    if (commaIdx >= 0) s = s.slice(0, commaIdx).trim();

    s = s.replace(/\.+$/, "");
    if (s === "") return null;

    if (s.startsWith("[")) {
        const endIdx = s.indexOf("]");
        if (endIdx < 0) return null;
        const inside = s.slice(1, endIdx);
        return inside === "" ? null : inside;
    }

    const firstColon = s.indexOf(":");
    if (firstColon >= 0 && s.indexOf(":", firstColon + 1) === -1) {
        const host = s.slice(0, firstColon);
        const port = s.slice(firstColon + 1);
        if (host === "" || port === "") return null;
        if (!/^\d+$/.test(port)) return null;
        return host;
    }

    return s;
}

function requestHostname(req: Request, trustProxy: boolean) {
    const host = headerValue(req.headers["host"]);
    const forwardedHost = headerValue(req.headers["x-forwarded-host"]);

    if (trustProxy && forwardedHost) {
        const forwarded = hostnameFromHostHeader(forwardedHost);
        if (forwarded) return forwarded;
    }

    if (!host) return null;
    return hostnameFromHostHeader(host);
}

function normalizeAllowedHostPattern(raw: string): string | null {
    let s = raw.trim().toLowerCase();
    if (s === "" || s === "*") return null;

    s = s.replace(/^https?:\/\//, "");
    const slashIdx = s.indexOf("/");
    if (slashIdx >= 0) s = s.slice(0, slashIdx);
    s = s.replace(/\.+$/, "");
    if (s === "") return null;

    let prefix = "";
    if (s.startsWith("*.")) {
        prefix = "*.";
        s = s.slice(2);
    } else if (s.startsWith(".")) {
        prefix = ".";
        s = s.slice(1);
    }

    const hostname = hostnameFromHostHeader(s);
    if (!hostname) return null;
    return prefix + hostname;
}

function isHostnameAllowed(hostname: string, allowedPatterns: string[]) {
    for (const pattern of allowedPatterns) {
        if (pattern === hostname) return true;

        if (pattern.startsWith(".")) {
            const base = pattern.slice(1);
            if (base !== "" && (hostname === base || hostname.endsWith("." + base))) return true;
            continue;
        }

        if (pattern.startsWith("*.")) {
            const base = pattern.slice(2);
            if (base !== "" && (hostname === base || hostname.endsWith("." + base))) return true;
            continue;
        }
    }

    return false;
}

export function startHttpServer(opts: { config: AppConfig; allowList: AllowList | null; geoFence: GeoFence | null }) {
    const { config, allowList, geoFence } = opts;

    const app = express();
    app.set("trust proxy", config.trustProxy); // respect X-Forwarded-For (e.g. Cloudflare / tunnels)

    const allowedHostPatterns = config.httpAllowedHosts.map(normalizeAllowedHostPattern).filter((s): s is string => s !== null);
    if (allowedHostPatterns.length > 0) {
        app.use((req, res, next) => {
            const hostname = requestHostname(req, config.trustProxy);
            if (!hostname) return res.status(400).type("text/plain").send("invalid host\n");

            if (!isHostnameAllowed(hostname, allowedHostPatterns)) {
                return res.status(403).type("text/plain").send("host not allowed\n");
            }

            next();
        });
    }

    const publicDir = path.resolve(process.cwd(), "public");
    app.use(express.static(publicDir));

    app.post("/unlock", (req, res) => {
        const ip = normalizeIp(req.ip);

        if (!ip) return res.status(400).type("text/plain").send("no ip\n");

        if (!allowList) return res.status(500).type("text/plain").send("allowList not configured\n");
        allowList.allowIp(ip);

        const accept = req.accepts(["text", "json"]);
        if (accept === "json") {
            return res.status(200).json({ ok: true, ip, country: geoFence?.countryForIp(ip) ?? null });
        }

        return res.status(200).type("text/plain").send(`OK. allowed ${ip}\n`);
    });

    const httpServer = http.createServer(app);
    httpServer.listen(config.httpPort, config.httpBindHost, () => {
        console.log(`unlock http listening on ${config.httpBindHost}:${config.httpPort}`);
    });

    return httpServer;
}
