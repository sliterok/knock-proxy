import express from "express";
import http from "node:http";
import path from "node:path";

import type { AppConfig } from "./config";
import type { AllowList } from "./allowList";
import type { GeoFence } from "./geoFence";
import { normalizeIp } from "./ip";

function parseTtlQuery(raw: unknown, fallback: number) {
    if (typeof raw === "string" && raw.trim() !== "") {
        const n = Number(raw);
        if (Number.isFinite(n)) return n;
    }
    return fallback;
}

export function startHttpServer(opts: { config: AppConfig; allowList: AllowList | null; geoFence: GeoFence | null }) {
    const { config, allowList, geoFence } = opts;

    const app = express();
    app.set("trust proxy", config.trustProxy); // respect X-Forwarded-For (e.g. Cloudflare / tunnels)

    const publicDir = path.resolve(process.cwd(), "public");
    app.use(express.static(publicDir));

    app.post("/unlock", (req, res) => {
        if (config.accessMode === "geoip") {
            return res.status(409).type("text/plain").send("unlock disabled (ACCESS_MODE=geoip)\n");
        }

        const ttl = parseTtlQuery(req.query?.ttl, config.defaultTtlSec);
        const ip = normalizeIp(req.ip);

        if (!ip) return res.status(400).type("text/plain").send("no ip\n");

        if (config.accessMode !== "allowlist" && (!geoFence || !geoFence.isAllowed(ip))) {
            const cc = geoFence?.countryForIp(ip) ?? "unknown";
            const accept = req.accepts(["text", "json"]);
            if (accept === "json") return res.status(403).json({ ok: false, ip, country: cc });
            return res.status(403).type("text/plain").send(`forbidden (country=${cc})\n`);
        }

        if (!allowList) return res.status(500).type("text/plain").send("allowList not configured\n");
        const grantedTtlSec = allowList.allowIp(ip, ttl);

        const accept = req.accepts(["text", "json"]);
        if (accept === "json") {
            return res.status(200).json({ ok: true, ip, grantedTtlSec });
        }

        return res.status(200).type("text/plain").send(`OK. allowed ${ip} for ${grantedTtlSec}s\n`);
    });

    const httpServer = http.createServer(app);
    httpServer.listen(config.httpPort, config.httpBindHost, () => {
        console.log(`unlock http listening on ${config.httpBindHost}:${config.httpPort}`);
    });

    return httpServer;
}
