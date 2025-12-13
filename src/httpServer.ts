import express from "express";
import http from "node:http";
import path from "node:path";

import type { AppConfig } from "./config";
import type { AllowList } from "./allowList";
import { normalizeIp } from "./ip";

function parseTtlQuery(raw: unknown, fallback: number) {
    if (typeof raw === "string" && raw.trim() !== "") {
        const n = Number(raw);
        if (Number.isFinite(n)) return n;
    }
    return fallback;
}

export function startHttpServer(opts: { config: AppConfig; allowList: AllowList }) {
    const { config, allowList } = opts;

    const app = express();
    app.set("trust proxy", config.trustProxy); // respect X-Forwarded-For (e.g. Cloudflare / tunnels)

    const publicDir = path.resolve(process.cwd(), "public");
    app.use(express.static(publicDir));

    app.get("/unlock", (req, res) => {
        const ttl = parseTtlQuery(req.query?.ttl, config.defaultTtlSec);
        const ip = normalizeIp(req.ip);

        if (!ip) return res.status(400).type("text/plain").send("no ip\n");

        const grantedTtlSec = allowList.allowIp(ip, ttl);

        const accept = req.accepts(["text", "json"]);
        if (accept === "json") {
            return res.status(200).json({ ok: true, ip, grantedTtlSec });
        }

        return res.status(200).type("text/plain").send(`OK. allowed ${ip} for ${grantedTtlSec}s\n`);
    });

    const httpServer = http.createServer(app);
    httpServer.listen(config.httpPort, config.bindHost, () => {
        console.log(`unlock http listening on ${config.bindHost}:${config.httpPort}`);
    });

    return httpServer;
}

