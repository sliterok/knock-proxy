import express from "express";
import http from "node:http";
import path from "node:path";

import type { AppConfig } from "./config";
import type { AllowList } from "./allowList";
import type { GeoFence } from "./geoFence";
import { normalizeIp } from "./ip";

export function startHttpServer(opts: { config: AppConfig; allowList: AllowList | null; geoFence: GeoFence | null }) {
    const { config, allowList, geoFence } = opts;

    const app = express();
    app.set("trust proxy", config.trustProxy); // respect X-Forwarded-For (e.g. Cloudflare / tunnels)

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
