import express from "express";
import type { Request, Response } from "express";
import https from "node:https";
import path from "node:path";

// @ts-ignore
import Greenlock from "@root/greenlock";
import GreenlockExpress from "greenlock-express";

import type { AppConfig } from "./config";
import type { AllowList } from "./allowList";
import type { GeoFence } from "./geoFence";
import { normalizeIp } from "./ip";

// --- Helpers ---
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
    if (s.startsWith("[")) {
        const endIdx = s.indexOf("]");
        if (endIdx < 0) return null;
        return s.slice(1, endIdx) || null;
    }
    const firstColon = s.indexOf(":");
    if (firstColon >= 0 && s.indexOf(":", firstColon + 1) === -1) {
        return s.slice(0, firstColon) || null;
    }
    return s;
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
    if (s.startsWith("*.")) { prefix = "*."; s = s.slice(2); }
    else if (s.startsWith(".")) { prefix = "."; s = s.slice(1); }
    const hostname = hostnameFromHostHeader(s);
    return hostname ? prefix + hostname : null;
}

function isHostnameAllowed(hostname: string, allowedPatterns: string[]) {
    for (const pattern of allowedPatterns) {
        if (pattern === hostname) return true;
        if (pattern.startsWith(".")) {
            const base = pattern.slice(1);
            if (base !== "" && (hostname === base || hostname.endsWith("." + base))) return true;
        }
        if (pattern.startsWith("*.")) {
            const base = pattern.slice(2);
            if (base !== "" && (hostname === base || hostname.endsWith("." + base))) return true;
        }
    }
    return false;
}

function dropConnection(socket: any) {
    try {
        if (typeof socket.resetAndDestroy === "function") socket.resetAndDestroy();
        else socket.destroy();
    } catch {
        try { socket.destroy(); } catch { }
    }
}

// --- Types ---
interface GreenlockInstance {
    httpsOptions: https.ServerOptions;
    serve: (app: any) => void;
}

type ServerOptions = {
    config: AppConfig;
    allowList: AllowList | null;
    geoFence: GeoFence | null;
};

// --- Main Server ---

export async function startServer(opts: ServerOptions) {
    const { config, allowList, geoFence } = opts;

    const allowedHostPatterns = config.httpAllowedHosts
        .map(normalizeAllowedHostPattern)
        .filter((s): s is string => s !== null);

    // Define the path to the adapter we created
    // This MUST be a relative string path so Greenlock can require() it.
    const challengeModulePath = "./adapter.js";

    // 1. MANAGEMENT PHASE
    if (allowedHostPatterns.length > 0) {
        const gl = Greenlock.create({
            packageRoot: process.cwd(),
            configDir: "./greenlock.d",
            maintainerEmail: config.email,
        });

        await gl.manager.defaults({
            subscriberEmail: config.email,
            agreeToTerms: true,
            challenges: {
                "dns-01": {
                    module: challengeModulePath,
                    token: config.cloudflareToken
                }
            }
        });

        const domainsToRegister = allowedHostPatterns.filter(h => !h.startsWith("*") && !h.startsWith("."));
        for (const domain of domainsToRegister) {
            try {
                await gl.add({
                    subject: domain,
                    altnames: [domain]
                });
                console.log(`Registered domain: ${domain}`);
            } catch (e) {
                // Ignore "already registered"
            }
        }
    }

    // 2. SERVING PHASE
    const glx = GreenlockExpress.init({
        packageRoot: process.cwd(),
        configDir: "./greenlock.d",
        maintainerEmail: config.email,
        cluster: false,
        challenges: {
            "dns-01": {
                module: challengeModulePath,
                token: config.cloudflareToken
            }
        }
    }) as unknown as GreenlockInstance;

    // 3. HIJACK SNI (ClientHello Dropper)
    const httpsOptions = { ...glx.httpsOptions };
    const greenlockSNI = httpsOptions.SNICallback;

    httpsOptions.SNICallback = (servername: string, cb: (err: Error | null, ctx?: any) => void) => {
        if (!servername || !isHostnameAllowed(servername, allowedHostPatterns)) {
            return cb(new Error("Connection Dropped"));
        }

        if (greenlockSNI) {
            return greenlockSNI(servername, cb);
        } else {
            cb(null, undefined);
        }
    };

    // 4. EXPRESS APP
    const app = express();
    app.set("trust proxy", config.trustProxy);
    app.disable('x-powered-by');

    if (allowedHostPatterns.length > 0) {
        app.use((req, res, next) => {
            const hostname = headerValue(req.headers["host"]);
            const cleanHost = hostname ? hostnameFromHostHeader(hostname) : null;
            if (!cleanHost || !isHostnameAllowed(cleanHost, allowedHostPatterns)) {
                dropConnection(req.socket);
                try { res.destroy(); } catch { }
                return;
            }
            next();
        });
    }

    const publicDir = path.resolve(process.cwd(), "public");
    app.use(express.static(publicDir));

    app.post("/unlock", (req, res) => {
        const ip = normalizeIp(req.ip);
        if (!ip) return res.status(400).send("no ip\n");
        if (!allowList) return res.status(500).send("allowList not configured\n");

        allowList.allowIp(ip);

        const accept = req.accepts(["text", "json"]);
        if (accept === "json") {
            return res.status(200).json({ ok: true, ip, country: geoFence?.countryForIp(ip) ?? null });
        }
        return res.status(200).type("text/plain").send(`OK. allowed ${ip}\n`);
    });

    // 5. START SERVER
    const httpsServer = https.createServer(httpsOptions, app);

    httpsServer.listen(config.httpPort, config.httpBindHost, () => {
        console.log(`Secure server listening on ${config.httpBindHost}:${config.httpPort}`);
    });

    return httpsServer;
}