import express from "express";
import https from "node:https";
import path from "node:path";
import GreenlockExpress from "greenlock-express"
// @ts-ignore
import CloudflareChallenge from "acme-dns-01-cloudflare"

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


type ServerOptions = {
    config: AppConfig
    allowList: AllowList | null;
    geoFence: GeoFence | null;
};

export async function startServer(opts: ServerOptions) {
    const { config, allowList, geoFence } = opts;

    // 1. Prepare Whitelist
    const allowedHostPatterns = config.httpAllowedHosts
        .map(normalizeAllowedHostPattern)
        .filter((s): s is string => s !== null);

    // 2. Instantiate Cloudflare Challenge
    const dnsChallenge = new CloudflareChallenge({
        token: config.cloudflareToken,
        verifyPropagation: true,
        verbose: false
    });

    // 3. Initialize Greenlock
    const glx = GreenlockExpress.init({
        packageRoot: process.cwd(),
        configDir: "./greenlock.d",
        maintainerEmail: config.email,
        cluster: false,
        challenges: {
            "dns-01": dnsChallenge
        }
    } as GreenlockExpress.Options);

    // 4. REGISTER SITES (The missing step!)
    // We iterate over your allowed hosts and tell Greenlock to manage them.
    // Note: This is async but we don't necessarily need to await it to start the server,
    // Greenlock will handle it in the background/on-request.
    if (allowedHostPatterns.length > 0) {
        // Filter out wildcard patterns (*.foo.com) as they require different handling
        // We only register explicit domains (example.com, www.example.com)
        const domainsToRegister = allowedHostPatterns.filter(h => !h.startsWith("*") && !h.startsWith("."));

        for (const domain of domainsToRegister) {
            glx.add({
                subject: domain,
                altnames: [domain]
            }).catch((e: any) => {
                console.error(`Failed to register domain ${domain} with Greenlock:`, e);
            });
        }
    }

    // 5. Hijack SNI (ClientHello Dropper)
    const httpsOptions = { ...glx.httpsOptions };
    const originalSNI = httpsOptions.SNICallback;

    httpsOptions.SNICallback = (servername: string, cb: (err: Error | null, ctx?: any) => void) => {
        // --- CLIENT HELLO DROPPER ---
        if (!servername || !isHostnameAllowed(servername, allowedHostPatterns)) {
            // Log for debugging (optional)
            // console.log(`Dropped connection for SNI: ${servername}`);
            return cb(new Error("Connection Dropped"));
        }

        // Pass to Greenlock
        if (originalSNI) {
            return originalSNI(servername, cb);
        } else {
            cb(null, undefined);
        }
    };

    // 6. Express App
    const app = express();
    app.set("trust proxy", config.trustProxy);
    app.disable('x-powered-by');

    // Host Header Check (Defense in Depth)
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

    // 7. Start HTTPS Server
    // Note: We use config.httpPort for the HTTPS port as per your previous requests,
    // even though the var name says "http".
    const httpsServer = https.createServer(httpsOptions, app);

    httpsServer.listen(config.httpPort, config.httpBindHost, () => {
        console.log(`Secure server listening on ${config.httpBindHost}:${config.httpPort}`);
        console.log(`Allowed Hosts: ${allowedHostPatterns.join(", ")}`);
    });

    return httpsServer;
}