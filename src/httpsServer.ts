import express from "express";
import type { Request, Response } from "express";
import https from "node:https";
import path from "node:path";
import dns from "node:dns";


// @ts-ignore
import Greenlock from "greenlock";
import GreenlockStore from "greenlock-store-fs"

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

// --- MANUAL CLOUDFLARE IMPLEMENTATION (Fixed) ---

const CF_API = "https://api.cloudflare.com/client/v4";

async function getZoneId(domain: string, token: string): Promise<string | null> {
    const parts = domain.split(".");
    // Walk up the domain tree to find the Zone (e.g. for _greenlock.sub.example.com, try example.com)
    while (parts.length >= 2) {
        const zoneName = parts.join(".");
        try {
            const res = await fetch(`${CF_API}/zones?name=${zoneName}`, {
                headers: { "Authorization": `Bearer ${token}`, "Content-Type": "application/json" }
            });
            const data: any = await res.json();
            if (data.success && data.result && data.result.length > 0) {
                // Ensure precise match to avoid sub-zone confusion
                const zone = data.result.find((z: any) => z.name === zoneName);
                if (zone) return zone.id;
            }
        } catch (e) { }
        parts.shift();
    }
    return null;
}

const ManualCloudflareChallenge = {
    create: function (options: any) { return ManualCloudflareChallenge; },

    set: function (opts: any, domain: string, key: string, val: string, cb: Function) {
        (async () => {
            try {
                const token = opts.token || opts.cloudflareToken;
                if (!token) throw new Error("Cloudflare Token missing");

                const zoneId = await getZoneId(domain, token);
                if (!zoneId) throw new Error(`Could not find Cloudflare Zone for ${domain}`);

                // --- FIX: DETECT DRY RUN ---
                // Greenlock dry-run domains look like '_greenlock-dryrun-xxxx.example.com'
                // Real challenges are just 'example.com' and need '_acme-challenge' prepended.
                let recordName = domain;
                if (!domain.startsWith("_greenlock-dryrun")) {
                    recordName = `_acme-challenge.${domain}`;
                }

                // Cloudflare needs the digest (val), or key if val is missing
                const txtValue = val || key;

                console.log(`Setting TXT record: ${recordName} -> ${txtValue}`);

                const res = await fetch(`${CF_API}/zones/${zoneId}/dns_records`, {
                    method: "POST",
                    headers: { "Authorization": `Bearer ${token}`, "Content-Type": "application/json" },
                    body: JSON.stringify({
                        type: "TXT",
                        name: recordName,
                        content: txtValue,
                        ttl: 120
                    })
                });

                const json: any = await res.json();
                if (!json.success) {
                    // Ignore "Record already exists" errors (code 81057) to be safe
                    const isDup = json.errors.some((e: any) => e.code === 81057);
                    if (!isDup) {
                        console.error("CF Create Error:", JSON.stringify(json.errors));
                        throw new Error("Failed to create DNS record");
                    }
                } else {
                    // Save ID for cleanup
                    if (!opts.dns_records) opts.dns_records = {};
                    opts.dns_records[domain] = json.result.id;
                }

                console.log(`Waiting 20s for propagation...`);
                await new Promise(r => setTimeout(r, 20000));

                cb(null);
            } catch (e) {
                cb(e);
            }
        })();
    },

    remove: function (opts: any, domain: string, key: string, cb: Function) {
        (async () => {
            try {
                const token = opts.token || opts.cloudflareToken;
                const recordId = opts.dns_records ? opts.dns_records[domain] : null;

                if (recordId) {
                    const zoneId = await getZoneId(domain, token);
                    if (zoneId) {
                        await fetch(`${CF_API}/zones/${zoneId}/dns_records/${recordId}`, {
                            method: "DELETE",
                            headers: { "Authorization": `Bearer ${token}`, "Content-Type": "application/json" }
                        });
                        console.log(`Cleaned up record for ${domain}`);
                    }
                }
                cb(null);
            } catch (e) {
                cb(null);
            }
        })();
    },

    get: function (opts: any, domain: string, key: string, cb: Function) {
        cb(null);
    }
};


// --- MAIN SERVER ---

type ServerOptions = {
    config: AppConfig
    allowList: AllowList | null;
    geoFence: GeoFence | null;
};

export async function startServer(opts: ServerOptions) {
    const { config, allowList, geoFence } = opts;

    // 1. FORCE DNS TO CLOUDFLARE (Fixes ENOTFOUND errors)
    // This forces Node to use 1.1.1.1 instead of your local/docker resolver
    // which might be caching the "Not Found" response.
    try {
        dns.setServers(["1.1.1.1", "8.8.8.8"]);
    } catch (e) {
        console.warn("Could not set custom DNS servers:", e);
    }

    const allowedHostPatterns = config.httpAllowedHosts
        .map(normalizeAllowedHostPattern)
        .filter((s): s is string => s !== null);

    const store = GreenlockStore.create({
        configDir: "./greenlock.d",
        debug: false
    });

    const gl = Greenlock.create({
        server: "https://acme-v02.api.letsencrypt.org/directory",
        version: "draft-11",
        store: store,
        challenges: { "dns-01": ManualCloudflareChallenge },
        challengeType: "dns-01",
        agreeTos: true,
        email: config.email,
        debug: true,
        cloudflareToken: config.cloudflareToken
    });

    // Register Domains
    const domainsToRegister = allowedHostPatterns.filter(h => !h.startsWith("*") && !h.startsWith("."));

    for (const domain of domainsToRegister) {
        try {
            console.log(`Ensuring certificate for: ${domain}`);
            await gl.register({
                domains: [domain],
                email: config.email,
                agreeTos: true,
                rsaKeySize: 2048,
                challengeType: "dns-01"
            });
        } catch (e) {
            console.error(`Certificate Error (${domain}):`, e);
        }
    }

    // Hijack SNI
    const httpsOptions = { ...gl.tlsOptions };
    const originalSNI = httpsOptions.SNICallback;

    httpsOptions.SNICallback = (servername: string, cb: (err: Error | null, ctx?: any) => void) => {
        if (!servername || !isHostnameAllowed(servername, allowedHostPatterns)) {
            return cb(new Error("Connection Dropped"));
        }
        if (originalSNI) return originalSNI(servername, cb);
        cb(null, undefined);
    };

    // Express App
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

    const httpsServer = https.createServer(httpsOptions, app);

    httpsServer.listen(config.httpPort, config.httpBindHost, () => {
        console.log(`Secure server listening on ${config.httpBindHost}:${config.httpPort}`);
    });

    return httpsServer;
}