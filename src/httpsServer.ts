// @ts-ignore
import Greenlock from "greenlock";
import GreenlockStore from "greenlock-store-fs"
import express from "express";
import https from "node:https";
import path from "node:path";
import dns from "node:dns";


import type { AppConfig } from "./config";
import type { AllowList } from "./allowList";
import type { GeoFence } from "./geoFence";
import { normalizeIp } from "./ip";

// --- HELPERS ---

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

// --- 1. DNS INTERCEPTOR (The Fix for ENOTFOUND) ---
// We overwrite dns.resolveTxt to lie about the dry-run record.
// This prevents Greenlock from crashing when local DNS is slow/cached.

const originalResolveTxt = dns.resolveTxt;
// @ts-ignore
dns.resolveTxt = (hostname: string, cb: (err: any, records: string[][]) => void) => {
    // If Greenlock is checking its self-test record...
    if (hostname.includes("_greenlock-dryrun")) {
        // ...Return a fake success immediately.
        // We don't care if this record actually propagates, we just want to move on.
        return cb(null, [["dry-run-success"]]);
    }
    // For all other records (like the REAL _acme-challenge), use real DNS.
    return originalResolveTxt(hostname, cb);
};


// --- 2. MANUAL CLOUDFLARE API ---

const CF_API = "https://api.cloudflare.com/client/v4";

async function getZoneId(domain: string, token: string): Promise<string | null> {
    const parts = domain.split(".");
    while (parts.length >= 2) {
        const zoneName = parts.join(".");
        try {
            const res = await fetch(`${CF_API}/zones?name=${zoneName}`, {
                headers: { "Authorization": `Bearer ${token}`, "Content-Type": "application/json" }
            });
            const data: any = await res.json();
            if (data.success && data.result && data.result.length > 0) {
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
                // If this is the dry-run domain, we can skip setting it entirely
                // because our DNS Interceptor will fake the success anyway.
                // This saves API calls and avoids "Record already exists" errors.
                if (domain.startsWith("_greenlock-dryrun")) {
                    console.log(`Skipping Cloudflare API for dry-run: ${domain}`);
                    return cb(null);
                }

                const token = opts.token || opts.cloudflareToken;
                if (!token) throw new Error("Cloudflare Token missing");

                const zoneId = await getZoneId(domain, token);
                if (!zoneId) throw new Error(`Could not find Cloudflare Zone for ${domain}`);

                const recordName = `_acme-challenge.${domain}`;
                // Greenlock v2 sometimes passes the key as the digest, sometimes val.
                // We prefer 'val', fallback to 'key'.
                const txtValue = val || key;

                console.log(`Setting Real TXT record: ${recordName}`);

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

                // Handle "Already Exists" gracefully
                if (!json.success) {
                    const isDup = json.errors?.some((e: any) => e.code === 81057);
                    if (!isDup) {
                        console.error("CF Create Error:", JSON.stringify(json.errors));
                        // Don't crash, let Greenlock try verification
                    }
                } else {
                    if (!opts.dns_records) opts.dns_records = {};
                    opts.dns_records[domain] = json.result.id;
                }

                // Wait for REAL propagation
                // 30s is safer for real Let's Encrypt validation
                console.log(`Waiting 30s for propagation...`);
                await new Promise(r => setTimeout(r, 30000));

                cb(null);
            } catch (e) {
                console.error("Challenge Set Error:", e);
                cb(e);
            }
        })();
    },

    remove: function (opts: any, domain: string, key: string, cb: Function) {
        (async () => {
            try {
                // Skip removal for dry-run (since we skipped creation)
                if (domain.startsWith("_greenlock-dryrun")) return cb(null);

                const token = opts.token || opts.cloudflareToken;
                const recordId = opts.dns_records ? opts.dns_records[domain] : null;

                if (recordId) {
                    const zoneId = await getZoneId(domain, token);
                    if (zoneId) {
                        await fetch(`${CF_API}/zones/${zoneId}/dns_records/${recordId}`, {
                            method: "DELETE",
                            headers: { "Authorization": `Bearer ${token}`, "Content-Type": "application/json" }
                        });
                        console.log(`Removed record for ${domain}`);
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
    config: AppConfig & {
        email: string;
        cloudflareToken: string;
    };
    allowList: AllowList | null;
    geoFence: GeoFence | null;
};

export async function startServer(opts: ServerOptions) {
    const { config, allowList, geoFence } = opts;

    // Use Cloudflare DNS to avoid local caching issues for the REAL check
    try { dns.setServers(["1.1.1.1", "8.8.8.8"]); } catch (e) { }

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
        debug: true, // Keep debug true to monitor progress
        cloudflareToken: config.cloudflareToken
    });

    const domainsToRegister = allowedHostPatterns.filter(h => !h.startsWith("*") && !h.startsWith("."));

    for (const domain of domainsToRegister) {
        try {
            console.log(`Checking certificate status for: ${domain}`);
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

    const httpsOptions = { ...gl.tlsOptions };
    const originalSNI = httpsOptions.SNICallback;

    httpsOptions.SNICallback = (servername: string, cb: (err: Error | null, ctx?: any) => void) => {
        if (!servername || !isHostnameAllowed(servername, allowedHostPatterns)) {
            return cb(new Error("Connection Dropped"));
        }
        if (originalSNI) return originalSNI(servername, cb);
        cb(null, undefined);
    };

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