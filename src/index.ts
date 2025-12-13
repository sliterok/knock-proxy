import express from "express";
import net from "node:net";
import http from "node:http";
import 'dotenv/config'

type Entry = { expiresAt: number };

const PROXY_PUBLIC_PORT = Number(process.env.PROXY_PUBLIC_PORT ?? 1080);
const DANTE_HOST = process.env.DANTE_HOST ?? "127.0.0.1";
const DANTE_PORT = Number(process.env.DANTE_PORT ?? 1081);
const DEFAULT_TTL_SEC = Number(process.env.DEFAULT_TTL_SEC ?? 20 * 60);

const allow = new Map<string, Entry>();

function now() {
    return Date.now();
}

function normalizeIp(raw: string | undefined): string | null {
    if (!raw) return null;
    // "::ffff:1.2.3.4" -> "1.2.3.4"
    if (raw.startsWith("::ffff:")) return raw.slice(7);
    // "[::1]" etc
    return raw.replace(/^\[|\]$/g, "");
}

function gc(ip?: string) {
    const t = now();
    if (ip) {
        const e = allow.get(ip);
        if (e && e.expiresAt <= t) allow.delete(ip);
        return;
    }
    for (const [k, v] of allow) if (v.expiresAt <= t) allow.delete(k);
}

function isAllowed(ip: string) {
    gc(ip);
    const e = allow.get(ip);
    return !!e && e.expiresAt > now();
}

function allowIp(ip: string, ttlSec: number) {
    const ttl = Math.max(10, Math.min(ttlSec, 24 * 60 * 60)); // 10s..24h
    allow.set(ip, { expiresAt: now() + ttl * 1000 });
    return ttl;
}

// ---------- HTTP "knock" ----------
const app = express();

app.set("trust proxy", true); // если будешь за Cloudflare/Tunnel — скажу как поменять

app.get("/unlock", (req, res) => {
    const ttl = Number(req.query.ttl ?? DEFAULT_TTL_SEC);
    const ip = normalizeIp(req.ip);

    if (!ip) return res.status(400).send("no ip");

    const granted = allowIp(ip, ttl);
    return res.status(200).send(`OK. allowed ${ip} for ${granted}s\n`);
});

const httpServer = http.createServer(app);
httpServer.listen(3000, "0.0.0.0", () => {
    console.log("unlock http listening on :3000");
});

// ---------- TCP gate (public socks port) ----------
const gate = net.createServer((client) => {
    const ip = normalizeIp(client.remoteAddress);
    if (!ip || !isAllowed(ip)) {
        client.destroy();
        return;
    }

    const upstream = net.connect({ host: DANTE_HOST, port: DANTE_PORT });

    client.on("error", () => upstream.destroy());
    upstream.on("error", () => client.destroy());

    client.pipe(upstream);
    upstream.pipe(client);
});

gate.on("error", (e) => console.error("gate error", e));
gate.listen(PROXY_PUBLIC_PORT, "0.0.0.0", () => {
    console.log(`gate listening on :${PROXY_PUBLIC_PORT} -> ${DANTE_HOST}:${DANTE_PORT}`);
});

// периодический GC
setInterval(() => gc(), 30_000).unref();
