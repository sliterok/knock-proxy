// socks5-check.ts
import net from "node:net";

type CheckOk = {
    ok: true;
    proxy: string;
    target: string;
    connectMs: number;
    handshakeMs: number;
    requestMs: number;
    totalMs: number;
    httpStatusLine: string;
    exitIp?: string;
};

type CheckFail = {
    ok: false;
    proxy: string;
    target: string;
    stage: "tcp" | "greeting" | "connect" | "http";
    message: string;
    totalMs: number;
};

type CheckResult = CheckOk | CheckFail;

function nowMs() {
    return Number(process.hrtime.bigint() / 1_000_000n);
}

function isIPv4(host: string) {
    const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (!m) return false;
    for (let i = 1; i <= 4; i++) {
        const n = Number(m[i]);
        if (!Number.isInteger(n) || n < 0 || n > 255) return false;
    }
    return true;
}

function parseHostPort(s: string): { host: string; port: number } {
    const idx = s.lastIndexOf(":");
    if (idx <= 0) throw new Error(`Invalid host:port: ${s}`);
    const host = s.slice(0, idx);
    const port = Number(s.slice(idx + 1));
    if (!Number.isInteger(port) || port <= 0 || port > 65535) throw new Error(`Invalid port: ${s}`);
    return { host, port };
}

class SocketReader {
    private bufs: Buffer[] = [];
    private total = 0;
    private ended = false;
    private err: Error | null = null;
    private waiters: Array<() => void> = [];

    constructor(private socket: net.Socket) {
        socket.on("data", (b) => {
            const buf = Buffer.from(b)
            this.bufs.push(buf);
            this.total += buf.length;
            this.flushWaiters();
        });
        socket.on("end", () => {
            this.ended = true;
            this.flushWaiters();
        });
        socket.on("close", () => {
            this.ended = true;
            this.flushWaiters();
        });
        socket.on("error", (e) => {
            this.err = e;
            this.flushWaiters();
        });
    }

    private flushWaiters() {
        const w = this.waiters;
        this.waiters = [];
        for (const fn of w) fn();
    }

    private async waitFor(predicate: () => boolean, timeoutMs: number) {
        if (predicate()) return;
        const start = nowMs();
        while (!predicate()) {
            if (this.err) throw this.err;
            if (this.ended) throw new Error("Socket ended before enough data arrived");
            const remaining = timeoutMs - (nowMs() - start);
            if (remaining <= 0) throw new Error("Timed out waiting for data");
            await new Promise<void>((resolve, reject) => {
                const t = setTimeout(() => {
                    cleanup();
                    reject(new Error("Timed out waiting for data"));
                }, remaining);

                const cleanup = () => clearTimeout(t);

                this.waiters.push(() => {
                    cleanup();
                    resolve();
                });
            });
        }
    }

    async readExactly(n: number, timeoutMs: number): Promise<Buffer> {
        await this.waitFor(() => this.total >= n, timeoutMs);

        let need = n;
        const out = Buffer.allocUnsafe(n);
        let off = 0;

        while (need > 0) {
            const b = this.bufs[0]!;
            if (b.length <= need) {
                b.copy(out, off);
                off += b.length;
                need -= b.length;
                this.bufs.shift();
            } else {
                b.copy(out, off, 0, need);
                this.bufs[0] = b.subarray(need);
                off += need;
                need = 0;
            }
        }

        this.total -= n;
        return out;
    }

    async readSome(maxBytes: number, timeoutMs: number): Promise<Buffer> {
        await this.waitFor(() => this.total > 0, timeoutMs);
        const n = Math.min(this.total, maxBytes);
        return this.readExactly(n, timeoutMs);
    }
}

function socksRepMessage(rep: number) {
    switch (rep) {
        case 0x00: return "Succeeded";
        case 0x01: return "General SOCKS server failure";
        case 0x02: return "Connection not allowed by ruleset";
        case 0x03: return "Network unreachable";
        case 0x04: return "Host unreachable";
        case 0x05: return "Connection refused by destination host";
        case 0x06: return "TTL expired";
        case 0x07: return "Command not supported";
        case 0x08: return "Address type not supported";
        default: return `Unknown error (REP=0x${rep.toString(16).padStart(2, "0")})`;
    }
}

async function checkSocks5(opts: {
    proxyHost: string;
    proxyPort: number;
    targetHost: string;
    targetPort: number;
    httpRequest?: string; // if provided, does a real HTTP request after CONNECT
    timeoutMs: number;
}): Promise<CheckResult> {
    const t0 = nowMs();
    const proxy = `${opts.proxyHost}:${opts.proxyPort}`;
    const target = `${opts.targetHost}:${opts.targetPort}`;

    let socket: net.Socket | undefined;
    try {
        const tcpStart = nowMs();
        socket = net.connect({ host: opts.proxyHost, port: opts.proxyPort });
        socket.setNoDelay(true);

        await new Promise<void>((resolve, reject) => {
            const onErr = (e: Error) => reject(e);
            const onConn = () => {
                socket!.off("error", onErr);
                resolve();
            };
            socket!.once("error", onErr);
            socket!.once("connect", onConn);

            const t = setTimeout(() => {
                socket!.off("error", onErr);
                socket!.off("connect", onConn);
                reject(new Error("Timed out connecting to proxy"));
            }, opts.timeoutMs);

            socket!.once("connect", () => clearTimeout(t));
            socket!.once("error", () => clearTimeout(t));
        });

        const connectMs = nowMs() - tcpStart;
        const reader = new SocketReader(socket);

        // Greeting: VER=5, NMETHODS=1, METHODS=[0x00 no-auth]
        const hsStart = nowMs();
        socket.write(Buffer.from([0x05, 0x01, 0x00]));
        const sel = await reader.readExactly(2, opts.timeoutMs);
        if (sel[0] !== 0x05) throw new Error(`Bad SOCKS version in greeting reply: ${sel[0]}`);
        if (sel[1] !== 0x00) throw new Error(`Proxy requires auth or refused no-auth (METHOD=0x${sel[1].toString(16)})`);
        const handshakeMs = nowMs() - hsStart;

        // CONNECT request
        const reqStart = nowMs();
        let atyp: number;
        let addr: Buffer;

        if (isIPv4(opts.targetHost)) {
            atyp = 0x01;
            addr = Buffer.from(opts.targetHost.split(".").map((x) => Number(x)));
        } else {
            atyp = 0x03;
            const name = Buffer.from(opts.targetHost, "utf8");
            if (name.length > 255) throw new Error("Domain name too long for SOCKS5");
            addr = Buffer.concat([Buffer.from([name.length]), name]);
        }

        const port = Buffer.allocUnsafe(2);
        port.writeUInt16BE(opts.targetPort, 0);

        const connectReq = Buffer.concat([Buffer.from([0x05, 0x01, 0x00, atyp]), addr, port]);
        socket.write(connectReq);

        const repHead = await reader.readExactly(4, opts.timeoutMs);
        if (repHead[0] !== 0x05) throw new Error(`Bad SOCKS version in connect reply: ${repHead[0]}`);

        const rep = repHead[1];
        const repAtyp = repHead[3];

        // Consume BND.ADDR + BND.PORT (we don't really need them, but must read)
        if (repAtyp === 0x01) {
            await reader.readExactly(4 + 2, opts.timeoutMs);
        } else if (repAtyp === 0x03) {
            const lenBuf = await reader.readExactly(1, opts.timeoutMs);
            await reader.readExactly(lenBuf[0] + 2, opts.timeoutMs);
        } else if (repAtyp === 0x04) {
            await reader.readExactly(16 + 2, opts.timeoutMs);
        } else {
            throw new Error(`Unknown ATYP in reply: ${repAtyp}`);
        }

        if (rep !== 0x00) {
            return {
                ok: false,
                proxy,
                target,
                stage: "connect",
                message: socksRepMessage(rep),
                totalMs: nowMs() - t0,
            };
        }

        const requestMs = nowMs() - reqStart;

        // Optional HTTP check
        let httpStatusLine = "";
        let exitIp: string | undefined;

        if (opts.httpRequest) {
            socket.write(opts.httpRequest);

            // Read up to ~32KB total or until socket closes
            let acc = Buffer.alloc(0);
            const deadline = nowMs() + opts.timeoutMs;

            while (acc.length < 32 * 1024) {
                const remaining = deadline - nowMs();
                if (remaining <= 0) throw new Error("Timed out waiting for HTTP response");
                const chunk = await reader.readSome(8192, remaining);
                acc = Buffer.concat([acc, chunk]);
                const str = acc.toString("latin1");
                if (str.includes("\r\n\r\n")) break;
            }

            const txt = acc.toString("latin1");
            const [head, bodyRaw = ""] = txt.split("\r\n\r\n", 2);
            httpStatusLine = head.split("\r\n")[0] ?? "";
            const body = bodyRaw.trim();

            // ipify returns plain text IP
            if (/^HTTP\/1\.[01]\s+200\b/.test(httpStatusLine)) {
                const m = body.match(/(\d{1,3}(?:\.\d{1,3}){3})/);
                if (m) exitIp = m[1];
            } else {
                return {
                    ok: false,
                    proxy,
                    target,
                    stage: "http",
                    message: `HTTP check failed: ${httpStatusLine || "no status line"}`,
                    totalMs: nowMs() - t0,
                };
            }
        }

        return {
            ok: true,
            proxy,
            target,
            connectMs,
            handshakeMs,
            requestMs,
            totalMs: nowMs() - t0,
            httpStatusLine: httpStatusLine || "(skipped)",
            exitIp,
        };
    } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        return {
            ok: false,
            proxy: `${opts.proxyHost}:${opts.proxyPort}`,
            target: `${opts.targetHost}:${opts.targetPort}`,
            stage: msg.includes("greeting") ? "greeting" : msg.includes("HTTP") ? "http" : msg.includes("proxy") ? "tcp" : "tcp",
            message: msg,
            totalMs: nowMs() - t0,
        };
    } finally {
        if (socket) socket.destroy();
    }
}

function parseArgs(argv: string[]) {
    // Usage:
    // node socks5-check.ts 1.2.3.4 1080 [--timeout=8000] [--target=host:port]
    const [proxyHost, proxyPortRaw, ...rest] = argv;

    if (!proxyHost || !proxyPortRaw) {
        throw new Error(
            "Usage: node socks5-check.ts <proxyHost> <proxyPort> [--timeout=8000] [--target=host:port]"
        );
    }

    const proxyPort = Number(proxyPortRaw);
    if (!Number.isInteger(proxyPort) || proxyPort <= 0 || proxyPort > 65535) throw new Error("Invalid proxyPort");

    let timeoutMs = 8000;
    let targetHost = "api.ipify.org";
    let targetPort = 80;

    for (const a of rest) {
        if (a.startsWith("--timeout=")) timeoutMs = Number(a.slice("--timeout=".length));
        else if (a.startsWith("--target=")) {
            const hp = parseHostPort(a.slice("--target=".length));
            targetHost = hp.host;
            targetPort = hp.port;
        }
    }
    if (!Number.isFinite(timeoutMs) || timeoutMs < 1000) throw new Error("Invalid timeoutMs");

    return { proxyHost, proxyPort, timeoutMs, targetHost, targetPort };
}

async function main() {
    const { proxyHost, proxyPort, timeoutMs, targetHost, targetPort } = parseArgs(process.argv.slice(2));

    const httpRequest =
        `GET /?format=text HTTP/1.1\r\n` +
        `Host: ${targetHost}\r\n` +
        `User-Agent: socks5-check/1.0\r\n` +
        `Connection: close\r\n` +
        `\r\n`;

    const res = await checkSocks5({
        proxyHost,
        proxyPort,
        targetHost,
        targetPort,
        httpRequest,
        timeoutMs,
    });

    console.log(JSON.stringify(res, null, 2));
    process.exit(res.ok ? 0 : 1);
}

main().catch((e) => {
    console.error(e);
    process.exit(1);
});
