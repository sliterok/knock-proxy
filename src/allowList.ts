import fs from "node:fs/promises";
import net from "node:net";
import path from "node:path";

export type AllowEntry = { ip: string; lastUsedAt: number };
type SubnetBucket = { lastUsedAt: number; entries: AllowEntry[] };

type PersistedAllowList = {
    updatedAt: number;
    subnets: Record<string, { lastUsedAt: number; entries: AllowEntry[] }>;
};

export type AllowListOptions = {
    persistPath?: string;
    maxEntriesPerSubnet?: number;
    subnetStaleMs?: number;
    usagePersistIntervalMs?: number;
    nowMs?: () => number;
};

function isNodeError(e: unknown): e is NodeJS.ErrnoException {
    return e instanceof Error;
}

function tryUnrefTimer(t: NodeJS.Timeout) {
    // best effort; older runtimes may not support it for all timer handles
    try {
        t.unref();
    } catch { }
}

function ipv4SubnetKey(ip: string) {
    const parts = ip.split(".");
    if (parts.length !== 4) return ip;
    return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
}

function parseIpv4(ip: string): [number, number, number, number] | null {
    const parts = ip.split(".");
    if (parts.length !== 4) return null;
    const out: number[] = [];
    for (const p of parts) {
        if (p.trim() === "") return null;
        const n = Number(p);
        if (!Number.isInteger(n) || n < 0 || n > 255) return null;
        out.push(n);
    }
    return [out[0]!, out[1]!, out[2]!, out[3]!];
}

function ipv4ToIpv6Groups(ipv4: string): [string, string] | null {
    const parts = parseIpv4(ipv4);
    if (!parts) return null;
    const hi = (parts[0] << 8) | parts[1];
    const lo = (parts[2] << 8) | parts[3];
    return [hi.toString(16), lo.toString(16)];
}

function ipv6Groups(ip: string): string[] | null {
    // Strip zone id if present (e.g. fe80::1%lo0)
    const zoneIdx = ip.indexOf("%");
    if (zoneIdx >= 0) ip = ip.slice(0, zoneIdx);

    const [leftRaw, rightRaw] = ip.split("::", 2);
    const left = leftRaw ? leftRaw.split(":").filter((s) => s !== "") : [];
    const right = rightRaw ? rightRaw.split(":").filter((s) => s !== "") : [];

    const rightExpanded = [...right];
    const lastRight = rightExpanded[rightExpanded.length - 1];
    if (lastRight && lastRight.includes(".")) {
        const ipv4Groups = ipv4ToIpv6Groups(lastRight);
        if (!ipv4Groups) return null;
        rightExpanded.splice(rightExpanded.length - 1, 1, ...ipv4Groups);
    }

    const groupsPresent = left.length + rightExpanded.length;
    if (groupsPresent > 8) return null;
    const zeros = 8 - groupsPresent;

    const groups = [...left, ...Array.from({ length: zeros }, () => "0"), ...rightExpanded];
    if (groups.length !== 8) return null;

    return groups.map((g) => {
        const n = Number.parseInt(g, 16);
        if (!Number.isFinite(n) || n < 0 || n > 0xffff) return "0000";
        return n.toString(16).padStart(4, "0");
    });
}

function ipv6SubnetKey(ip: string) {
    const groups = ipv6Groups(ip);
    if (!groups) return ip;
    return `${groups.slice(0, 4).join(":")}::/64`;
}

function subnetKey(ip: string) {
    const t = net.isIP(ip);
    if (t === 4) return ipv4SubnetKey(ip);
    if (t === 6) return ipv6SubnetKey(ip);
    return ip;
}

async function writeFileAtomic(filePath: string, data: string) {
    const dir = path.dirname(filePath);
    await fs.mkdir(dir, { recursive: true });

    const tmp = `${filePath}.tmp.${process.pid}.${Date.now()}`;
    await fs.writeFile(tmp, data, "utf8");
    try {
        await fs.rename(tmp, filePath);
    } catch (e) {
        if (isNodeError(e) && (e.code === "EEXIST" || e.code === "EPERM")) {
            await fs.rm(filePath, { force: true });
            await fs.rename(tmp, filePath);
            return;
        }
        throw e;
    }
}

export class AllowList {
    private readonly subnets = new Map<string, SubnetBucket>();

    private readonly persistPath: string | null;
    private readonly maxEntriesPerSubnet: number;
    private readonly subnetStaleMs: number;
    private readonly usagePersistIntervalMs: number;
    private readonly nowMs: () => number;

    private dirty = false;
    private persistTimer: NodeJS.Timeout | null = null;
    private persistDueAt = 0;
    private persistInFlight: Promise<void> | null = null;
    private lastPersistAt = 0;

    constructor(opts: AllowListOptions = {}) {
        this.persistPath = opts.persistPath && opts.persistPath.trim() !== "" ? opts.persistPath : null;
        this.maxEntriesPerSubnet = Math.max(1, Math.min(opts.maxEntriesPerSubnet ?? 100, 10_000));
        this.subnetStaleMs = Math.max(60_000, opts.subnetStaleMs ?? 7 * 24 * 60 * 60 * 1000);
        this.usagePersistIntervalMs = Math.max(10_000, opts.usagePersistIntervalMs ?? 60_000);
        this.nowMs = opts.nowMs ?? (() => Date.now());
    }

    async loadFromDisk() {
        if (!this.persistPath) return;
        try {
            const raw = await fs.readFile(this.persistPath, "utf8");
            const parsed = JSON.parse(raw) as unknown;
            if (!parsed || typeof parsed !== "object") return;

            const now = this.nowMs();
            const subnets = (parsed as { subnets?: unknown }).subnets;
            if (!subnets || typeof subnets !== "object") return;

            for (const [k, rawSubnet] of Object.entries(subnets as Record<string, unknown>)) {
                if (!rawSubnet || typeof rawSubnet !== "object") continue;
                const rawEntries = (rawSubnet as { entries?: unknown }).entries;
                if (!Array.isArray(rawEntries)) continue;

                const entries: AllowEntry[] = [];
                for (const e of rawEntries) {
                    if (!e || typeof e !== "object") continue;
                    const ip = (e as { ip?: unknown }).ip;
                    if (typeof ip !== "string" || ip.trim() === "") continue;
                    const lastUsedAtRaw = (e as { lastUsedAt?: unknown }).lastUsedAt;
                    const lastUsedAt = Number.isFinite(lastUsedAtRaw as number) ? Number(lastUsedAtRaw) : now;
                    entries.push({ ip, lastUsedAt });
                }
                if (entries.length === 0) continue;

                const rawSubnetLastUsedAt = (rawSubnet as { lastUsedAt?: unknown }).lastUsedAt;
                const subnetLastUsedAt = Number.isFinite(rawSubnetLastUsedAt as number) ? Number(rawSubnetLastUsedAt) : 0;
                const entriesMaxLastUsedAt = entries.reduce((acc, e) => Math.max(acc, e.lastUsedAt), 0);
                const lastUsedAt = Math.max(subnetLastUsedAt, entriesMaxLastUsedAt, 0) || now;

                if (now - lastUsedAt > this.subnetStaleMs) continue;

                const trimmed = entries.length > this.maxEntriesPerSubnet ? entries.slice(-this.maxEntriesPerSubnet) : entries;
                this.subnets.set(k, { lastUsedAt, entries: trimmed });
            }

            this.dirty = false;
        } catch (e) {
            if (isNodeError(e) && e.code === "ENOENT") return;
            console.warn("allowList load failed:", e);
        }
    }

    private markDirty(delayMs: number) {
        if (!this.persistPath) return;
        this.dirty = true;
        const dueAt = this.nowMs() + delayMs;

        if (this.persistTimer && dueAt >= this.persistDueAt) return;

        if (this.persistTimer) clearTimeout(this.persistTimer);
        this.persistDueAt = dueAt;
        this.persistTimer = setTimeout(() => {
            this.persistTimer = null;
            this.persistDueAt = 0;
            void this.flushToDisk();
        }, delayMs);
        tryUnrefTimer(this.persistTimer);
    }

    private snapshot(): PersistedAllowList {
        const subnets: PersistedAllowList["subnets"] = {};
        for (const [k, v] of this.subnets) subnets[k] = { lastUsedAt: v.lastUsedAt, entries: v.entries };
        return { updatedAt: this.nowMs(), subnets };
    }

    private async flushToDisk() {
        if (!this.persistPath) return;
        if (this.persistInFlight) {
            try {
                await this.persistInFlight;
            } catch { }
        }
        if (!this.dirty) return;

        const persistPath = this.persistPath;
        this.dirty = false;
        const payload = JSON.stringify(this.snapshot());

        this.persistInFlight = writeFileAtomic(persistPath, payload);
        try {
            await this.persistInFlight;
            this.lastPersistAt = this.nowMs();
        } catch (e) {
            console.warn("allowList persist failed:", e);
            this.dirty = true;
        } finally {
            this.persistInFlight = null;
        }

        if (this.dirty) this.markDirty(250);
    }

    private touchUsage(subnet: SubnetBucket, isImmediate: boolean) {
        const now = this.nowMs();
        subnet.lastUsedAt = now;
        if (isImmediate) {
            this.markDirty(250);
            return;
        }

        const earliestPersistAt = this.lastPersistAt + this.usagePersistIntervalMs;
        const delay = Math.max(1000, earliestPersistAt - now);
        this.markDirty(delay);
    }

    gc(ip?: string) {
        const now = this.nowMs();
        let changed = false;

        const gcSubnet = (key: string, subnet: SubnetBucket) => {
            if (subnet.entries.length === 0 || now - subnet.lastUsedAt > this.subnetStaleMs) {
                this.subnets.delete(key);
                changed = true;
                return;
            }

            if (subnet.entries.length > this.maxEntriesPerSubnet) {
                subnet.entries = subnet.entries.slice(-this.maxEntriesPerSubnet);
                changed = true;
            }
        };

        if (ip) {
            const key = subnetKey(ip);
            const subnet = this.subnets.get(key);
            if (!subnet) return;
            gcSubnet(key, subnet);
            if (changed) this.markDirty(1000);
            return;
        }

        for (const [k, v] of this.subnets) gcSubnet(k, v);
        if (changed) this.markDirty(1000);
    }

    isAllowed(ip: string) {
        this.gc(ip);

        const key = subnetKey(ip);
        const subnet = this.subnets.get(key);
        if (!subnet) return false;

        const now = this.nowMs();
        let foundIdx = -1;
        for (let i = 0; i < subnet.entries.length; i++) {
            if (subnet.entries[i]!.ip === ip) {
                foundIdx = i;
                break;
            }
        }
        if (foundIdx < 0) return false;

        const entry = subnet.entries[foundIdx]!;
        entry.lastUsedAt = now;
        this.touchUsage(subnet, false);

        // Ring buffer behavior: move recently used entry to the end
        if (foundIdx !== subnet.entries.length - 1) {
            subnet.entries.splice(foundIdx, 1);
            subnet.entries.push(entry);
        }

        return true;
    }

    allowIp(ip: string) {
        const now = this.nowMs();

        const key = subnetKey(ip);
        const subnet = this.subnets.get(key) ?? { lastUsedAt: now, entries: [] };
        subnet.lastUsedAt = now;

        let foundIdx = -1;
        for (let i = 0; i < subnet.entries.length; i++) {
            if (subnet.entries[i]!.ip === ip) {
                foundIdx = i;
                break;
            }
        }

        const entry: AllowEntry = { ip, lastUsedAt: now };
        if (foundIdx >= 0) subnet.entries.splice(foundIdx, 1);
        subnet.entries.push(entry);

        if (subnet.entries.length > this.maxEntriesPerSubnet) {
            subnet.entries = subnet.entries.slice(-this.maxEntriesPerSubnet);
        }

        this.subnets.set(key, subnet);
        this.touchUsage(subnet, true);
    }
}
