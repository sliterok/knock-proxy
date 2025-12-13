export type AllowEntry = { expiresAt: number };

export class AllowList {
    private allow = new Map<string, AllowEntry>();

    constructor(private readonly nowMs = () => Date.now()) { }

    gc(ip?: string) {
        const t = this.nowMs();
        if (ip) {
            const e = this.allow.get(ip);
            if (e && e.expiresAt <= t) this.allow.delete(ip);
            return;
        }
        for (const [k, v] of this.allow) if (v.expiresAt <= t) this.allow.delete(k);
    }

    isAllowed(ip: string) {
        this.gc(ip);
        const e = this.allow.get(ip);
        return !!e && e.expiresAt > this.nowMs();
    }

    allowIp(ip: string, ttlSec: number) {
        const ttl = Math.max(10, Math.min(ttlSec, 7 * 24 * 60 * 60)); // 10s..7d
        console.log('Allowed', ip, 'for', ttl)
        this.allow.set(ip, { expiresAt: this.nowMs() + ttl * 1000 });
        return ttl;
    }
}
