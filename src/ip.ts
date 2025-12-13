export function normalizeIp(raw: string | undefined): string | null {
    if (!raw) return null;
    // "::ffff:1.2.3.4" -> "1.2.3.4"
    if (raw.startsWith("::ffff:")) return raw.slice(7);
    // "[::1]" etc
    return raw.replace(/^\[|\]$/g, "");
}

