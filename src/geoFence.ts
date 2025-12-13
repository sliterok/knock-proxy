type GeoipLookupResult = { country?: string } | null;

type GeoipLiteModule = { lookup: (ip: string) => GeoipLookupResult };

async function loadGeoipLite(): Promise<GeoipLiteModule> {
    const mod = await import("geoip-lite");
    const geoip = (mod as unknown as { default?: unknown }).default ?? mod;
    if (!geoip || typeof geoip !== "object" || typeof (geoip as GeoipLiteModule).lookup !== "function") {
        throw new Error("geoip-lite module missing lookup()");
    }
    return geoip as GeoipLiteModule;
}

export class GeoFence {
    private readonly allow: Set<string>;
    private readonly lookup: (ip: string) => GeoipLookupResult;

    private constructor(allow: Set<string>, lookup: (ip: string) => GeoipLookupResult) {
        this.allow = allow;
        this.lookup = lookup;
    }

    static async create(allowCountries: string[]): Promise<GeoFence | null> {
        const allow = new Set(
            allowCountries
                .map((c) => c.trim().toUpperCase())
                .filter((c) => c !== "")
        );
        if (allow.size === 0) return null;

        const geoip = await loadGeoipLite();
        return new GeoFence(allow, (ip) => geoip.lookup(ip));
    }

    countryForIp(ip: string): string | null {
        const r = this.lookup(ip);
        const cc = r?.country?.toUpperCase();
        if (!cc || cc === "ZZ") return null;
        return cc;
    }

    isAllowed(ip: string): boolean {
        if (this.allow.has("*")) return true;
        const cc = this.countryForIp(ip);
        return !!cc && this.allow.has(cc);
    }
}

