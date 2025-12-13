import "dotenv/config";

import { AllowList } from "./allowList";
import { loadConfig } from "./config";
import { GeoFence } from "./geoFence";
import { startHttpServer } from "./httpServer";
import { startTcpGate } from "./tcpGate";

async function main() {
    const config = loadConfig();

    const needsAllowList = config.accessMode !== "geoip";
    const needsGeoFence = config.accessMode !== "allowlist";

    const allowList = needsAllowList
        ? new AllowList({
            persistPath: config.allowListPath,
            maxEntriesPerSubnet: config.allowListMaxPerSubnet,
            subnetStaleMs: config.allowListSubnetStaleMs,
        })
        : null;

    if (allowList) {
        await allowList.loadFromDisk();
        setInterval(() => allowList.gc(), config.gcIntervalMs).unref();
    }

    const geoFence = needsGeoFence ? await GeoFence.create(config.allowCountries) : null;
    if (needsGeoFence && !geoFence) {
        throw new Error("ACCESS_MODE requires GeoIP, but ALLOW_COUNTRIES is empty");
    }

    startHttpServer({ config, allowList, geoFence });
    startTcpGate({ config, allowList, geoFence });
}

main().catch((e) => {
    console.error(e);
    process.exitCode = 1;
});
