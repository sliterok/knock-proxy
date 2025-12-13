import "dotenv/config";

import { AllowList } from "./allowList";
import { loadConfig } from "./config";
import { GeoFence } from "./geoFence";
import { startHttpServer } from "./httpServer";
import { startTcpGate } from "./tcpGate";

async function main() {
    const config = loadConfig();

    const allowList = new AllowList({
            persistPath: config.allowListPath,
            maxEntriesPerSubnet: config.allowListMaxPerSubnet,
            subnetStaleMs: config.allowListSubnetStaleMs,
        });

    await allowList.loadFromDisk();
    setInterval(() => allowList.gc(), config.gcIntervalMs).unref();

    const wantsGeoFence = config.accessMode !== "allowlist";
    const geoFence = wantsGeoFence ? await GeoFence.create(config.allowCountries) : null;
    if (wantsGeoFence && !geoFence) {
        throw new Error("ACCESS_MODE requires GeoIP, but ALLOW_COUNTRIES is empty");
    }

    startHttpServer({ config, allowList, geoFence });
    startTcpGate({ config, allowList, geoFence });
}

main().catch((e) => {
    console.error(e);
    process.exitCode = 1;
});
