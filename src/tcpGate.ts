import net from "node:net";

import type { AppConfig } from "./config";
import type { AllowList } from "./allowList";
import type { GeoFence } from "./geoFence";
import { normalizeIp } from "./ip";

export function startTcpGate(opts: { config: AppConfig; allowList: AllowList | null; geoFence: GeoFence | null }) {
    const { config, allowList, geoFence } = opts;

    const gate = net.createServer((client) => {
        const ip = normalizeIp(client.remoteAddress);
        if (!ip) {
            client.destroy();
            return;
        }

        if (config.accessMode !== "geoip" && (!allowList || !allowList.isAllowed(ip))) {
            client.destroy();
            return;
        }

        if (config.accessMode !== "allowlist" && (!geoFence || !geoFence.isAllowed(ip))) {
            client.destroy();
            return;
        }

        const upstream = net.connect({ host: config.danteHost, port: config.dantePort });

        client.on("error", () => upstream.destroy());
        upstream.on("error", () => client.destroy());

        client.pipe(upstream);
        upstream.pipe(client);
    });

    gate.on("error", (e) => console.error("gate error", e));
    gate.listen(config.proxyPublicPort, config.tcpBindHost, () => {
        console.log(
            `gate listening on ${config.tcpBindHost}:${config.proxyPublicPort} -> ${config.danteHost}:${config.dantePort}`
        );
    });

    return gate;
}
