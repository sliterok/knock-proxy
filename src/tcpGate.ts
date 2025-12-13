import net from "node:net";

import type { AppConfig } from "./config";
import type { AllowList } from "./allowList";
import { normalizeIp } from "./ip";

export function startTcpGate(opts: { config: AppConfig; allowList: AllowList }) {
    const { config, allowList } = opts;

    const gate = net.createServer((client) => {
        const ip = normalizeIp(client.remoteAddress);
        if (!ip || !allowList.isAllowed(ip)) {
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
    gate.listen(config.proxyPublicPort, config.bindHost, () => {
        console.log(
            `gate listening on ${config.bindHost}:${config.proxyPublicPort} -> ${config.danteHost}:${config.dantePort}`
        );
    });

    return gate;
}

