import "dotenv/config";

import { AllowList } from "./allowList";
import { loadConfig } from "./config";
import { startHttpServer } from "./httpServer";
import { startTcpGate } from "./tcpGate";

const config = loadConfig();
const allowList = new AllowList();

startHttpServer({ config, allowList });
startTcpGate({ config, allowList });

setInterval(() => allowList.gc(), config.gcIntervalMs).unref();

