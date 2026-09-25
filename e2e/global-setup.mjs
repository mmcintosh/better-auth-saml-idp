import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { GENERATED, KC, SSP } from "./lib/config.mjs";
import { configureKeycloak } from "./lib/keycloak.mjs";
import { assertPortsFree, compose, startIdp, stopListener, stopProcessGroup, waitFor, writeSimpleSamlphpMetadata } from "./lib/procs.mjs";
import { ensureTls } from "./lib/tls.mjs";
import { startTestSp } from "./lib/test-sp.mjs";

/** Starts IdP (workerd), Keycloak + SimpleSAMLphp (Docker), and the node-saml test SP. */
export default async function globalSetup() {
  ensureTls();
  await assertPortsFree();
  const stops = [];
  const teardown = async () => {
    if (process.env.KEEP) return console.log("[e2e] KEEP=1: leaving IdP, SPs and containers running");
    for (const stop of stops.reverse()) {
      try {
        await stop();
      } catch {}
    }
  };
  const onSignal = () => teardown().finally(() => process.exit(130));
  process.once("SIGINT", onSignal);
  process.once("SIGTERM", onSignal);
  try {
    const idp = await startIdp();
    stops.push(() => {
      stopProcessGroup(idp.pid);
      return stopListener(8787);
    });
    writeSimpleSamlphpMetadata(idp.cert);
    writeFileSync(join(GENERATED, "state.json"), JSON.stringify({ cert: idp.cert }));

    const sp = await startTestSp(idp.cert);
    stops.push(() => sp.close());

    compose(["up", "-d", "--force-recreate"]);
    stops.push(() => compose(["down", "-v"], { stdio: "ignore" }));
    await waitFor(`${KC}/realms/master`, "Keycloak");
    await waitFor(`${SSP}/simplesaml/`, "SimpleSAMLphp");
    await configureKeycloak(idp.cert);
    return teardown;
  } catch (e) {
    try {
      compose(["logs", "--tail", "60"]); // make startup failures self-explaining (CI)
    } catch {}
    await teardown();
    throw e;
  }
}
