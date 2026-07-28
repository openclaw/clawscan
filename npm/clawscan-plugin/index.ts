import { resolveBundledBinaryPath } from "@openclaw/clawscan/resolve-binary";
import { definePluginEntry, type OpenClawPluginApi } from "openclaw/plugin-sdk/plugin-entry";
import { registerInstallGate } from "./src/register.ts";

export default definePluginEntry({
  id: "clawscan",
  name: "ClawScan Install Gate",
  description: "Scans candidate skills and plugins before OpenClaw installs or updates them.",
  register: (api: OpenClawPluginApi) => registerInstallGate(api, resolveBundledBinaryPath),
});
