# Sandbox

ClawScan runs command-backed scanners and judges in
`ghcr.io/openclaw/clawscan-runtime:latest` by default:

```bash
clawscan ./my-skill --scanner skillspector
```

Use `--sandbox off` only in an already-isolated environment, or when you have
installed scanner dependencies on the host with `clawscan install`. Use
`--sandbox-env <NAME>` or a profile `sandbox.env` list to pass judge-specific
environment variables into the container.

## Worker cleanup

A supervising worker can set `CLAWSCAN_SANDBOX_RUN_ID` to a fresh random ID
(1-64 letters, digits, dots, underscores or hyphens; start with a letter or digit).
ClawScan labels each container with `org.openclaw.clawscan.run-id` and a random
`org.openclaw.clawscan.command-id`. After terminating ClawScan, the worker owns
cleanup: select containers by the exact run label, verify their ownership labels,
and remove them by container ID, including containers created after cancellation.
Docker's `--rm` handles normal exits; ClawScan itself does not sweep containers.
