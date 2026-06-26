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
