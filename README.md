# ClawScan

Standalone scanner runner for OpenClaw skills.

V1 is a small CLI foundation:

```bash
clawscan ./my-skill \
  --scanner skillspector \
  --scanner virustotal \
  --output ./run.json
```

Secrets are read from environment variables, never CLI flags.
