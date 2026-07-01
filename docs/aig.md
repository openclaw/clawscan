# Tencent AI-Infra-Guard

The `aig` scanner adapter talks to a running Tencent AI-Infra-Guard API service.
It is not a command-backed scanner, and ClawScan does not start, install, or
expose the service for you.

Use this scanner only against a local or private-network A.I.G deployment. The
upstream service commonly runs without built-in authentication, so do not bind it
to a public interface or publish it through a tunnel.

## Minimum Local Setup

1. Follow the upstream A.I.G Docker/API service instructions from
   <https://github.com/Tencent/AI-Infra-Guard>.
2. Bind the service to `127.0.0.1` or another private interface.
3. Confirm the API is reachable from the same environment where `clawscan` runs.
4. Set `AIG_BASE_URL` when the service is not available at the default
   `http://localhost:8088`.
5. Set model/provider environment variables only when your A.I.G deployment
   requires them.

ClawScan treats A.I.G model and API keys as environment-only configuration. It
does not add CLI flags for these secrets and records only redacted evidence in
artifacts.

## Manual Smoke Test

Run a smoke test against a local/private service:

```bash
AIG_BASE_URL=http://localhost:8088 \
  clawscan ./README.md --scanner aig --sandbox off --json
```

For a directory target, ClawScan uploads a temporary ZIP archive to the A.I.G
service. For a URL target, ClawScan asks A.I.G to scan the URL directly.

An unreachable service should fail clearly in the scanner result, for example
with an `AI-Infra-Guard task creation failed` or upload failure message. That is
expected when `AIG_BASE_URL` is wrong or the service is not running.

## Benchmark Runs

The benchmark workflow forwards `AIG_*` environment variables to ClawScan, but it
does not start an A.I.G sidecar. Use `--scanner aig` in benchmark runs only when
`AIG_BASE_URL` points at an already-running private service.

Keep benchmark artifacts secret-safe:

- Do not print A.I.G API keys or model keys.
- Do not expose a no-auth A.I.G service publicly.
- Prefer private runners or private network access for live A.I.G benchmark
  runs.
