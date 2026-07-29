# ClawScan Install Gate for OpenClaw

`@openclaw/clawscan-plugin` registers OpenClaw's `before_install` hook and
fails closed when ClawScan cannot produce a trustworthy gate artifact.

This package requires OpenClaw's
[cold install-provider contract](https://github.com/openclaw/openclaw/pull/115197),
which discovers explicitly trusted `before_install` providers before both CLI
and Gateway install/update operations. Earlier prerelease builds that only run
hooks already loaded in the current process are not supported.

Install the plugin through OpenClaw:

```sh
openclaw plugins install @openclaw/clawscan-plugin
```

That operator action explicitly trusts and enables this config-free plugin by
writing `plugins.entries.clawscan.enabled=true` and adding `clawscan` to
`plugins.allow` when the allowlist is configured. If the package is placed by
another mechanism, run `openclaw plugins enable clawscan` and ensure the
allowlist includes `clawscan` before relying on the install hook.

By default, every candidate skill or plugin is scanned with SkillSpector
(`CLAWSCAN_SKILLSPECTOR_LLM=0`) and `clawscan-static` inside ClawScan's Docker
sandbox. This no-LLM mode does not send source files to a model provider, but
SkillSpector still sends dependency names to [OSV.dev](https://osv.dev/) for
CVE lookups.

If Docker mode is unavailable on the host, including on native Windows, the
plugin visibly reports that the gate is degraded and runs only
`clawscan-static` with the sandbox disabled. This fallback is a small static
tripwire, not equivalent protection.

The plugin accepts only an explicit `configPath` and `profile`. Relative config
paths resolve from the plugin directory; the untrusted candidate directory is
never searched for ClawScan configuration.

The gate cannot scan its own first installation because its hook is not active
yet. Enable it immediately after installation. Once enabled, it scans
subsequent updates, including updates to itself.
