# Building npm packages

The default build produces the universal `@openclaw/clawscan` package with all
six supported binaries:

```sh
node scripts/build-npm-package.mjs --version v0.0.0 --pack --smoke
```

Use `--platform` to build a smaller tarball containing one binary. For example:

```sh
node scripts/build-npm-package.mjs --version v0.0.0 --platform linux-x64 --out dist/npm-linux-x64 --pack
npm install --global ./dist/npm-linux-x64/openclaw-clawscan-linux-x64-0.0.0.tgz
clawscan --version
```

Supported values are `darwin-x64`, `darwin-arm64`, `linux-x64`, `linux-arm64`,
`win32-x64`, and `win32-arm64`. The package name is
`@openclaw/clawscan-<platform>`, and its `os` and `cpu` fields restrict installation
to that platform. Each package keeps the `clawscan` command and the
`./resolve-binary` export, with its binary under `binaries/<platform>/`.

Use a distinct `--out` directory to retain multiple builds; each build replaces
its output directory. Add `--smoke` when building for the current host to install
the tarball in a temporary prefix and run `--version` and a static scan.

The platform-specific tarballs are local build artifacts. Registry publication
still uses the universal package; publishing the additional names requires their
registry bootstrap, trusted-publisher setup, and release-workflow integration.
