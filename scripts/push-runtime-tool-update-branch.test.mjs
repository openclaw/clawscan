import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const scriptPath = fileURLToPath(new URL('./push-runtime-tool-update-branch.sh', import.meta.url));
const workflowPath = fileURLToPath(
  new URL('../.github/workflows/runtime-tool-updates.yml', import.meta.url),
);
const gitPath = execFileSync('sh', ['-c', 'command -v git'], { encoding: 'utf8' }).trim();
const branch = 'automation/runtime-tool-updates';

function git(cwd, ...args) {
  return execFileSync(gitPath, args, { cwd, encoding: 'utf8' }).trim();
}

function commitFile(repo, name, content, message) {
  writeFileSync(join(repo, name), content);
  git(repo, 'add', name);
  git(repo, 'commit', '-m', message);
  return git(repo, 'rev-parse', 'HEAD');
}

function createFixture({ existingBranch }) {
  const root = mkdtempSync(join(tmpdir(), 'clawscan-runtime-lease-'));
  const remote = join(root, 'remote.git');
  const seed = join(root, 'seed');
  const worker = join(root, 'worker');

  mkdirSync(seed);
  git(root, 'init', '--bare', remote);
  git(seed, 'init');
  git(seed, 'config', 'user.name', 'Test Seed');
  git(seed, 'config', 'user.email', 'seed@example.com');
  commitFile(seed, 'README.md', 'main\n', 'initial main');
  git(seed, 'branch', '-M', 'main');
  git(seed, 'remote', 'add', 'origin', remote);
  git(seed, 'push', '-u', 'origin', 'main');

  if (existingBranch) {
    git(seed, 'switch', '-c', branch);
    commitFile(seed, 'runtime.txt', 'old\n', 'old runtime update');
    git(seed, 'push', 'origin', `HEAD:refs/heads/${branch}`);
    git(seed, 'switch', 'main');
  }

  git(root, 'clone', '--branch', 'main', remote, worker);
  git(worker, 'config', 'user.name', 'Test Worker');
  git(worker, 'config', 'user.email', 'worker@example.com');
  const workerHead = commitFile(worker, 'runtime.txt', 'new\n', 'new runtime update');

  return { root, remote, worker, workerHead };
}

function runPush(worker, env = process.env) {
  return spawnSync('bash', [scriptPath, 'origin', branch], {
    cwd: worker,
    env,
    encoding: 'utf8',
  });
}

function remoteHead(remote) {
  return git(remote, 'rev-parse', `refs/heads/${branch}`);
}

function installRacingHook(fixture, { branchExists }) {
  const racer = join(fixture.root, 'racer');
  git(fixture.root, 'clone', '--branch', branchExists ? branch : 'main', fixture.remote, racer);
  git(racer, 'config', 'user.name', 'Test Racer');
  git(racer, 'config', 'user.email', 'racer@example.com');
  if (!branchExists) {
    git(racer, 'switch', '-c', branch);
  }
  const racerHead = commitFile(racer, 'race.txt', 'race\n', 'competing runtime update');

  const hook = join(fixture.worker, '.git', 'hooks', 'pre-push');
  writeFileSync(
    hook,
    `#!/bin/sh\nset -eu\n"${gitPath}" -C "${racer}" push origin HEAD:refs/heads/${branch} >/dev/null\n`,
  );
  chmodSync(hook, 0o755);
  return racerHead;
}

function installFetchRaceWrapper(fixture) {
  const racer = join(fixture.root, 'fetch-racer');
  git(fixture.root, 'clone', '--branch', branch, fixture.remote, racer);
  git(racer, 'config', 'user.name', 'Test Fetch Racer');
  git(racer, 'config', 'user.email', 'fetch-racer@example.com');
  const racerHead = commitFile(racer, 'fetch-race.txt', 'race\n', 'competing fetch-time update');

  const bin = join(fixture.root, 'bin');
  const marker = join(fixture.root, 'fetch-race-fired');
  mkdirSync(bin);
  const wrapper = join(bin, 'git');
  writeFileSync(
    wrapper,
    `#!/bin/sh
set -eu
if [ "\${1:-}" = "fetch" ] && [ ! -e "${marker}" ]; then
  : > "${marker}"
  "${gitPath}" -C "${racer}" push origin HEAD:refs/heads/${branch} >/dev/null
fi
exec "${gitPath}" "$@"
`,
  );
  chmodSync(wrapper, 0o755);
  return {
    env: { ...process.env, PATH: `${bin}:${process.env.PATH}` },
    racerHead,
  };
}

test('creates the automation branch only while it remains absent', () => {
  const fixture = createFixture({ existingBranch: false });
  try {
    const result = runPush(fixture.worker);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(remoteHead(fixture.remote), fixture.workerHead);
  } finally {
    rmSync(fixture.root, { recursive: true, force: true });
  }
});

test('replaces the observed automation branch tip', () => {
  const fixture = createFixture({ existingBranch: true });
  try {
    const result = runPush(fixture.worker);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(remoteHead(fixture.remote), fixture.workerHead);
  } finally {
    rmSync(fixture.root, { recursive: true, force: true });
  }
});

test('rejects a competing update after observing an existing branch', () => {
  const fixture = createFixture({ existingBranch: true });
  try {
    const racerHead = installRacingHook(fixture, { branchExists: true });
    const result = runPush(fixture.worker);
    assert.notEqual(result.status, 0);
    assert.equal(remoteHead(fixture.remote), racerHead);
  } finally {
    rmSync(fixture.root, { recursive: true, force: true });
  }
});

test('rejects a competing update between observation and fetch', () => {
  const fixture = createFixture({ existingBranch: true });
  try {
    const race = installFetchRaceWrapper(fixture);
    const result = runPush(fixture.worker, race.env);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /changed while its lease was being prepared/u);
    assert.equal(remoteHead(fixture.remote), race.racerHead);
  } finally {
    rmSync(fixture.root, { recursive: true, force: true });
  }
});

test('rejects a competing branch creation after observing it absent', () => {
  const fixture = createFixture({ existingBranch: false });
  try {
    const racerHead = installRacingHook(fixture, { branchExists: false });
    const result = runPush(fixture.worker);
    assert.notEqual(result.status, 0);
    assert.equal(remoteHead(fixture.remote), racerHead);
  } finally {
    rmSync(fixture.root, { recursive: true, force: true });
  }
});

test('workflow serializes writers and delegates the guarded push', () => {
  const workflow = readFileSync(workflowPath, 'utf8');
  assert.match(workflow, /group: runtime-tool-updates/u);
  assert.match(workflow, /cancel-in-progress: false/u);
  assert.match(workflow, /scripts\/push-runtime-tool-update-branch\.sh origin "\$BRANCH"/u);
  assert.doesNotMatch(workflow, /git push --force-with-lease origin "\$BRANCH"/u);
});
