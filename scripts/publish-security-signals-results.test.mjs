import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chownSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readlinkSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const scriptPath = fileURLToPath(new URL('./publish-security-signals-results.sh', import.meta.url));

function fixture(t, { submission = true } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'clawscan-publish-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const bin = join(root, 'bin');
  mkdirSync(bin);
  writeFileSync(join(bin, 'hf'), '#!/bin/sh\nprintf "%s\\n" "$@" > "$HF_ARGS_FILE"\n', { mode: 0o755 });
  const argsFile = join(root, 'hf-args');
  const output = join(root, 'results.jsonl');
  const submissions = join(root, 'submissions');
  const score = { verificationStatus: 'artifact-validated', metrics: { caseCount: 1 } };
  if (submission) {
    const dir = join(submissions, 'example');
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'metadata.json'), '{}');
    writeFileSync(join(dir, 'predictions.jsonl'), '{"id":"one","prediction":"clean"}\n');
  }
  writeFileSync(join(bin, 'score'), `#!/bin/sh
test -f "$1/predictions.jsonl" && test "$2" = --json || exit 1
printf '%s\\n' '${JSON.stringify(score)}'
`, { mode: 0o755 });
  return {
    argsFile,
    bin,
    output,
    submissions,
    run(mode, token = '') {
      return spawnSync('bash', [scriptPath, mode, '--root', submissions, '--output', output], {
        encoding: 'utf8',
        env: { PATH: `${bin}:/usr/bin:/bin`, HF_TOKEN: token, HF_ARGS_FILE: argsFile, CLAWSCAN_VALIDATE_SUBMISSION_CMD: 'score' },
      });
    },
  };
}

test('publishes through hf without passing credentials in arguments', (t) => {
  const f = fixture(t);
  const result = f.run('--publish', 'fixture');
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(readFileSync(f.argsFile, 'utf8').trim().split('\n'), [
    'upload', 'OpenClaw/clawhub-security-signals-results', f.output, 'results.jsonl', '--repo-type', 'dataset',
  ]);
  const row = JSON.parse(readFileSync(f.output, 'utf8'));
  assert.equal(row.submissionId, 'example');
  assert.deepEqual(row.metrics, { caseCount: 1 });
});

test('dry run writes an empty local payload without invoking hf', (t) => {
  const f = fixture(t, { submission: false });
  const result = f.run('--dry-run');
  assert.equal(result.status, 0, result.stderr);
  assert.equal(readFileSync(f.output, 'utf8'), '');
  assert.equal(existsSync(f.argsFile), false);
});

test('publishing still requires a token', (t) => {
  const f = fixture(t);
  const result = f.run('--publish');
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /HF_TOKEN is required/);
  assert.equal(existsSync(f.argsFile), false);
});

test('refuses to replace results when the submission root has no rows', (t) => {
  const f = fixture(t, { submission: false });
  writeFileSync(f.output, 'previous results\n');
  const result = f.run('--publish', 'fixture');
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /No Security Signals submissions/);
  assert.equal(existsSync(f.argsFile), false);
  assert.equal(readFileSync(f.output, 'utf8'), 'previous results\n');
});

test('a later scoring failure leaves only the last complete payload available', (t) => {
  const f = fixture(t);
  const second = join(f.submissions, 'z-second');
  mkdirSync(second);
  writeFileSync(join(second, 'metadata.json'), '{}');
  writeFileSync(join(second, 'predictions.jsonl'), '{"id":"two","prediction":"clean"}\n');
  writeFileSync(join(f.bin, 'score'), `#!/bin/sh
case "$1" in */z-second) echo 'benchmark rows unavailable' >&2; exit 1 ;; esac
echo '{"metrics":{"caseCount":1}}'
`, { mode: 0o755 });

  const failed = () => {
    const result = f.run('--publish', 'fixture');
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /benchmark rows unavailable/);
    assert.equal(existsSync(f.argsFile), false);
  };
  failed();
  assert.equal(existsSync(f.output), false);

  writeFileSync(f.output, 'previous results\n');
  failed();
  assert.equal(readFileSync(f.output, 'utf8'), 'previous results\n');
});

test('a failed directory listing cannot publish the rows found so far', (t) => {
  const f = fixture(t);
  writeFileSync(join(f.bin, 'find'), '#!/bin/sh\nprintf "%s\\0" "$1/example/metadata.json"\nexit 1\n', { mode: 0o755 });
  const result = f.run('--publish', 'fixture');
  assert.notEqual(result.status, 0);
  assert.equal(existsSync(f.argsFile), false);
  assert.equal(existsSync(f.output), false);
});

test('successful replacement preserves a linked output and its file permissions', (t) => {
  const f = fixture(t);
  const target = join(f.submissions, 'last-complete.jsonl');
  writeFileSync(target, 'previous results\n', { mode: 0o640 });
  symlinkSync(target, f.output);
  const group = process.getgroups().find((gid) => gid !== statSync(target).gid);
  if (group !== undefined) chownSync(target, process.getuid(), group);
  const before = statSync(target);
  const result = f.run('--dry-run');
  assert.equal(result.status, 0, result.stderr);
  assert.equal(readlinkSync(f.output), target);
  const after = statSync(target);
  assert.deepEqual([after.uid, after.gid, after.mode], [before.uid, before.gid, before.mode]);
  assert.equal(JSON.parse(readFileSync(target, 'utf8')).submissionId, 'example');
});
