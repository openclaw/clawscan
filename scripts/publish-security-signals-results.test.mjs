import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
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
    output,
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
