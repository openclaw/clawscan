import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const scriptPath = fileURLToPath(new URL('./publish-security-signals-results.sh', import.meta.url));

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'clawscan-publish-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const bin = join(root, 'bin');
  mkdirSync(bin);
  writeFileSync(join(bin, 'hf'), '#!/bin/sh\nprintf "%s\\n" "$@" > "$HF_ARGS_FILE"\n', { mode: 0o755 });
  const argsFile = join(root, 'hf-args');
  const output = join(root, 'results.jsonl');
  return {
    argsFile,
    output,
    run(mode, token = '') {
      return spawnSync('bash', [scriptPath, mode, '--root', join(root, 'submissions'), '--output', output], {
        encoding: 'utf8',
        env: { PATH: `${bin}:/usr/bin:/bin`, HF_TOKEN: token, HF_ARGS_FILE: argsFile },
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
  assert.equal(readFileSync(f.output, 'utf8'), '');
});

test('dry run writes a payload without invoking hf', (t) => {
  const f = fixture(t);
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
