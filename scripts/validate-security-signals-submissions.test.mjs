import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const script = fileURLToPath(new URL('./validate-security-signals-submissions.sh', import.meta.url));

test('selects submissions at the event base in a depth-two PR checkout', (t) => {
  const root = mkdtempSync(join(tmpdir(), 'clawscan-submission-base-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const source = join(root, 'source');
  const checkout = join(root, 'checkout');
  mkdirSync(source);
  mkdirSync(checkout);
  const env = {
    PATH: process.env.PATH,
    HOME: root,
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_AUTHOR_NAME: 'Fixture',
    GIT_AUTHOR_EMAIL: 'fixture@example.com',
    GIT_COMMITTER_NAME: 'Fixture',
    GIT_COMMITTER_EMAIL: 'fixture@example.com',
  };
  const git = (cwd, ...args) => execFileSync('git', args, { cwd, env, encoding: 'utf8' }).trim();
  git(source, 'init', '-q', '-b', 'main');
  const changed = 'leaderboard/submissions/changed entry';
  const unchanged = 'leaderboard/submissions/base-only';
  for (const dir of [changed, unchanged]) {
    mkdirSync(join(source, dir), { recursive: true });
    writeFileSync(join(source, dir, 'metadata.json'), '{}\n');
    writeFileSync(join(source, dir, 'predictions.jsonl'), '{}\n');
  }
  git(source, 'add', '.');
  git(source, 'commit', '-qm', 'initial submissions');
  git(source, 'checkout', '-qb', 'pr');
  writeFileSync(join(source, changed, 'predictions.jsonl'), '{"pr":true}\n');
  git(source, 'commit', '-qam', 'change submission');
  git(source, 'checkout', '-q', 'main');
  writeFileSync(join(source, unchanged, 'metadata.json'), '{"base":true}\n');
  git(source, 'commit', '-qam', 'advance base');
  const base = git(source, 'rev-parse', 'HEAD');
  git(source, 'merge', '-q', '--no-ff', '-m', 'PR merge', 'pr');

  git(checkout, 'init', '-q');
  git(checkout, 'fetch', '-q', '--depth=2', source, 'main');
  git(checkout, 'checkout', '-q', '--detach', 'FETCH_HEAD');
  assert.equal(git(checkout, 'rev-parse', '--is-shallow-repository'), 'true');
  function validate(sha) {
    return spawnSync('bash', [script], {
      cwd: checkout, encoding: 'utf8',
      env: { ...env, GITHUB_BASE_REF: 'main', CLAWSCAN_SUBMISSION_BASE_SHA: sha, CLAWSCAN_VALIDATE_SUBMISSION_CMD: 'true' },
    });
  }
  const result = validate(base);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.stdout.split('\n').filter((line) => line.startsWith('Validating ')), [`Validating ${changed}`]);
  assert.equal(result.stderr, '');

  const missing = validate('0000000000000000000000000000000000000000');
  assert.notEqual(missing.status, 0);
  assert.doesNotMatch(missing.stdout, /No Security Signals submissions changed/);
});
