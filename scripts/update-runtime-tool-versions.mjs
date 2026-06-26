import { execFileSync } from 'node:child_process';
import { readFile, writeFile } from 'node:fs/promises';

const dockerfilePath = new URL('../docker/clawscan-runtime/Dockerfile', import.meta.url);

const pins = [
  {
    arg: 'SKILLSPECTOR_REF',
    latest: () => gitHead('https://github.com/NVIDIA/skillspector.git'),
  },
  {
    arg: 'CISCO_AI_SKILL_SCANNER_VERSION',
    latest: () => pypiVersion('cisco-ai-skill-scanner'),
  },
  {
    arg: 'SNYK_AGENT_SCAN_VERSION',
    latest: () => pypiVersion('snyk-agent-scan'),
  },
  {
    arg: 'CLAUDE_CODE_VERSION',
    latest: () => npmVersion('@anthropic-ai/claude-code'),
  },
  {
    arg: 'OPENAI_CODEX_VERSION',
    latest: () => npmVersion('@openai/codex'),
  },
  {
    arg: 'AGENTVERUS_SCANNER_VERSION',
    latest: () => npmVersion('agentverus-scanner'),
  },
  {
    arg: 'SOCKET_CLI_VERSION',
    latest: () => npmVersion('socket'),
  },
];

let dockerfile = await readFile(dockerfilePath, 'utf8');
let changed = false;

for (const pin of pins) {
  const latest = await pin.latest();
  const pattern = new RegExp(`^ARG ${pin.arg}=([^\\n]+)$`, 'm');
  const match = dockerfile.match(pattern);
  if (!match) {
    throw new Error(`Missing ${pin.arg} in ${dockerfilePath.pathname}`);
  }
  const current = match[1].trim();
  if (current === latest) {
    console.log(`${pin.arg}: ${current} unchanged`);
    continue;
  }
  console.log(`${pin.arg}: ${current} -> ${latest}`);
  dockerfile = dockerfile.replace(pattern, `ARG ${pin.arg}=${latest}`);
  changed = true;
}

if (changed) {
  await writeFile(dockerfilePath, dockerfile);
} else {
  console.log('Runtime tool pins are already current.');
}

async function npmVersion(name) {
  const response = await fetch(`https://registry.npmjs.org/${encodeURIComponent(name)}/latest`);
  if (!response.ok) {
    throw new Error(`npm metadata fetch failed for ${name}: ${response.status} ${response.statusText}`);
  }
  const metadata = await response.json();
  if (!metadata.version) {
    throw new Error(`npm metadata missing version for ${name}`);
  }
  return metadata.version;
}

async function pypiVersion(name) {
  const response = await fetch(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`);
  if (!response.ok) {
    throw new Error(`PyPI metadata fetch failed for ${name}: ${response.status} ${response.statusText}`);
  }
  const metadata = await response.json();
  if (!metadata.info?.version) {
    throw new Error(`PyPI metadata missing version for ${name}`);
  }
  return metadata.info.version;
}

function gitHead(repo) {
  const output = execFileSync('git', ['ls-remote', repo, 'HEAD'], { encoding: 'utf8' }).trim();
  const [sha] = output.split(/\s+/);
  if (!/^[0-9a-f]{40}$/i.test(sha)) {
    throw new Error(`Could not resolve HEAD for ${repo}: ${output}`);
  }
  return sha;
}
