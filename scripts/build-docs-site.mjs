import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const docsDir = path.join(root, 'docs');
const outDir = path.join(root, 'dist', 'docs-site');

const pages = [
  ['index.md', 'Overview'],
  ['quickstart.md', 'Quickstart'],
  ['scanners.md', 'Scanners'],
  ['judge.md', 'Judge'],
  ['benchmarks.md', 'Benchmarks'],
  ['artifacts.md', 'Artifacts'],
  ['development.md', 'Development'],
];

const css = `
:root {
  color-scheme: light dark;
  --bg: #f8fafc;
  --fg: #152033;
  --muted: #5d6a7e;
  --line: #d9e1ec;
  --panel: #ffffff;
  --accent: #0969da;
  --code: #eef3f8;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0e1117;
    --fg: #e6edf3;
    --muted: #98a6b8;
    --line: #2d3746;
    --panel: #151b23;
    --accent: #58a6ff;
    --code: #1f2937;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--fg);
  font: 16px/1.6 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
.layout {
  display: grid;
  grid-template-columns: 260px minmax(0, 1fr);
  min-height: 100vh;
}
nav {
  border-right: 1px solid var(--line);
  padding: 28px 22px;
  background: var(--panel);
}
.brand {
  display: block;
  color: var(--fg);
  font-weight: 760;
  font-size: 20px;
  margin-bottom: 20px;
}
nav ul { list-style: none; margin: 0; padding: 0; }
nav li { margin: 4px 0; }
nav a {
  display: block;
  border-radius: 7px;
  color: var(--muted);
  padding: 8px 10px;
}
nav a.current {
  background: var(--code);
  color: var(--fg);
  font-weight: 650;
}
main {
  width: min(920px, 100%);
  padding: 44px 32px 80px;
}
h1, h2, h3 { line-height: 1.2; margin: 1.8em 0 0.55em; }
h1 { font-size: 38px; margin-top: 0; }
h2 { font-size: 26px; border-top: 1px solid var(--line); padding-top: 1.1em; }
h3 { font-size: 20px; }
p, ul, ol, table, pre { margin: 0 0 1.15em; }
ul, ol { padding-left: 1.45em; }
code {
  background: var(--code);
  border-radius: 5px;
  padding: 0.12em 0.32em;
  font-size: 0.92em;
}
pre {
  overflow-x: auto;
  background: var(--code);
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 15px 16px;
}
pre code {
  background: transparent;
  border-radius: 0;
  padding: 0;
}
table {
  border-collapse: collapse;
  display: block;
  overflow-x: auto;
}
th, td {
  border: 1px solid var(--line);
  padding: 8px 10px;
  vertical-align: top;
}
th {
  background: var(--code);
  text-align: left;
}
blockquote {
  border-left: 4px solid var(--line);
  color: var(--muted);
  margin: 0 0 1.15em;
  padding-left: 14px;
}
@media (max-width: 760px) {
  .layout { display: block; }
  nav {
    border-right: 0;
    border-bottom: 1px solid var(--line);
    padding: 18px;
  }
  nav ul {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
  }
  main { padding: 30px 20px 64px; }
  h1 { font-size: 32px; }
}
`;

await mkdir(outDir, { recursive: true });
await writeFile(path.join(outDir, 'style.css'), css.trimStart());
await writeFile(path.join(outDir, '.nojekyll'), '');

for (const [file, title] of pages) {
  const markdown = await readFile(path.join(docsDir, file), 'utf8');
  const html = pageShell(file, title, renderMarkdown(markdown));
  const outputFile = file.replace(/\.md$/, '.html');
  await writeFile(path.join(outDir, outputFile), html);
}

console.log(`Built ${pages.length} docs page(s) in ${path.relative(root, outDir)}`);

function pageShell(currentFile, title, body) {
  const nav = pages
    .map(([file, label]) => {
      const href = file.replace(/\.md$/, '.html');
      const current = file === currentFile ? ' class="current"' : '';
      return `<li><a${current} href="${href}">${escapeHtml(label)}</a></li>`;
    })
    .join('\n');
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)} - ClawScan</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
  <div class="layout">
    <nav aria-label="Documentation">
      <a class="brand" href="index.html">ClawScan</a>
      <ul>
${nav}
      </ul>
    </nav>
    <main>
${body}
    </main>
  </div>
</body>
</html>
`;
}

function renderMarkdown(markdown) {
  const lines = markdown.replace(/\r\n/g, '\n').split('\n');
  const out = [];
  let paragraph = [];
  let listType = '';
  let inCode = false;
  let codeLanguage = '';
  let codeLines = [];
  let tableRows = [];
  let blockquote = [];
  let lastListItemIndex = -1;

  const flushParagraph = () => {
    if (paragraph.length === 0) {
      return;
    }
    out.push(`<p>${renderInline(paragraph.join(' '))}</p>`);
    paragraph = [];
  };
  const flushList = () => {
    if (!listType) {
      return;
    }
    out.push(`</${listType}>`);
    listType = '';
    lastListItemIndex = -1;
  };
  const flushTable = () => {
    if (tableRows.length === 0) {
      return;
    }
    out.push(renderTable(tableRows));
    tableRows = [];
  };
  const flushBlockquote = () => {
    if (blockquote.length === 0) {
      return;
    }
    out.push(`<blockquote>${blockquote.map((line) => `<p>${renderInline(line)}</p>`).join('')}</blockquote>`);
    blockquote = [];
  };
  const flushAll = () => {
    flushParagraph();
    flushList();
    flushTable();
    flushBlockquote();
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (inCode) {
      if (line.startsWith('```')) {
        out.push(`<pre><code class="language-${escapeHtml(codeLanguage)}">${escapeHtml(codeLines.join('\n'))}</code></pre>`);
        inCode = false;
        codeLanguage = '';
        codeLines = [];
      } else {
        codeLines.push(line);
      }
      continue;
    }

    if (line.startsWith('```')) {
      flushAll();
      inCode = true;
      codeLanguage = line.slice(3).trim();
      continue;
    }

    if (!line.trim()) {
      flushAll();
      continue;
    }

    const heading = /^(#{1,3})\s+(.+)$/.exec(line);
    if (heading) {
      flushAll();
      const level = heading[1].length;
      const text = heading[2].trim();
      out.push(`<h${level} id="${slug(text)}">${renderInline(text)}</h${level}>`);
      continue;
    }

    if (line.startsWith('> ')) {
      flushParagraph();
      flushList();
      flushTable();
      blockquote.push(line.slice(2));
      continue;
    }

    if (isTableLine(line) && isTableSeparator(lines[i + 1] || '')) {
      flushParagraph();
      flushList();
      flushBlockquote();
      tableRows.push(line);
      tableRows.push(lines[i + 1]);
      i++;
      while (isTableLine(lines[i + 1] || '')) {
        tableRows.push(lines[i + 1]);
        i++;
      }
      flushTable();
      continue;
    }

    const unordered = /^-\s+(.+)$/.exec(line);
    if (unordered) {
      flushParagraph();
      flushTable();
      flushBlockquote();
      if (listType !== 'ul') {
        flushList();
        listType = 'ul';
        out.push('<ul>');
      }
      out.push(`<li>${renderInline(unordered[1])}</li>`);
      lastListItemIndex = out.length - 1;
      continue;
    }

    const ordered = /^\d+\.\s+(.+)$/.exec(line);
    if (ordered) {
      flushParagraph();
      flushTable();
      flushBlockquote();
      if (listType !== 'ol') {
        flushList();
        listType = 'ol';
        out.push('<ol>');
      }
      out.push(`<li>${renderInline(ordered[1])}</li>`);
      lastListItemIndex = out.length - 1;
      continue;
    }

    if (listType && lastListItemIndex >= 0 && /^\s{2,}\S/.test(line)) {
      out[lastListItemIndex] = out[lastListItemIndex].replace(
        '</li>',
        ` ${renderInline(line.trim())}</li>`,
      );
      continue;
    }

    flushList();
    flushTable();
    flushBlockquote();
    paragraph.push(line.trim());
  }

  if (inCode) {
    out.push(`<pre><code class="language-${escapeHtml(codeLanguage)}">${escapeHtml(codeLines.join('\n'))}</code></pre>`);
  }
  flushAll();
  return out.join('\n');
}

function renderInline(text) {
  let rendered = escapeHtml(text);
  rendered = rendered.replace(/`([^`]+)`/g, '<code>$1</code>');
  rendered = rendered.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  rendered = rendered.replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_match, label, href) => {
    const rewritten = href.replace(/\.md(#.*)?$/, '.html$1');
    return `<a href="${escapeAttribute(rewritten)}">${label}</a>`;
  });
  return rendered;
}

function renderTable(rows) {
  const parsed = rows.map(parseTableRow);
  const header = parsed[0] || [];
  const body = parsed.slice(2);
  const head = `<thead><tr>${header.map((cell) => `<th>${renderInline(cell)}</th>`).join('')}</tr></thead>`;
  const rowsHtml = body
    .map((row) => `<tr>${row.map((cell) => `<td>${renderInline(cell)}</td>`).join('')}</tr>`)
    .join('');
  return `<table>${head}<tbody>${rowsHtml}</tbody></table>`;
}

function parseTableRow(line) {
  return line
    .trim()
    .replace(/^\|/, '')
    .replace(/\|$/, '')
    .split('|')
    .map((cell) => cell.trim());
}

function isTableLine(line) {
  return /^\s*\|.+\|\s*$/.test(line);
}

function isTableSeparator(line) {
  return /^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?\s*$/.test(line);
}

function slug(text) {
  return text
    .toLowerCase()
    .replace(/`([^`]+)`/g, '$1')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');
}

function escapeAttribute(value) {
  return escapeHtml(value).replaceAll("'", '&#39;');
}
