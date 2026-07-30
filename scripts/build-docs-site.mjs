import { cp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const docsDir = path.join(root, 'docs');
const assetsDir = path.join(docsDir, 'assets');
const outDir = path.join(root, 'dist', 'docs-site');
const outAssetsDir = path.join(outDir, 'assets');
const pages = [
  ['index.md', 'Introduction'],
  ['scanners.md', 'Scanners'],
  ['profiles.md', 'Profiles'],
  ['judge.md', 'Judge'],
  ['sandbox.md', 'Sandbox'],
  ['benchmarks.md', 'Benchmarks'],
];

const navSections = [
  ['Start', ['index.md']],
  ['Workflow', ['scanners.md', 'profiles.md', 'judge.md', 'sandbox.md']],
  ['Evaluate', ['benchmarks.md']],
];

await rm(outDir, { recursive: true, force: true });
await mkdir(outDir, { recursive: true });
await cp(assetsDir, outAssetsDir, { recursive: true });
await writeFile(path.join(outDir, '.nojekyll'), '');

for (const [file, title] of pages) {
  const markdown = await readFile(path.join(docsDir, file), 'utf8');
  const html = pageShell(file, title, renderMarkdown(markdown));
  const outputFile = file.replace(/\.md$/, '.html');
  await writeFile(path.join(outDir, outputFile), html);
}

console.log(`Built ${pages.length} docs page(s) in ${path.relative(root, outDir)}`);

function pageShell(currentFile, title, body) {
  const pageMap = new Map(pages);
  const nav = navSections
    .map(([section, files]) => {
      const links = files
        .map((file) => {
          const label = pageMap.get(file);
          const href = file.replace(/\.md$/, '.html');
          const current = file === currentFile ? ' current' : '';
          const currentPage = file === currentFile ? ' aria-current="page"' : '';
          return `<a class="nav-link${current}" href="${href}"${currentPage}>${escapeHtml(label)}</a>`;
        })
        .join('');
      return `<section><h2>${escapeHtml(section)}</h2>${links}</section>`;
    })
    .join('\n');
  const currentIndex = pages.findIndex(([file]) => file === currentFile);
  const pageNav = renderPageNav(pages[currentIndex - 1], pages[currentIndex + 1]);
  const toc = renderToc(body);
  const isHome = currentFile === 'index.md';
  const sectionName =
    navSections.find(([, files]) => files.includes(currentFile))?.[0] ?? 'Documentation';
  const pageIntro = isHome ? renderHomeIntro() : renderPageHeading(title, sectionName);
  const bodyClass = isHome ? 'oc-app-surface home' : 'oc-app-surface docs-page';

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)} · ClawScan Docs</title>
  <meta name="description" content="ClawScan is an open, benchmarkable security scanning harness for agent skills.">
  <meta name="theme-color" content="#f6f5f3" media="(prefers-color-scheme: light)">
  <meta name="theme-color" content="#101012" media="(prefers-color-scheme: dark)">
  <meta property="og:image" content="assets/clawscan-banner.png">
  <link rel="icon" href="assets/clawscan-logo.png" type="image/png">
  <link rel="apple-touch-icon" href="assets/clawscan-logo.png">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Instrument+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
  <script>(function(){var s;try{s=localStorage.getItem('clawscan-theme')}catch(e){}var d=window.matchMedia&&matchMedia('(prefers-color-scheme: dark)').matches;document.documentElement.dataset.theme=s||(d?'dark':'light')})();</script>
  <link rel="stylesheet" href="assets/carapace/tokens.css">
  <link rel="stylesheet" href="assets/carapace/themes.css">
  <link rel="stylesheet" href="assets/carapace/typography.css">
  <link rel="stylesheet" href="assets/carapace/components.css">
  <link rel="stylesheet" href="assets/site.css">
  <script src="assets/site.js" defer></script>
</head>
<body class="${bodyClass}">
  <a class="skip-link oc-action oc-action-primary" href="#main-content">Skip to content</a>
  <header class="topbar">
    <a class="brand" href="index.html" aria-label="ClawScan documentation home">
      <img class="brand-mark" src="assets/clawscan-logo.png" alt="" width="29" height="29" aria-hidden="true">
      <span class="brand-product">ClawScan</span>
      <span class="brand-divider" aria-hidden="true">/</span>
      <span class="brand-section">docs</span>
    </a>
    <div class="topbar-center">
      <button class="install-command" type="button" data-copy-install aria-label="Copy npm install command">
        <span class="install-prompt" aria-hidden="true">$</span>
        <code>npm install -g @openclaw/clawscan</code>
        <span class="install-copy" aria-hidden="true">Copy</span>
      </button>
    </div>
    <div class="topbar-actions">
      <a class="source-link oc-action oc-action-ghost" href="https://github.com/openclaw/clawscan" rel="noopener">
        <svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M12 2a10 10 0 0 0-3.16 19.49c.5.09.68-.22.68-.48v-1.9c-2.78.6-3.37-1.18-3.37-1.18-.45-1.16-1.11-1.47-1.11-1.47-.91-.62.07-.61.07-.61 1 .07 1.53 1.03 1.53 1.03.9 1.53 2.35 1.09 2.92.83.09-.65.35-1.09.64-1.34-2.22-.25-4.56-1.11-4.56-4.94 0-1.09.39-1.98 1.03-2.68-.1-.25-.45-1.27.1-2.64 0 0 .84-.27 2.75 1.02A9.6 9.6 0 0 1 12 6.79a9.6 9.6 0 0 1 2.5.34c1.91-1.29 2.75-1.02 2.75-1.02.55 1.37.2 2.39.1 2.64.64.7 1.03 1.59 1.03 2.68 0 3.84-2.34 4.68-4.57 4.93.36.31.68.92.68 1.86V21c0 .27.18.58.69.48A10 10 0 0 0 12 2Z"/></svg>
        <span>Source</span>
      </a>
      <button class="icon-button" type="button" data-theme-toggle aria-label="Switch color theme" aria-pressed="false">
        <svg class="theme-icon-moon" viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M20.1 15.5A8.5 8.5 0 0 1 8.5 3.9 8.5 8.5 0 1 0 20.1 15.5Z"/></svg>
        <svg class="theme-icon-sun" viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8Zm0-6 1 3h-2l1-3Zm0 20-1-3h2l-1 3ZM2 12l3-1v2l-3-1Zm20 0-3 1v-2l3 1ZM4.9 4.9l2.8 1.4-1.4 1.4-1.4-2.8Zm14.2 14.2-2.8-1.4 1.4-1.4 1.4 2.8Zm0-14.2-1.4 2.8-1.4-1.4 2.8-1.4ZM4.9 19.1l1.4-2.8 1.4 1.4-2.8 1.4Z"/></svg>
      </button>
      <button class="nav-toggle" type="button" aria-label="Toggle documentation navigation" aria-expanded="false" aria-controls="docs-sidebar">
        <svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M4 6h16v2H4V6Zm0 5h16v2H4v-2Zm0 5h16v2H4v-2Z"/></svg>
      </button>
    </div>
  </header>
  <aside class="sidebar" id="docs-sidebar">
    <div class="sidebar-inner">
      <p class="sidebar-kicker">Documentation</p>
      <label class="search" for="doc-search">
        <svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="m20.7 19.3-4.1-4.1a7.5 7.5 0 1 0-1.4 1.4l4.1 4.1 1.4-1.4ZM5 11a6 6 0 1 1 12 0 6 6 0 0 1-12 0Z"/></svg>
        <input id="doc-search" type="search" placeholder="Filter docs…" autocomplete="off">
      </label>
      <nav class="docs-nav" aria-label="Documentation">
${nav}
      </nav>
    </div>
  </aside>
  <button class="sidebar-overlay" type="button" aria-label="Close documentation navigation" hidden></button>
  <main class="site-main" id="main-content">
    <div class="page-frame">
${pageIntro}
      <div class="doc-grid">
        <article class="doc">
${body}
${pageNav}
        </article>
${toc}
      </div>
    </div>
  </main>
</body>
</html>
`;
}

function renderPageHeading(title, section) {
  return `<header class="page-heading">
  <nav class="breadcrumb" aria-label="Breadcrumb">
    <a href="index.html">Docs</a>
    <span aria-hidden="true">/</span>
    <span>${escapeHtml(section)}</span>
  </nav>
  <h1>${escapeHtml(title)}</h1>
</header>`;
}

function renderHomeIntro() {
  return `<section class="home-hero" aria-labelledby="home-title">
  <div class="home-hero-copy">
    <p class="oc-eyebrow">OpenClaw security / ClawScan</p>
    <h1 id="home-title">Scan the skill.<br><span>Keep the evidence.</span></h1>
    <p class="home-lede">Run multiple agent-skill scanners, preserve their raw findings, and add an optional judge—without hiding what each tool actually reported.</p>
    <div class="home-actions">
      <a class="oc-action oc-action-primary" href="#quick-start">Install ClawScan</a>
      <a class="oc-action oc-action-secondary" href="scanners.html">Explore scanners</a>
    </div>
    <div class="home-proof" aria-label="ClawScan capabilities">
      <span><i aria-hidden="true"></i>Composable scanners</span>
      <span><i aria-hidden="true"></i>Raw JSON evidence</span>
      <span><i aria-hidden="true"></i>Benchmarkable profiles</span>
    </div>
  </div>
  <div class="scan-console" aria-label="Example ClawScan run">
    <div class="scan-console-head">
      <span>Example run</span>
      <span class="window-dots" aria-hidden="true"><i></i><i></i><i></i></span>
    </div>
    <div class="scan-console-command"><b>$</b> clawscan ./my-skill<br>&nbsp;&nbsp;--scanner skillspector --scanner cisco</div>
    <div class="scan-console-row"><span>skillspector</span><strong>completed</strong></div>
    <div class="scan-console-row"><span>cisco</span><strong>completed</strong></div>
    <div class="scan-console-result">
      <div><small>targets</small><strong>1</strong></div>
      <div><small>scanners</small><strong>2</strong></div>
      <div><small>artifact</small><strong>JSON</strong></div>
    </div>
  </div>
</section>
<section class="pipeline" aria-label="ClawScan pipeline">
  <div class="pipeline-step"><small>01 / Input</small><strong>Agent skill</strong></div>
  <div class="pipeline-step"><small>02 / Inspect</small><strong>Scanner suite</strong></div>
  <div class="pipeline-step"><small>03 / Preserve</small><strong>Raw evidence</strong></div>
  <div class="pipeline-step"><small>04 / Decide</small><strong>Optional judge</strong></div>
</section>
<nav class="home-cards" aria-label="Start with ClawScan">
  <a class="home-card oc-card oc-card-interactive" href="scanners.html">
    <small>Scanner catalog</small>
    <svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="m8 5 7 7-7 7 1.4 1.4 8.4-8.4-8.4-8.4L8 5Z"/></svg>
    <strong>Choose what inspects your skill.</strong>
  </a>
  <a class="home-card oc-card oc-card-interactive" href="profiles.html">
    <small>Profiles</small>
    <svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="m8 5 7 7-7 7 1.4 1.4 8.4-8.4-8.4-8.4L8 5Z"/></svg>
    <strong>Save a repeatable scan setup.</strong>
  </a>
  <a class="home-card oc-card oc-card-interactive" href="benchmarks.html">
    <small>Benchmarks</small>
    <svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="m8 5 7 7-7 7 1.4 1.4 8.4-8.4-8.4-8.4L8 5Z"/></svg>
    <strong>Measure the setup against known data.</strong>
  </a>
</nav>`;
}

function renderPageNav(previousPage, nextPage) {
  if (!previousPage && !nextPage) {
    return '';
  }
  const previous = previousPage
    ? `<a class="page-nav-prev oc-card oc-card-interactive" href="${previousPage[0].replace(/\.md$/, '.html')}"><small>Previous</small><span>${escapeHtml(previousPage[1])}</span></a>`
    : '';
  const next = nextPage
    ? `<a class="page-nav-next oc-card oc-card-interactive" href="${nextPage[0].replace(/\.md$/, '.html')}"><small>Next</small><span>${escapeHtml(nextPage[1])}</span></a>`
    : '';
  return `<nav class="page-nav" aria-label="Page navigation">${previous}${next}</nav>`;
}

function renderToc(body) {
  const headings = [...body.matchAll(/<h([23]) id="([^"]+)">(.+?)<\/h\1>/g)].slice(0, 12);
  if (headings.length === 0) {
    return '';
  }
  const links = headings
    .map((heading) => {
      const className = heading[1] === '3' ? ' class="toc-l3"' : '';
      return `<a${className} href="#${heading[2]}">${stripTags(heading[3])}</a>`;
    })
    .join('');
  return `<aside class="toc" aria-label="On this page"><h2>On This Page</h2>${links}</aside>`;
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

    if (/^<\/?details\b[^>]*>$/.test(line.trim()) || /^<summary\b[^>]*>.*<\/summary>$/.test(line.trim())) {
      flushAll();
      out.push(line.trim());
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
  rendered = rendered.replace(/&lt;(\/?(?:details|summary|code))&gt;/g, '<$1>');
  rendered = rendered.replace(/&lt;br&gt;/g, '<br>');
  rendered = rendered.replace(/`([^`]+)`/g, '<code>$1</code>');
  rendered = rendered.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  rendered = rendered.replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_match, label, href) => {
    const rewritten = href.replace(/^docs\//, '').replace(/\.md(#.*)?$/, '.html$1');
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
  return `<div class="table-scroll" tabindex="0" role="region" aria-label="Scrollable data table"><table>${head}<tbody>${rowsHtml}</tbody></table></div>`;
}

function parseTableRow(line) {
  const trimmed = line.trim().replace(/^\|/, '').replace(/\|$/, '');
  const cells = [];
  let cell = '';
  let escaped = false;
  for (const char of trimmed) {
    if (escaped) {
      if (char === '|') {
        cell += '|';
      } else {
        cell += `\\${char}`;
      }
      escaped = false;
      continue;
    }
    if (char === '\\') {
      escaped = true;
      continue;
    }
    if (char === '|') {
      cells.push(cell.trim());
      cell = '';
      continue;
    }
    cell += char;
  }
  if (escaped) {
    cell += '\\';
  }
  cells.push(cell.trim());
  return cells;
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

function stripTags(value) {
  return String(value).replace(/<[^>]+>/g, '');
}
