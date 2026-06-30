import { copyFile, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const docsDir = path.join(root, 'docs');
const assetsDir = path.join(docsDir, 'assets');
const outDir = path.join(root, 'dist', 'docs-site');
const outAssetsDir = path.join(outDir, 'assets');
const assets = ['clawscan-logo.svg', 'clawscan-logo.png', 'clawscan-banner.svg', 'clawscan-banner.png'];

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
  ['Run', ['scanners.md', 'profiles.md', 'judge.md', 'sandbox.md', 'benchmarks.md']],
];

let css = `
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

css = `
:root {
  color-scheme: light;
  --bg: #f9f9f9;
  --surface: #ffffff;
  --surface-muted: #fafafa;
  --ink: #0a0a0a;
  --ink-soft: #525252;
  --line: rgba(0, 0, 0, 0.08);
  --accent: #dc2626;
  --accent-deep: #b91c1c;
  --accent-subtle: rgba(220, 38, 38, 0.08);
  --code-bg: #101012;
  --code-fg: #f5f5f5;
  --code-inline-bg: rgba(10, 10, 10, 0.05);
  --shadow: 0 18px 46px rgba(10, 10, 10, 0.08);
  --font-display: "Bricolage Grotesque", "Manrope", -apple-system, BlinkMacSystemFont, system-ui, sans-serif;
  --font-body: "Manrope", -apple-system, BlinkMacSystemFont, system-ui, sans-serif;
  --font-mono: "IBM Plex Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
}
:root[data-theme="dark"] {
  color-scheme: dark;
  --bg: #060608;
  --surface: #0e0e10;
  --surface-muted: #131315;
  --ink: #fafafa;
  --ink-soft: #a1a1a1;
  --line: rgba(255, 255, 255, 0.08);
  --accent: #dc2626;
  --accent-deep: #ef4444;
  --accent-subtle: rgba(220, 38, 38, 0.13);
  --code-bg: #050507;
  --code-fg: #f5f5f5;
  --code-inline-bg: rgba(255, 255, 255, 0.07);
  --shadow: 0 18px 50px rgba(0, 0, 0, 0.45);
}
* { box-sizing: border-box; }
html {
  scroll-behavior: smooth;
  scroll-padding-top: 24px;
}
body {
  margin: 0;
  min-height: 100vh;
  background:
    radial-gradient(circle at 52% -10%, color-mix(in srgb, var(--accent) 15%, transparent), transparent 32rem),
    radial-gradient(circle at 92% 14%, color-mix(in srgb, var(--ink) 8%, transparent), transparent 30rem),
    var(--bg);
  color: var(--ink);
  font: 15px/1.65 var(--font-body);
  letter-spacing: 0;
  overflow-x: hidden;
  -webkit-font-smoothing: antialiased;
}
::selection { background: var(--accent); color: #fff; }
a {
  color: var(--accent);
  text-decoration: none;
  transition: color .12s, border-color .12s, background-color .12s;
}
a:hover {
  color: var(--accent-deep);
  text-decoration: underline;
  text-underline-offset: 0.18em;
}
.layout {
  display: grid;
  grid-template-columns: 268px minmax(0, 1fr);
  min-height: 100vh;
}
.sidebar {
  position: sticky;
  top: 0;
  height: 100vh;
  overflow: auto;
  padding: 24px 22px;
  border-right: 1px solid var(--line);
  background: color-mix(in srgb, var(--surface) 88%, transparent);
  backdrop-filter: blur(18px);
  scrollbar-width: thin;
  scrollbar-color: var(--line) transparent;
}
.sidebar-head {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 24px;
}
.brand {
  display: flex;
  align-items: center;
  gap: 11px;
  min-width: 0;
  flex: 1;
  color: var(--ink);
  text-decoration: none;
}
.brand:hover { text-decoration: none; color: var(--ink); }
.brand-mark {
  display: block;
  width: 30px;
  height: 30px;
  flex: 0 0 30px;
  border-radius: 7px;
  object-fit: contain;
}
.brand strong {
  display: block;
  color: var(--ink);
  font: 700 1.04rem/1.1 var(--font-display);
  letter-spacing: 0;
}
.brand small {
  display: block;
  margin-top: 3px;
  color: var(--ink-soft);
  font-size: .74rem;
  line-height: 1.2;
}
.theme-toggle {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 34px;
  height: 34px;
  flex: 0 0 auto;
  padding: 0;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: var(--surface-muted);
  color: var(--ink-soft);
  cursor: pointer;
}
.theme-toggle:hover {
  border-color: color-mix(in srgb, var(--ink) 24%, var(--line));
  color: var(--ink);
}
.theme-toggle svg {
  width: 16px;
  height: 16px;
  display: block;
}
.theme-icon-sun { display: none; }
:root[data-theme="dark"] .theme-icon-moon { display: none; }
:root[data-theme="dark"] .theme-icon-sun { display: block; }
.search {
  display: block;
  margin-bottom: 22px;
}
.search span {
  display: block;
  margin-bottom: 7px;
  color: var(--ink-soft);
  font-size: .7rem;
  font-weight: 700;
  letter-spacing: .02em;
  text-transform: uppercase;
}
.search input {
  width: 100%;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: var(--surface-muted);
  color: var(--ink);
  outline: none;
  padding: 9px 12px;
  font: inherit;
  font-size: .9rem;
}
.search input:focus {
  border-color: color-mix(in srgb, var(--accent) 58%, var(--line));
  box-shadow: 0 0 0 3px var(--accent-subtle);
}
nav section { margin-bottom: 18px; }
nav h2 {
  margin: 0 0 6px;
  color: var(--ink-soft);
  font-size: .68rem;
  font-weight: 700;
  letter-spacing: .02em;
  text-transform: uppercase;
}
.nav-link {
  display: block;
  margin: 1px 0;
  border-radius: 6px;
  color: var(--ink-soft);
  padding: 5px 10px;
  font-size: .9rem;
  line-height: 1.42;
}
.nav-link:hover {
  background: color-mix(in srgb, var(--ink) 5%, transparent);
  color: var(--ink);
  text-decoration: none;
}
.nav-link.current {
  background: var(--accent-subtle);
  color: var(--accent-deep);
  font-weight: 700;
}
.nav-toggle {
  display: none;
  position: fixed;
  top: calc(14px + env(safe-area-inset-top, 0px));
  right: calc(14px + env(safe-area-inset-right, 0px));
  z-index: 20;
  width: 40px;
  height: 40px;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: var(--surface);
  color: var(--ink);
  cursor: pointer;
  padding: 10px 9px;
  box-shadow: var(--shadow);
  flex-direction: column;
  justify-content: space-between;
}
.nav-toggle span {
  display: block;
  width: 100%;
  height: 2px;
  border-radius: 2px;
  background: currentColor;
  transition: transform .18s, opacity .18s;
}
.nav-toggle[aria-expanded="true"] span:nth-child(1) { transform: translateY(8px) rotate(45deg); }
.nav-toggle[aria-expanded="true"] span:nth-child(2) { opacity: 0; }
.nav-toggle[aria-expanded="true"] span:nth-child(3) { transform: translateY(-8px) rotate(-45deg); }
main {
  min-width: 0;
  width: 100%;
  max-width: 1180px;
  margin: 0 auto;
  padding: 32px clamp(20px, 4.5vw, 56px) 80px;
}
.hero {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 22px;
  flex-wrap: wrap;
  border-bottom: 1px solid var(--line);
  padding: 8px 0 22px;
  margin-bottom: 24px;
}
.eyebrow {
  margin: 0 0 8px;
  color: var(--ink-soft);
  font-size: .7rem;
  font-weight: 800;
  letter-spacing: .03em;
  text-transform: uppercase;
}
.hero h1 {
  margin: 0;
  color: var(--ink);
  font: 800 2.3rem/1.06 var(--font-display);
  letter-spacing: 0;
}
.hero-meta {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}
.btn-ghost {
  display: inline-flex;
  align-items: center;
  border: 1px solid var(--line);
  border-radius: 7px;
  background: var(--surface);
  color: var(--ink-soft);
  padding: 6px 11px;
  font-size: .83rem;
  font-weight: 700;
}
.btn-ghost:hover {
  border-color: color-mix(in srgb, var(--ink) 24%, var(--line));
  color: var(--ink);
  text-decoration: none;
}
.doc-grid {
  display: grid;
  grid-template-columns: minmax(0, 72ch) 200px;
  gap: 48px;
  align-items: start;
}
.doc {
  min-width: 0;
  max-width: 72ch;
  overflow-wrap: break-word;
}
.doc h1 {
  margin: 0 0 .45em;
  color: var(--ink);
  font: 800 2.5rem/1.08 var(--font-display);
  letter-spacing: 0;
}
.doc > h1:first-child { display: none; }
.doc h2 {
  position: relative;
  margin: 2em 0 .5em;
  color: var(--ink);
  font: 750 1.45rem/1.18 var(--font-display);
  letter-spacing: 0;
}
.doc h3 {
  position: relative;
  margin: 1.65em 0 .35em;
  color: var(--ink);
  font: 750 1.08rem/1.25 var(--font-display);
}
.doc h1:first-child,
.doc h2:first-child,
.doc h3:first-child { margin-top: 0; }
.doc p,
.doc ul,
.doc ol,
.doc table,
.doc pre { margin: 0 0 1.12em; }
.doc ul,
.doc ol { padding-left: 1.35rem; }
.doc li { margin: .25em 0; }
.doc strong { color: var(--ink); font-weight: 800; }
code { font-family: var(--font-mono); }
.doc code {
  background: var(--code-inline-bg);
  border: 1px solid var(--line);
  border-radius: 5px;
  color: var(--ink);
  padding: .08em .35em;
  font-size: .86em;
}
.doc pre {
  position: relative;
  overflow-x: auto;
  background: var(--code-bg);
  border: 1px solid color-mix(in srgb, var(--line) 75%, #000);
  border-radius: 8px;
  color: var(--code-fg);
  padding: 14px 18px;
  font-size: .86em;
  line-height: 1.62;
  box-shadow: 0 18px 44px rgba(0, 0, 0, .14);
}
.doc pre code {
  display: block;
  background: transparent;
  border: 0;
  border-radius: 0;
  color: inherit;
  font-size: 1em;
  padding: 0;
  white-space: pre;
}
.copy {
  position: absolute;
  top: 8px;
  right: 8px;
  border: 1px solid rgba(255, 255, 255, .16);
  border-radius: 6px;
  background: rgba(255, 255, 255, .08);
  color: var(--code-fg);
  cursor: pointer;
  opacity: 0;
  padding: 4px 9px;
  font: 700 .7rem/1 var(--font-body);
  transition: opacity .12s, background-color .12s;
}
.doc pre:hover .copy,
.copy:focus { opacity: 1; }
.copy:hover { background: rgba(255, 255, 255, .14); }
.copy.copied {
  opacity: 1;
  background: var(--accent);
  border-color: var(--accent);
}
table {
  width: 100%;
  border-collapse: collapse;
  display: block;
  overflow-x: auto;
  font-size: .92em;
}
th, td {
  border-bottom: 1px solid var(--line);
  padding: 9px 10px;
  vertical-align: top;
  text-align: left;
}
th {
  background: color-mix(in srgb, var(--ink) 5%, transparent);
  color: var(--ink);
  font-weight: 800;
}
blockquote {
  margin: 1.35em 0;
  border-left: 3px solid var(--accent);
  border-radius: 0 8px 8px 0;
  background: var(--accent-subtle);
  color: var(--ink);
  padding: 10px 16px;
}
blockquote p:last-child { margin-bottom: 0; }
.toc {
  position: sticky;
  top: 24px;
  max-height: calc(100vh - 48px);
  overflow: auto;
  border-left: 1px solid var(--line);
  padding-left: 14px;
  font-size: .84rem;
}
.toc h2 {
  margin: 0 0 10px;
  color: var(--ink-soft);
  font-size: .66rem;
  font-weight: 800;
  letter-spacing: .03em;
  text-transform: uppercase;
}
.toc a {
  display: block;
  border-left: 2px solid transparent;
  margin-left: -12px;
  padding: 4px 0 4px 10px;
  color: var(--ink-soft);
  line-height: 1.35;
}
.toc a:hover {
  color: var(--ink);
  text-decoration: none;
}
.toc a.active {
  border-left-color: var(--accent);
  color: var(--accent-deep);
  font-weight: 700;
}
.toc-l3 {
  padding-left: 22px !important;
  font-size: .94em;
}
.page-nav {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 14px;
  margin-top: 48px;
  border-top: 1px solid var(--line);
  padding-top: 20px;
}
.page-nav a {
  display: block;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: var(--surface);
  color: var(--ink-soft);
  padding: 13px 16px;
}
.page-nav a:hover {
  border-color: color-mix(in srgb, var(--accent) 48%, var(--line));
  color: var(--ink);
  text-decoration: none;
}
.page-nav small {
  display: block;
  margin-bottom: 5px;
  color: var(--ink-soft);
  font-size: .7rem;
  font-weight: 800;
  letter-spacing: .03em;
  text-transform: uppercase;
}
.page-nav span {
  display: block;
  color: var(--ink);
  font-weight: 800;
  line-height: 1.3;
}
.page-nav-next { text-align: right; grid-column: 2; }
.page-nav-prev:only-child { grid-column: 1; }
@media (max-width: 1179px) {
  .doc-grid { grid-template-columns: minmax(0, 72ch); }
  .toc { display: none; }
}
@media (max-width: 900px) {
  .layout { display: block; }
  .sidebar {
    position: fixed;
    inset: 0 30% 0 0;
    z-index: 15;
    max-width: 320px;
    transform: translateX(-100%);
    background: var(--surface);
    box-shadow: var(--shadow);
    transition: transform .22s ease;
    pointer-events: none;
  }
  .sidebar.open {
    transform: translateX(0);
    pointer-events: auto;
  }
  .nav-toggle { display: flex; }
  main { padding: 64px 18px 56px; }
  .hero h1 { font-size: 1.85rem; }
  .doc h1 { font-size: 2.1rem; }
}
@media (max-width: 520px) {
  main { padding: 60px 14px 48px; }
  .doc pre {
    margin-left: -14px;
    margin-right: -14px;
    border-radius: 0;
    border-left: 0;
    border-right: 0;
  }
  .page-nav { grid-template-columns: 1fr; }
  .page-nav-next { grid-column: 1; text-align: left; }
}
`;

await rm(outDir, { recursive: true, force: true });
await mkdir(outDir, { recursive: true });
await mkdir(outAssetsDir, { recursive: true });
await writeFile(path.join(outDir, 'style.css'), css.trimStart());
await writeFile(path.join(outDir, '.nojekyll'), '');

for (const asset of assets) {
  await copyFile(path.join(assetsDir, asset), path.join(outAssetsDir, asset));
}

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
          return `<a class="nav-link${current}" href="${href}">${escapeHtml(label)}</a>`;
        })
        .join('');
      return `<section><h2>${escapeHtml(section)}</h2>${links}</section>`;
    })
    .join('\n');
  const currentIndex = pages.findIndex(([file]) => file === currentFile);
  const pageNav = renderPageNav(pages[currentIndex - 1], pages[currentIndex + 1]);
  const toc = renderToc(body);
  const homeClass = currentFile === 'index.md' ? ' class="home"' : '';
  const heroTitle = title;
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)} - ClawScan</title>
  <meta name="description" content="ClawScan is an open, benchmarkable security scanning harness for agent skills.">
  <meta property="og:image" content="assets/clawscan-banner.png">
  <link rel="icon" href="assets/clawscan-logo.png" type="image/png">
  <link rel="apple-touch-icon" href="assets/clawscan-logo.png">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:wght@600;700;800&family=IBM+Plex+Mono:wght@400;500;600&family=Manrope:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <script>(function(){var s;try{s=localStorage.getItem('theme')}catch(e){}var d=window.matchMedia&&matchMedia('(prefers-color-scheme: dark)').matches;document.documentElement.dataset.theme=s||(d?'dark':'light')})();</script>
  <link rel="stylesheet" href="style.css">
</head>
<body${homeClass}>
  <button class="nav-toggle" type="button" aria-label="Toggle navigation" aria-expanded="false">
    <span aria-hidden="true"></span><span aria-hidden="true"></span><span aria-hidden="true"></span>
  </button>
  <div class="layout">
    <aside class="sidebar">
      <div class="sidebar-head">
        <a class="brand" href="index.html" aria-label="ClawScan docs home">
          <img class="brand-mark" src="assets/clawscan-logo.png" alt="" width="30" height="30" aria-hidden="true">
          <span><strong>ClawScan</strong><small>Composable security scanning harness for agent skills</small></span>
        </a>
        <button class="theme-toggle" type="button" aria-label="Toggle dark mode" aria-pressed="false" data-theme-toggle>
          <svg class="theme-icon-moon" viewBox="0 0 20 20" aria-hidden="true"><path d="M14.6 12.1A6.5 6.5 0 0 1 7.4 2.7a6.5 6.5 0 1 0 7.2 9.4z" fill="currentColor"/></svg>
          <svg class="theme-icon-sun" viewBox="0 0 20 20" aria-hidden="true"><circle cx="10" cy="10" r="3.4" fill="currentColor"/><g stroke="currentColor" stroke-width="1.6" stroke-linecap="round"><line x1="10" y1="2" x2="10" y2="4"/><line x1="10" y1="16" x2="10" y2="18"/><line x1="2" y1="10" x2="4" y2="10"/><line x1="16" y1="10" x2="18" y2="10"/><line x1="4.2" y1="4.2" x2="5.6" y2="5.6"/><line x1="14.4" y1="14.4" x2="15.8" y2="15.8"/><line x1="4.2" y1="15.8" x2="5.6" y2="14.4"/><line x1="14.4" y1="5.6" x2="15.8" y2="4.2"/></g></svg>
        </button>
      </div>
      <label class="search"><span>Search</span><input id="doc-search" type="search" placeholder="scanners, judge, benchmarks"></label>
      <nav aria-label="Documentation">
${nav}
      </nav>
    </aside>
    <main>
      <header class="hero">
        <div>
          <h1>${escapeHtml(heroTitle)}</h1>
        </div>
        <div class="hero-meta">
          <a class="btn-ghost" href="https://github.com/openclaw/clawscan" rel="noopener">GitHub</a>
          <a class="btn-ghost" href="index.html#quick-start">Quickstart</a>
        </div>
      </header>
      <div class="doc-grid">
        <article class="doc">
${body}
${pageNav}
        </article>
${toc}
      </div>
    </main>
  </div>
  <script>
const themeRoot = document.documentElement;
function applyTheme(mode) {
  themeRoot.dataset.theme = mode;
  document.querySelectorAll('[data-theme-toggle]').forEach((button) => {
    button.setAttribute('aria-pressed', mode === 'dark' ? 'true' : 'false');
  });
}
function storedTheme() {
  try { return localStorage.getItem('theme'); } catch { return null; }
}
function persistTheme(mode) {
  try { localStorage.setItem('theme', mode); } catch {}
}
applyTheme(themeRoot.dataset.theme === 'dark' ? 'dark' : 'light');
document.querySelectorAll('[data-theme-toggle]').forEach((button) => {
  button.addEventListener('click', () => {
    const next = themeRoot.dataset.theme === 'dark' ? 'light' : 'dark';
    applyTheme(next);
    persistTheme(next);
  });
});
const systemDark = window.matchMedia && matchMedia('(prefers-color-scheme: dark)');
function onSystemChange(event) {
  if (storedTheme()) return;
  applyTheme(event.matches ? 'dark' : 'light');
}
if (systemDark) {
  if (systemDark.addEventListener) systemDark.addEventListener('change', onSystemChange);
  else if (systemDark.addListener) systemDark.addListener(onSystemChange);
}
const sidebar = document.querySelector('.sidebar');
const toggle = document.querySelector('.nav-toggle');
const mobileNav = window.matchMedia('(max-width: 900px)');
function setSidebarOpen(open) {
  if (!sidebar || !toggle) return;
  sidebar.classList.toggle('open', open);
  toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
  if (mobileNav.matches) {
    if (open) sidebar.removeAttribute('aria-hidden');
    else sidebar.setAttribute('aria-hidden', 'true');
  } else {
    sidebar.removeAttribute('aria-hidden');
  }
}
setSidebarOpen(false);
toggle?.addEventListener('click', () => setSidebarOpen(!sidebar?.classList.contains('open')));
document.addEventListener('click', (event) => {
  if (!sidebar?.classList.contains('open')) return;
  if (sidebar.contains(event.target) || toggle?.contains(event.target)) return;
  setSidebarOpen(false);
});
document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape') setSidebarOpen(false);
});
if (mobileNav.addEventListener) mobileNav.addEventListener('change', () => setSidebarOpen(false));
else mobileNav.addListener?.(() => setSidebarOpen(false));
const input = document.getElementById('doc-search');
input?.addEventListener('input', () => {
  const query = input.value.trim().toLowerCase();
  document.querySelectorAll('nav section').forEach((section) => {
    let any = false;
    section.querySelectorAll('.nav-link').forEach((link) => {
      const match = !query || link.textContent.toLowerCase().includes(query);
      link.style.display = match ? 'block' : 'none';
      if (match) any = true;
    });
    section.style.display = any ? 'block' : 'none';
  });
});
document.querySelectorAll('.doc pre').forEach((pre) => {
  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'copy';
  button.textContent = 'Copy';
  button.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(pre.querySelector('code')?.textContent ?? '');
      button.textContent = 'Copied';
      button.classList.add('copied');
      setTimeout(() => {
        button.textContent = 'Copy';
        button.classList.remove('copied');
      }, 1400);
    } catch {
      button.textContent = 'Failed';
      setTimeout(() => {
        button.textContent = 'Copy';
      }, 1400);
    }
  });
  pre.appendChild(button);
});
const tocLinks = document.querySelectorAll('.toc a');
if (tocLinks.length) {
  const byElement = new Map();
  tocLinks.forEach((link) => {
    const id = link.getAttribute('href').slice(1);
    const element = document.getElementById(id);
    if (element) byElement.set(element, link);
  });
  const setActive = (link) => {
    tocLinks.forEach((item) => item.classList.remove('active'));
    link.classList.add('active');
  };
  const observer = new IntersectionObserver((entries) => {
    const visible = entries.filter((entry) => entry.isIntersecting).sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
    if (visible.length) {
      const link = byElement.get(visible[0].target);
      if (link) setActive(link);
    }
  }, { rootMargin: '-15% 0px -65% 0px', threshold: 0 });
  byElement.forEach((_link, element) => observer.observe(element));
}
  </script>
</body>
</html>
`;
}

function renderPageNav(previousPage, nextPage) {
  if (!previousPage && !nextPage) {
    return '';
  }
  const previous = previousPage
    ? `<a class="page-nav-prev" href="${previousPage[0].replace(/\.md$/, '.html')}"><small>Previous</small><span>${escapeHtml(previousPage[1])}</span></a>`
    : '';
  const next = nextPage
    ? `<a class="page-nav-next" href="${nextPage[0].replace(/\.md$/, '.html')}"><small>Next</small><span>${escapeHtml(nextPage[1])}</span></a>`
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
  return `<table>${head}<tbody>${rowsHtml}</tbody></table>`;
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
