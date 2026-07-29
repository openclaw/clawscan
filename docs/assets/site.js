const root = document.documentElement;
const sidebar = document.querySelector('.sidebar');
const overlay = document.querySelector('.sidebar-overlay');
const menuButton = document.querySelector('.nav-toggle');
const mobileNav = window.matchMedia('(max-width: 52rem)');

function readStoredTheme() {
  try {
    return localStorage.getItem('clawscan-theme');
  } catch {
    return null;
  }
}

function storeTheme(theme) {
  try {
    localStorage.setItem('clawscan-theme', theme);
  } catch {
    // Theme persistence is optional in privacy-restricted browsing modes.
  }
}

function applyTheme(theme) {
  root.dataset.theme = theme;
  document.querySelectorAll('[data-theme-toggle]').forEach((button) => {
    button.setAttribute('aria-pressed', theme === 'dark' ? 'true' : 'false');
    button.setAttribute(
      'aria-label',
      theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme',
    );
  });
}

applyTheme(root.dataset.theme === 'dark' ? 'dark' : 'light');

document.querySelectorAll('[data-theme-toggle]').forEach((button) => {
  button.addEventListener('click', () => {
    const nextTheme = root.dataset.theme === 'dark' ? 'light' : 'dark';
    applyTheme(nextTheme);
    storeTheme(nextTheme);
  });
});

const systemTheme = window.matchMedia('(prefers-color-scheme: dark)');
const onSystemThemeChange = (event) => {
  if (!readStoredTheme()) {
    applyTheme(event.matches ? 'dark' : 'light');
  }
};

if (systemTheme.addEventListener) {
  systemTheme.addEventListener('change', onSystemThemeChange);
} else {
  systemTheme.addListener?.(onSystemThemeChange);
}

function setNavigationOpen(open) {
  if (!sidebar || !overlay || !menuButton) {
    return;
  }
  const focusWasInSidebar = sidebar.contains(document.activeElement);
  const sidebarIsHidden = mobileNav.matches && !open;
  sidebar.classList.toggle('open', open);
  overlay.classList.toggle('open', open);
  overlay.hidden = !open;
  menuButton.setAttribute('aria-expanded', open ? 'true' : 'false');
  sidebar.toggleAttribute('inert', sidebarIsHidden);
  if (sidebarIsHidden) {
    sidebar.setAttribute('aria-hidden', 'true');
  } else {
    sidebar.removeAttribute('aria-hidden');
  }
  document.body.style.overflow = mobileNav.matches && open ? 'hidden' : '';
  if (sidebarIsHidden && focusWasInSidebar) {
    menuButton.focus();
  }
}

setNavigationOpen(false);
menuButton?.addEventListener('click', () => {
  setNavigationOpen(!sidebar?.classList.contains('open'));
});
overlay?.addEventListener('click', () => setNavigationOpen(false));

document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape') {
    setNavigationOpen(false);
  }
});

const onViewportChange = () => setNavigationOpen(false);
if (mobileNav.addEventListener) {
  mobileNav.addEventListener('change', onViewportChange);
} else {
  mobileNav.addListener?.(onViewportChange);
}

const searchInput = document.getElementById('doc-search');
searchInput?.addEventListener('input', () => {
  const query = searchInput.value.trim().toLowerCase();
  document.querySelectorAll('.docs-nav section').forEach((section) => {
    let hasMatch = false;
    section.querySelectorAll('.nav-link').forEach((link) => {
      const matches = !query || link.textContent.toLowerCase().includes(query);
      link.hidden = !matches;
      hasMatch ||= matches;
    });
    section.hidden = !hasMatch;
  });
});

document.addEventListener('keydown', (event) => {
  const target = event.target;
  const isTyping = target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement;
  if (event.key === '/' && !isTyping && searchInput) {
    event.preventDefault();
    if (mobileNav.matches) {
      setNavigationOpen(true);
    }
    searchInput.focus();
  }
});

async function copyText(button, text) {
  const idleLabel = button.dataset.idleLabel || button.textContent;
  try {
    await navigator.clipboard.writeText(text);
    button.textContent = 'Copied';
    button.classList.add('copied');
  } catch {
    button.textContent = 'Copy failed';
  }
  window.setTimeout(() => {
    button.textContent = idleLabel;
    button.classList.remove('copied');
  }, 1500);
}

document.querySelectorAll('.doc pre').forEach((pre) => {
  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'copy';
  button.textContent = 'Copy';
  button.dataset.idleLabel = 'Copy';
  button.setAttribute('aria-label', 'Copy code');
  button.addEventListener('click', () => {
    copyText(button, pre.querySelector('code')?.textContent ?? '');
  });
  pre.appendChild(button);
});

document.querySelectorAll('[data-copy-install]').forEach((button) => {
  const label = button.querySelector('.install-copy');
  if (!label) {
    return;
  }
  label.dataset.idleLabel = 'Copy';
  button.addEventListener('click', () => {
    copyText(label, 'npm install -g @openclaw/clawscan');
  });
});

const tocLinks = document.querySelectorAll('.toc a');
if (tocLinks.length && 'IntersectionObserver' in window) {
  const linksByHeading = new Map();
  tocLinks.forEach((link) => {
    const heading = document.getElementById(link.hash.slice(1));
    if (heading) {
      linksByHeading.set(heading, link);
    }
  });

  const observer = new IntersectionObserver(
    (entries) => {
      const visible = entries
        .filter((entry) => entry.isIntersecting)
        .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
      const activeLink = visible.length ? linksByHeading.get(visible[0].target) : null;
      if (!activeLink) {
        return;
      }
      tocLinks.forEach((link) => link.classList.toggle('active', link === activeLink));
    },
    { rootMargin: '-18% 0px -68% 0px', threshold: 0 },
  );

  linksByHeading.forEach((_link, heading) => observer.observe(heading));
}
