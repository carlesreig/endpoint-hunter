/****************************
* CONFIGURACIÓ
****************************/
const DEBUG = false;
function log(...args) { if (DEBUG) console.log(...args); }

/****************************
* ESTAT
****************************/
let activeTags = new Set();
let showOnlySensitive = false;
let showOnlyDomain = false;
let allEndpoints = [];
let currentDomain = null;
let searchTerm = ''; 

const TAG_DISPLAY_NAMES = { 
  xss: 'XSS', sqli: 'SQLi', lfi: 'LFI', idor: 'IDOR', 
  auth: 'AUTH', rce: 'RCE', ssrf: 'SSRF' 
};

/****************************
* HELPERS
****************************/
// Helper i18n
function i18n(key, fallback) {
  return browser.i18n.getMessage(key) || fallback;
}

function localizePage() {
  document.querySelectorAll('[data-i18n-title]').forEach(el => {
    const msg = i18n(el.dataset.i18nTitle);
    if (msg) {
      el.title = msg;
      el.setAttribute('aria-label', msg);
    }
  });
  document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
    const msg = i18n(el.dataset.i18nPlaceholder);
    if (msg) el.placeholder = msg;
  });
}

// Extreu domini base: example.com d'un hostname com www.example.com
function getBaseDomain(hostname) { return getBaseDomain(hostname); }

function getVisibleEndpoints() {
  return allEndpoints.filter(e => {
    // Filtre "només sensibles"
    if (showOnlySensitive && !e.sensitive) {
      log(`⛔ Reject by sensitive filter: endpoint=${e.url}, sensitive=${e.sensitive}`);
      return false;
    }

    // Filtre "només domini" amb subdominis
    if (showOnlyDomain && currentDomain) {
      try {
        // Parse endpoint URL robustly: accept absolute URLs, or use inspected domain as base for relative ones
        let urlObj;
        try {
          urlObj = new URL(e.url);
        } catch (e_parse) {
          urlObj = new URL(e.url, `https://${currentDomain}`);
        }
        // Normalize hostnames and domain (strip possible trailing dots)
        let hostname = urlObj.hostname.toLowerCase();
        let domain = currentDomain.toLowerCase();
        if (hostname.endsWith('.')) hostname = hostname.slice(0, -1);
        if (domain.endsWith('.')) domain = domain.slice(0, -1);
        // Match exact domain or any subdomain (e.g., sub.example.com endsWith .example.com)
        const domainMatch = hostname === domain || hostname.endsWith('.' + domain);
        log(`🔍 Domain filter check (normalized): hostname=${hostname}, domain=${domain}, match=${domainMatch}`);
        if (!domainMatch) {
          log(`⛔ Reject by domain filter: hostname=${hostname}, endpoint=${e.url}`);
          return false;
        }
        // Domain matches; continue and apply tag filters if any
        log(`✅ Domain filter passed: hostname=${hostname} — continuing to tag filters if set`);
      } catch (err) {
        log('❌ Error parsing endpoint URL for domain filter:', err);
        return false;
      }
    }

    // Filtre per tags actius (OR: almenys un)
    if (activeTags.size) {
      const match = [...activeTags].some(tag => e.tags?.[tag]);
      log(`🔍 Tag filter check: endpoint=${e.url}, activeTags=${[...activeTags].join(',')}, matched=${match}`);
      if (!match) {
        log(`⛔ Reject by tag filter: endpoint=${e.url}`);
        return false;
      }
    }

    // Filtre de cerca (URL o params)
    if (searchTerm) {
      const s = String(searchTerm).toLowerCase();
      const urlMatch = e.url && String(e.url).toLowerCase().includes(s);
      const paramsStr = e.params ? (Array.isArray(e.params) ? e.params.join(' ') : JSON.stringify(e.params)) : '';
      const paramsMatch = String(paramsStr).toLowerCase().includes(s);
      log(`🔍 Search filter check: endpoint=${e.url}, search=${searchTerm}, urlMatch=${urlMatch}, paramsMatch=${paramsMatch}`);
      if (!urlMatch && !paramsMatch) {
        log(`⛔ Reject by search filter: endpoint=${e.url}`);
        return false;
      }
    }

    return true; 
  });
}

// Return visible endpoints in display order (newest first)
function getVisibleEndpointsReversed() {
  return getVisibleEndpoints().slice().reverse();
}

// Helper to obtain inspected page hostname by trying multiple properties and both callback/promise eval styles
function getInspectedHostname() { return EH.getInspectedHostname(); }

// Check if parameter values are reflected in the current page DOM
// Optimized: Search happens inside the page context to avoid transferring huge HTML strings.
async function checkReflections() {
  const endpoints = getVisibleEndpoints();
  const valuesToSearch = [];
  const mapValueToParam = {}; // value -> { endpointIndex, paramName }

  endpoints.forEach(e => {
    if (!e.latestValues) return;
    Object.entries(e.latestValues).forEach(([param, value]) => {
      if (value && value.length > 3) { // Ignore short noise
        const vLower = value.toLowerCase();
        valuesToSearch.push(vLower);
        if (!mapValueToParam[vLower]) mapValueToParam[vLower] = [];
        mapValueToParam[vLower].push({ endpoint: e, param });
      }
    });
  });

  if (!valuesToSearch.length) return;

  // Safe eval: JSON.stringify ensures values are treated as data, not code.
  const expr = `(function() {
    const html = document.documentElement.outerHTML.toLowerCase();
    const needles = ${JSON.stringify(valuesToSearch)};
    return needles.filter(n => html.includes(n));
  })()`;

  browser.devtools.inspectedWindow.eval(expr, (matches, err) => {
    if (err || !matches || !matches.length) return;
    
    let changed = false;
    matches.forEach(match => {
      const entries = mapValueToParam[match];
      if (entries) {
        entries.forEach(entry => {
          // Activar tag XSS si es detecta reflexió
          if (!entry.endpoint.tags) entry.endpoint.tags = {};
          if (!entry.endpoint.tags.xss) {
            entry.endpoint.tags.xss = true;
            changed = true;
          }
          if (!entry.endpoint.reflectedParams) entry.endpoint.reflectedParams = [];
          if (!entry.endpoint.reflectedParams.includes(entry.param)) {
            entry.endpoint.reflectedParams.push(entry.param);
          }
        });
      }
    });
    if (changed) render();
  });
}

async function updateDomainFilter() {
  log('🔍 Actualitzant domini actiu...');
  try {
    let hostname = await getInspectedHostname();
    if (hostname) {
      currentDomain = getBaseDomain(hostname);
      log(`✅ Domini actiu base (from inspected host): ${currentDomain} (inspected host: ${hostname})`);
      render();
      checkReflections();
      return true;
    }

    // Fallback: derive most common base domain from stored endpoints
    try {
      const counts = {};
      allEndpoints.forEach(e => {
        try {
          const u = new URL(e.url);
          const base = getBaseDomain(u.hostname);
          counts[base] = (counts[base] || 0) + 1;
        } catch (ignore) {}
      });
      const entries = Object.entries(counts).sort((a,b) => b[1]-a[1]);
      if (entries.length) {
        currentDomain = entries[0][0];
        log(`✅ Domini actiu base (derived from endpoints): ${currentDomain}`);
        render();
        checkReflections();
        return true;
      }
    } catch (e) {
      log('❌ Error deriving domain from endpoints:', e);
    }

    currentDomain = null;
    render();
    return false;
  } catch (err) {
    log('❌ Error obtenint hostname de la pestanya inspeccionada:', err);
    currentDomain = null;
    render();
    return false;
  }
}

function formatParams(params) { return EH.formatParams(params); }

// Create small inline SVG icons via DOM (avoid innerHTML for AMO/CSP friendliness)
function createSVGIcon(name, w = 16, h = 16, title) {
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('width', String(w));
  svg.setAttribute('height', String(h));
  svg.setAttribute('focusable', 'false');
  svg.setAttribute('aria-hidden', 'true');
  if (title) {
    const t = document.createElementNS(ns, 'title');
    t.textContent = title;
    svg.appendChild(t);
  }

  if (name === 'export' || name === 'download') {
    const path = document.createElementNS(ns, 'path');
    path.setAttribute('fill', 'currentColor');
    path.setAttribute('d', 'M5 20h14v-2H5v2zm7-18v10l3.3-3.3 1.4 1.42L12 17.41 7.3 11.71l1.4-1.42L11 12V2h1z');
    svg.appendChild(path);
  } else if (name === 'copy') {
    const path = document.createElementNS(ns, 'path');
    path.setAttribute('fill', 'currentColor');
    path.setAttribute('d', 'M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm-1 12H9V9h9v8z');
    svg.appendChild(path);
  } else {
    // fallback square
    const rect = document.createElementNS(ns, 'rect');
    rect.setAttribute('x', '3');
    rect.setAttribute('y', '3');
    rect.setAttribute('width', '18');
    rect.setAttribute('height', '18');
    rect.setAttribute('fill', 'currentColor');
    svg.appendChild(rect);
  }
  return svg;
}

/****************************
* RENDER
****************************/
function render() {
  const list = document.getElementById("list");
  list.textContent = "";

  const endpointsToShow = getVisibleEndpointsReversed();

  if (!endpointsToShow.length) {
    const em = document.createElement("em");
    em.textContent = i18n("noEndpoints", "No hi ha endpoints per mostrar");
    list.appendChild(em);
    return;
  }

  endpointsToShow.forEach((e, index) => {
    const div = createEndpointDiv(e, index);
    list.appendChild(div);
  });

  bindEndpointButtons();
  updateTagButtonsState();
}

function createEndpointDiv(e, index) {
  const div = document.createElement("div");
  div.className = "endpoint" + (e.sensitive ? " sensitive" : "");

  const methodDiv = document.createElement("div");
  methodDiv.className = "method";

  // Left part: method text, badge and tags
  const methodLeft = document.createElement('div');
  methodLeft.className = 'method-left';
  const methodText = document.createElement('span');
  methodText.className = 'method-text';
  methodText.textContent = e.method;
  methodLeft.appendChild(methodText);
  if (e.sensitive) {
    const badge = document.createElement("span");
    badge.className = "badge sensitive-badge";
    badge.textContent = i18n("sensitive", "SENSITIVE");
    methodLeft.appendChild(document.createTextNode(" "));
    methodLeft.appendChild(badge);
  }

  // Render tag bubbles (xss, sqli, lfi, idor, auth) into left part
  const tagsDiv = document.createElement('div');
  tagsDiv.className = 'tags';
  Object.entries(e.tags || {}).forEach(([t, v]) => {
    if (v) {
      const tb = document.createElement('span');
      tb.className = `tag-bubble tag-${t}`;
      tb.textContent = i18n(`tag_${t}`, TAG_DISPLAY_NAMES[t] || t.toUpperCase());
      tb.title = tb.textContent;
      tagsDiv.appendChild(tb);
    }
  });
  if (tagsDiv.childElementCount) methodLeft.appendChild(tagsDiv);

  // Right part: hits
  const hitsDiv = document.createElement("div");
  hitsDiv.className = 'hits';
  hitsDiv.textContent = `${i18n("hits", "Hits")}: ${e.count}`;
  const methodRight = document.createElement('div');
  methodRight.className = 'method-right';
  methodRight.appendChild(hitsDiv);

  methodDiv.append(methodLeft, methodRight);

  const urlDiv = document.createElement("div");
  urlDiv.className = "url";
  urlDiv.textContent = e.url;

  const paramsDiv = document.createElement("div");
  paramsDiv.textContent = `${i18n("params", "Params")}: ${formatParams(e.params)}`;

  const exportBtn = document.createElement("button");
  exportBtn.className = "icon-btn export";
  exportBtn.dataset.index = index;
  exportBtn.title = i18n("export", "Exporta");
  exportBtn.setAttribute('aria-label', exportBtn.title);
  exportBtn.appendChild(EH.createSVGIcon('export', 16, 16, exportBtn.title));

  const copyBtn = document.createElement("button");
  copyBtn.className = "icon-btn copy";
  copyBtn.dataset.index = index;
  copyBtn.title = i18n("copy", "Copia");
  copyBtn.setAttribute('aria-label', copyBtn.title);
  copyBtn.appendChild(createSVGIcon('copy', 16, 16, copyBtn.title));

  // Actions column (left): export above copy (more compact)
  const actionsDiv = document.createElement('div');
  actionsDiv.className = 'endpoint-actions';
  actionsDiv.appendChild(exportBtn);
  actionsDiv.appendChild(copyBtn);

  // Main content (right)
  const contentDiv = document.createElement('div');
  contentDiv.className = 'endpoint-content';
  contentDiv.append(methodDiv, urlDiv, paramsDiv);

  div.append(actionsDiv, contentDiv);
  return div;
}

/****************************
* BINDINGS DINÀMICS
****************************/
function bindEndpointButtons() {
  document.querySelectorAll(".export").forEach(btn => btn.addEventListener("click", exportEndpoint));
  document.querySelectorAll(".copy").forEach(btn => btn.addEventListener("click", copyEndpoint));
}

/****************************
* ACCIONS
****************************/
function exportEndpoint(e) {
  const btn = e.currentTarget || e.target.closest && e.target.closest('button') || e.target;
  const endpoint = getVisibleEndpointsReversed()[btn?.dataset?.index];
  if (!endpoint) return;
  const blob = new Blob([JSON.stringify(endpoint, null, 2)], { type: "application/json" });
  const urlBlob = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = urlBlob;
  a.download = "endpoint.json";
  a.click();
  URL.revokeObjectURL(urlBlob);
}

function copyEndpoint(e) {
  const btn = e.currentTarget || e.target.closest && e.target.closest('button') || e.target;
  const endpoint = getVisibleEndpointsReversed()[btn?.dataset?.index];
  if (!endpoint) return;
  const text = `${endpoint.method} --> ${endpoint.url} --> Params: ${formatParams(endpoint.params)}`;
  navigator.clipboard.writeText(text).then(() => {
    const row = btn.closest('.endpoint');
    if (row) {
      row.classList.add('flash');
      setTimeout(() => row.classList.remove('flash'), 900);
    }
  }).catch(err => {
    log('❌ Error copiant al portapapers:', err);
  });
}

function copyVisibleEndpoints() {
  const endpoints = getVisibleEndpointsReversed();
  if (!endpoints.length) return;

  const text = endpoints.map(e => `Method: ${e.method}\nURL: ${e.url}\nParams: ${formatParams(e.params)}`).join("\n\n");
  navigator.clipboard.writeText(text).then(() => {
    const list = document.getElementById("list");
    // transient flash effect on the list
    list.classList.add('flash');
    setTimeout(() => { list.classList.remove('flash'); }, 900);
  }).catch(err => {
    log('❌ Error copiant al portapapers:', err);
  });
}

/****************************
* INIT
****************************/
async function init() {
  log('🚀 Inicialitzant panel...');
  const data = await browser.storage.local.get("endpoints");
  allEndpoints = data.endpoints || [];
  log(`📊 ${allEndpoints.length} endpoints carregats`);
  await updateDomainFilter();
  localizePage();
  render();
  log('✅ Panel inicialitzat');
}

init();

/****************************
* BOTONS PRINCIPALS
****************************/
const toggleSensitiveBtn = document.getElementById("toggleSensitive");
toggleSensitiveBtn.addEventListener("click", () => {
  showOnlySensitive = !showOnlySensitive;
  toggleSensitiveBtn.setAttribute('aria-pressed', String(showOnlySensitive));
  toggleSensitiveBtn.title = showOnlySensitive ? i18n("btnAll", "Mostra tots") : i18n("btnSensitive", "Només sensibles");
  render();
});

const toggleDomainBtn = document.getElementById("toggleDomain");
toggleDomainBtn.addEventListener("click", async () => {
  showOnlyDomain = !showOnlyDomain;
  toggleDomainBtn.setAttribute('aria-pressed', String(showOnlyDomain));
  toggleDomainBtn.title = showOnlyDomain ? i18n("btnAllDomains", "Mostrar tots dominis") : i18n("btnDomain", "Només domini");
  await updateDomainFilter();
  render();
});

// Find / Search UI wiring
const toggleFindBtn = document.getElementById("toggleAll");
const findContainer = document.getElementById("findContainer");
const findInput = document.getElementById("findInput");
const clearFindBtn = document.getElementById("clearFind");

if (toggleFindBtn) {
  toggleFindBtn.addEventListener("click", () => {
    if (!findContainer) return;
    const hidden = findContainer.classList.contains('hidden');
    if (hidden) {
      findContainer.classList.remove('hidden');
      findContainer.setAttribute('aria-hidden','false');
      toggleFindBtn.setAttribute('aria-pressed', 'true');
      findInput?.focus();
    } else {
      findContainer.classList.add('hidden');
      findContainer.setAttribute('aria-hidden','true');
      toggleFindBtn.setAttribute('aria-pressed', 'false');
      searchTerm = '';
      if (findInput) findInput.value = '';
    }
    render();
  });
}

if (findInput) {
  findInput.addEventListener("input", e => {
    searchTerm = e.target.value.trim();
    render();
  });
  findInput.addEventListener("keydown", e => {
    if (e.key === 'Escape') {
      searchTerm = '';
      findInput.value = '';
      findInput.blur();
      render();
    }
  });
}

if (clearFindBtn) {
  clearFindBtn.addEventListener("click", () => {
    searchTerm = '';
    if (findInput) findInput.value = '';
    render();
  });
}

const toggleThemeBtn = document.getElementById("toggleTheme");
if (toggleThemeBtn) {
  toggleThemeBtn.addEventListener("click", () => {
    const html = document.documentElement;
    const current = html.getAttribute("data-theme");
    const next = current === "dark" ? "light" : "dark";
    html.setAttribute("data-theme", next);
    browser.storage.local.set({ theme: next });
  });
  // Init theme
  browser.storage.local.get("theme").then(data => {
    if (data.theme) {
      document.documentElement.setAttribute("data-theme", data.theme);
    }
  });
}

document.getElementById("copyVisible").addEventListener("click", copyVisibleEndpoints);
document.getElementById("clear").addEventListener("click", async () => {
  await browser.runtime.sendMessage({ action: "clear-endpoints" });
  allEndpoints = [];
  render();
});

// Tag filter buttons (toggle behavior)
function updateTagButtonsState() {
  document.querySelectorAll('#filters .tag-filter-btn').forEach(btn => {
    const tag = btn.dataset.tag;
    btn.setAttribute('aria-pressed', String(activeTags.has(tag)));
  });
}

// Generate filter buttons dynamically based on TAG_DISPLAY_NAMES
function initFilterButtons() {
  const container = document.getElementById('filters');
  if (!container) return;
  container.innerHTML = ''; // Clear existing static buttons
  
  Object.entries(TAG_DISPLAY_NAMES).forEach(([tag, label]) => {
    const btn = document.createElement('button');
    btn.className = `tag-filter-btn tag-${tag}`;
    btn.dataset.tag = tag;
    btn.textContent = i18n(`tag_${tag}`, label);
    btn.title = i18n(`filter_${tag}`, `Filtra per ${label}`);
    btn.setAttribute('aria-pressed', String(activeTags.has(tag)));
    btn.addEventListener('click', () => {
      if (activeTags.has(tag)) activeTags.delete(tag);
      else activeTags.add(tag);
      render();
    });
    container.appendChild(btn);
  });
}

initFilterButtons();

browser.storage.onChanged.addListener((changes, area) => {
  if (area !== "local" || !changes.endpoints) return;
  allEndpoints = Array.isArray(changes.endpoints.newValue) ? changes.endpoints.newValue : [];
  render();
});
