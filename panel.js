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

/****************************
* HELPERS
****************************/
// Extreu domini base: example.com d'un hostname com www.example.com
function getBaseDomain(hostname) { return EH.getBaseDomain(hostname); }

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

async function updateDomainFilter() {
  log('🔍 Actualitzant domini actiu...');
  try {
    let hostname = await getInspectedHostname();
    if (hostname) {
      currentDomain = getBaseDomain(hostname);
      log(`✅ Domini actiu base (from inspected host): ${currentDomain} (inspected host: ${hostname})`);
      render();
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
    em.textContent = "No hi ha endpoints per mostrar";
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
    badge.textContent = "SENSITIVE";
    methodLeft.appendChild(document.createTextNode(" "));
    methodLeft.appendChild(badge);
  }

  // Render tag bubbles (xss, sqli, lfi, idor, auth) into left part
  const tagsDiv = document.createElement('div');
  tagsDiv.className = 'tags';
  const tagNames = { xss: 'XSS', sqli: 'SQLi', lfi: 'LFI', idor: 'IDOR', auth: 'AUTH' };
  Object.entries(e.tags || {}).forEach(([t, v]) => {
    if (v) {
      const tb = document.createElement('span');
      tb.className = `tag-bubble tag-${t}`;
      tb.textContent = tagNames[t] || t.toUpperCase();
      tb.title = tagNames[t] || t.toUpperCase();
      tagsDiv.appendChild(tb);
    }
  });
  if (tagsDiv.childElementCount) methodLeft.appendChild(tagsDiv);

  // Right part: hits
  const hitsDiv = document.createElement("div");
  hitsDiv.className = 'hits';
  hitsDiv.textContent = `Hits: ${e.count}`;
  const methodRight = document.createElement('div');
  methodRight.className = 'method-right';
  methodRight.appendChild(hitsDiv);

  methodDiv.append(methodLeft, methodRight);

  const urlDiv = document.createElement("div");
  urlDiv.className = "url";
  urlDiv.textContent = e.url;

  const paramsDiv = document.createElement("div");
  paramsDiv.textContent = `Params: ${formatParams(e.params)}`;

  const exportBtn = document.createElement("button");
  exportBtn.className = "icon-btn export";
  exportBtn.dataset.index = index;
  exportBtn.title = "Exporta";
  exportBtn.setAttribute('aria-label', 'Exporta endpoint');
  exportBtn.appendChild(EH.createSVGIcon('export', 16, 16, 'Exporta'));

  const copyBtn = document.createElement("button");
  copyBtn.className = "icon-btn copy";
  copyBtn.dataset.index = index;
  copyBtn.title = "Copia";
  copyBtn.setAttribute('aria-label', 'Copia endpoint');
  copyBtn.appendChild(createSVGIcon('copy', 16, 16, 'Copia'));

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
  toggleSensitiveBtn.title = showOnlySensitive ? "Mostra tots" : "Només sensibles";
  render();
});

const toggleDomainBtn = document.getElementById("toggleDomain");
toggleDomainBtn.addEventListener("click", async () => {
  showOnlyDomain = !showOnlyDomain;
  toggleDomainBtn.setAttribute('aria-pressed', String(showOnlyDomain));
  toggleDomainBtn.title = showOnlyDomain ? "Mostrar tots dominis" : "Només domini";
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

document.querySelectorAll('#filters .tag-filter-btn').forEach(btn => {
  btn.addEventListener('click', e => {
    const tag = btn.dataset.tag;
    if (activeTags.has(tag)) {
      activeTags.delete(tag);
      btn.setAttribute('aria-pressed', 'false');
    } else {
      activeTags.add(tag);
      btn.setAttribute('aria-pressed', 'true');
    }
    render();
  });
});

browser.storage.onChanged.addListener((changes, area) => {
  if (area !== "local" || !changes.endpoints) return;
  allEndpoints = Array.isArray(changes.endpoints.newValue) ? changes.endpoints.newValue : [];
  render();
});
