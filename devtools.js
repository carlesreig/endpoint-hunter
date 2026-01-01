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

const TAG_DISPLAY_NAMES = { 
  xss: 'XSS', sqli: 'SQLi', lfi: 'LFI', idor: 'IDOR', 
  auth: 'AUTH', rce: 'RCE', ssrf: 'SSRF' 
};

/****************************
* HELPERS
****************************/
// Extreu el domini base d'un hostname (eliminant subdominis com www)
function getBaseDomain(hostname) { return EH.getBaseDomain(hostname); }

// Obtenir endpoints filtrats per subdomini, tags i sensitive
function getVisibleEndpoints() {
  return allEndpoints.filter(e => {
    // Filtre "només sensibles"
    if (showOnlySensitive && !e.sensitive) {
      log(`⛔ Reject by sensitive filter: endpoint=${e.url}, sensitive=${e.sensitive}`);
      return false;
    }

    // Filtre domini/subdomini
    if (showOnlyDomain && currentDomain) {
      try {
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

    // Filtre per tags actius (OR)
    if (activeTags.size) {
      const match = [...activeTags].some(tag => e.tags?.[tag]);
      log(`🔍 Tag filter check: endpoint=${e.url}, activeTags=${[...activeTags].join(',')}, matched=${match}`);
      if (!match) {
        log(`⛔ Reject by tag filter: endpoint=${e.url}`);
        return false;
      }
    }

    return true;
  });
}

// Create DevTools panel to host `panel.html` (works with callback or promise versions)
function createDevToolsPanel() {
  if (!browser?.devtools?.panels?.create) {
    log('⚠️ devtools.panels.create not available in this runtime');
    return;
  }
  try {
    const maybePromise = browser.devtools.panels.create("Endpoint Hunter", "icons/icon-48.png", "panel.html");

    function attachOnShown(panel, source) {
      try {
        if (panel && panel.onShown && typeof panel.onShown.addListener === 'function') {
          panel.onShown.addListener((panelWindow) => {
            log(`🔔 DevTools panel shown (${source}). Refreshing inspected domain and rendering panel UI.`);
            try {
              // If the panel's page exposes updateDomainFilter/render, call them
              if (panelWindow && typeof panelWindow.updateDomainFilter === 'function') {
                panelWindow.updateDomainFilter().then(() => {
                  if (typeof panelWindow.render === 'function') panelWindow.render();
                }).catch(err => log('❌ updateDomainFilter() threw in panelWindow:', err));
              } else if (panelWindow && typeof panelWindow.render === 'function') {
                // At least re-render
                panelWindow.render();
              }
            } catch (e) {
              log('❌ Error invoking panelWindow functions onShown:', e);
            }
          });
        }
      } catch (e) {
        log('❌ Error attaching onShown listener:', e);
      }
    }

    if (maybePromise && typeof maybePromise.then === 'function') {
      maybePromise.then(panel => {
        log('✅ DevTools panel created (promise)');
        attachOnShown(panel, 'promise');
      }).catch(err => log('❌ Error creating panel (promise)', err));
    } else {
      try {
        browser.devtools.panels.create("Endpoint Hunter", "icons/icon-48.png", "panel.html", function(panel) {
          log('✅ DevTools panel created (callback)');
          attachOnShown(panel, 'callback');
        });
      } catch (e) {
        log('❌ Error creating panel (callback)', e);
      }
    }
  } catch (err) {
    log('❌ Error creating DevTools panel:', err);
  }
}
createDevToolsPanel();

// Helper to obtain inspected page hostname by trying multiple properties and both callback/promise eval styles
function getInspectedHostname() { return EH.getInspectedHostname(); }

async function updateDomainFilter() {
  log('🔍 Actualitzant domini actiu...');
  try {
    let hostname = await getInspectedHostname();
    if (hostname) {
      currentDomain = getBaseDomain(hostname);
      log(`✅ Domini actiu base (from inspected host): ${currentDomain} (inspected host: ${hostname})`);
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
        return true;
      }
    } catch (e) {
      log('❌ Error deriving domain from endpoints:', e);
    }

    currentDomain = null;
    return false;
  } catch (err) {
    log('❌ Error obtenint hostname de la pestanya inspeccionada:', err);
    currentDomain = null;
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

  const endpointsToShow = getVisibleEndpoints();

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
}

function createEndpointDiv(e, index) {
  const div = document.createElement("div");
  div.className = "endpoint" + (e.sensitive ? " sensitive" : "");

  const methodDiv = document.createElement("div");
  methodDiv.className = "method";
  methodDiv.textContent = e.method;
  if (e.sensitive) {
    const badge = document.createElement("span");
    badge.className = "badge sensitive-badge";
    badge.textContent = "SENSITIVE";
    methodDiv.appendChild(document.createTextNode(" "));
    methodDiv.appendChild(badge);
  }

  // Render tag bubbles (xss, sqli, lfi, idor, auth)
  const tagsDiv = document.createElement('div');
  tagsDiv.className = 'tags';
  Object.entries(e.tags || {}).forEach(([t, v]) => {
    if (v) {
      const tb = document.createElement('span');
      tb.className = `tag-bubble tag-${t}`;
      tb.textContent = TAG_DISPLAY_NAMES[t] || t.toUpperCase();
      tb.title = TAG_DISPLAY_NAMES[t] || t.toUpperCase();
      tagsDiv.appendChild(tb);
    }
  });
  if (tagsDiv.childElementCount) methodDiv.appendChild(tagsDiv);

  const urlDiv = document.createElement("div");
  urlDiv.className = "url";
  urlDiv.textContent = e.url;

  const paramsDiv = document.createElement("div");
  paramsDiv.textContent = `Params: ${formatParams(e.params)}`;

  const hitsDiv = document.createElement("div");
  hitsDiv.textContent = `Hits: ${e.count}`;

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

  div.append(methodDiv, urlDiv, paramsDiv, hitsDiv, exportBtn, copyBtn);
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
  const endpoint = getVisibleEndpoints()[btn?.dataset?.index];
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
  const endpoint = getVisibleEndpoints()[btn?.dataset?.index];
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
  const endpoints = getVisibleEndpoints();
  if (!endpoints.length) return;

  const text = endpoints.map(e => `Method: ${e.method}\nURL: ${e.url}\nParams: ${formatParams(e.params)}`).join("\n\n");
  navigator.clipboard.writeText(text).then(() => {
    const list = document.getElementById("list");
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
const toggleSensitiveBtn2 = document.getElementById("toggleSensitive");
toggleSensitiveBtn2.addEventListener("click", () => {
  showOnlySensitive = !showOnlySensitive;
  toggleSensitiveBtn2.setAttribute('aria-pressed', String(showOnlySensitive));
  toggleSensitiveBtn2.title = showOnlySensitive ? "Mostra tots" : "Només sensibles";
  render();
});

const toggleDomainBtn2 = document.getElementById("toggleDomain");
toggleDomainBtn2.addEventListener("click", async () => {
  showOnlyDomain = !showOnlyDomain;
  toggleDomainBtn2.setAttribute('aria-pressed', String(showOnlyDomain));
  toggleDomainBtn2.title = showOnlyDomain ? "Mostrar tots dominis" : "Només domini";
  await updateDomainFilter();
  render();
});

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
function updateTagButtonsStateDevtools() {
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
    btn.textContent = label;
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

// Call update after render
const originalRenderDevtools = render;
render = function() { originalRenderDevtools(); updateTagButtonsStateDevtools(); };

browser.storage.onChanged.addListener((changes, area) => {
  if (area !== "local" || !changes.endpoints) return;
  allEndpoints = Array.isArray(changes.endpoints.newValue) ? changes.endpoints.newValue : [];
  render();
});
