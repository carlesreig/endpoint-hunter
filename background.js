/****************************
* CONFIG: externalitzat a `config.js`
****************************/

// Load configuration constants from global `ENDPOINT_HUNTER_CONFIG` (set in config.js)
// Provide safe defaults if the config object is not present (backwards compatible).
const _CFG = globalThis.ENDPOINT_HUNTER_CONFIG || {};

/** @type {string[]} */
// Use values from `config.js` (ENDPOINT_HUNTER_CONFIG). Keep empty fallback to avoid
// duplicating the canonical defaults in multiple places.
const SENSITIVE_PATHS = _CFG.SENSITIVE_PATHS || [];

/** @type {string[]} */
const SENSITIVE_PARAMS = _CFG.SENSITIVE_PARAMS || [];

/** @type {string[]} */
const SENSITIVE_METHODS = _CFG.SENSITIVE_METHODS || [];

/** @type {string[]} */
const IGNORED_EXTENSIONS = _CFG.IGNORED_EXTENSIONS || [];

const DEBUG = false;
function bgLog(...args) { if (DEBUG) console.log(...args); }

/****************************
* TAG RULES (heurístiques)
****************************/

// Tagging heuristics come from `config.js`. Keep object fallback empty to avoid duplicates.
const TAG_RULES = _CFG.TAG_RULES || {}; 

/****************************
* HELPERS
****************************/

function isSensitiveEndpoint(url, method, params, responseHeaders) {
  if (globalThis.ENDPOINT_HUNTER_DETECTION && typeof globalThis.ENDPOINT_HUNTER_DETECTION.isSensitiveEndpoint === 'function') {
    return globalThis.ENDPOINT_HUNTER_DETECTION.isSensitiveEndpoint(url, method, params, _CFG); // isSensitive no sol necessitar headers, però es podria afegir
  }
  // Fallback (previous inline logic)
  const path = url.pathname.toLowerCase();
  if (SENSITIVE_METHODS.includes(method)) return true;
  if (SENSITIVE_PATHS.some(p => path.includes(p))) return true;
  if (params.some(p => SENSITIVE_PARAMS.includes(p.toLowerCase()))) return true;
  if (/\/(login|admin|auth|account)\.php$/.test(path)) {
    bgLog('⚠️ Sensitive php endpoint detected:', path);
    return true;
  }
  return false;
}

function detectTags(url, method, params, status, responseHeaders) {
  if (globalThis.ENDPOINT_HUNTER_DETECTION && typeof globalThis.ENDPOINT_HUNTER_DETECTION.detectTags === 'function') {
    return globalThis.ENDPOINT_HUNTER_DETECTION.detectTags(url, method, params, status, responseHeaders, _CFG);
  }

  const path = url.pathname.toLowerCase();
  const lowerParams = params.map(p => p.toLowerCase());

  // Collect parameter values from URL query string
  const values = [];
  try {
    for (const v of url.searchParams.values()) values.push((v||'').toLowerCase());
  } catch (e) {
    // ignore
  }

  // Patterns for value-based detection
  const xssValuePattern = /<\s*script|%3cscript|&lt;script|on\w+\s*=|javascript:|%3c|%3e|<[^>]+>/i;
  const sqliValuePattern = /('|\")\s*(or|and)\s+\d+\s*=\s*\d+|--|\/\*|\bunion\b|\bselect\b|\bdrop\b|\binsert\b/i;

  const valueLooksLikeXss = values.some(v => xssValuePattern.test(v));
  const valueLooksLikeSqli = values.some(v => sqliValuePattern.test(v));

  const xssDetected = TAG_RULES.xss.methods.includes(method) &&
                       (lowerParams.some(p => TAG_RULES.xss.params.includes(p)) || valueLooksLikeXss || path.includes('search') || path.includes('query'));

  const sqliDetected = TAG_RULES.sqli.methods.includes(method) &&
                        (lowerParams.some(p => TAG_RULES.sqli.params.includes(p)) || valueLooksLikeSqli);

  if (xssDetected) bgLog('🔔 XSS detected for', url.href, {params: lowerParams, values});
  if (sqliDetected) bgLog('🔔 SQLi detected for', url.href, {params: lowerParams, values});

  return {
    xss: xssDetected,
    sqli: sqliDetected,
    lfi: TAG_RULES.lfi.methods.includes(method) &&
         lowerParams.some(p => TAG_RULES.lfi.params.includes(p)),
    idor: TAG_RULES.idor.methods.includes(method) &&
          (lowerParams.some(p => TAG_RULES.idor.params.includes(p)) ||
           /\d+/.test(path)),
    auth: TAG_RULES.auth.paths.some(p => path.includes(p)) ||
          status === 401 || status === 403
  };
}

function isInteresting(details) {
  if (globalThis.ENDPOINT_HUNTER_DETECTION && typeof globalThis.ENDPOINT_HUNTER_DETECTION.isInteresting === 'function') {
    return globalThis.ENDPOINT_HUNTER_DETECTION.isInteresting(details, _CFG);
  }

  const url = details.url.toLowerCase();
  
  // ❌ Filtrar imatges + fonts + altres arxius estàtics
  if (IGNORED_EXTENSIONS.some(ext => url.includes(ext))) return false;

  // ✅ Tractar .php com a interessant (dinàmic, potencialment vulnerable)
  if (url.includes('.php')) {
    bgLog('✨ .php detected, marking as interesting:', url);
    return true;
  }
  
  // ✅ JS dinàmics SÍ (endpoints hardcoded, configs)
  if (details.type === "xmlhttprequest" || details.type === "fetch") {
    return true; // TOTS els XHR/fetch són interessants
  }
  
  // ❌ CSS estàtics NO
  if (url.includes('.css') && details.type !== "xmlhttprequest") return false;
  
  // ✅ JS dinàmics o amb noms sospitosos
  if (url.includes('.js') && (
    details.type === "xmlhttprequest" ||
    url.includes('config') ||
    url.includes('api') ||
    url.includes('admin') ||
    !url.includes('/static/') && !url.includes('/assets/')
  )) {
    return true;
  }
  
  return false;
}

/****************************
* ESTAT GLOBAL + PATRONS DINÀMICS
****************************/

let endpoints = new Map();
let dynamicPatterns = new Map(); // patró → {count, examples}
let saveTimeout = null;

/****************************
* AUTO-APRENENTATGE DE PATRONS
****************************/

function learnDynamicPattern(pathname, method) {
  const pathsSeen = Array.from(endpoints.values())
    .filter(e => e.method === method)
    .flatMap(e => e.originalExamples || [])
    .filter(p => p.startsWith(pathname.split('/').slice(0, -1).join('/')));
  
  if (pathsSeen.length >= 3) {
    const commonPrefix = pathsSeen[0].split('/').slice(0, -2).join('/');
    const hasDynamicSuffix = pathsSeen.every(p => 
      p.startsWith(commonPrefix) && 
      p.split('/').pop().match(/^[A-Z0-9]{4,}$/)
    );
    
    if (hasDynamicSuffix) {
      const patternKey = `${commonPrefix}/{id}`;
      if (!dynamicPatterns.has(patternKey)) {
        dynamicPatterns.set(patternKey, {
          count: pathsSeen.length,
          examples: pathsSeen.slice(0, 5) // màxim 5 exemples
        });
        console.log(`✅ Nou patró après: ${patternKey} (${pathsSeen.length} exemples)`);
      }
    }
  }
}

function normalizePath(pathname, method) {
  // Comprovar patrons apresos
  for (const [pattern] of dynamicPatterns) {
    const regex = new RegExp(pattern.replace('/{id}', '/[A-Z0-9]{4,}'));
    if (regex.test(pathname)) {
      return pattern;
    }
  }
  return pathname;
}

/****************************
* STORAGE SYNC (DEBOUNCE)
****************************/

function saveEndpoints() {
  if (saveTimeout) clearTimeout(saveTimeout);
  saveTimeout = setTimeout(() => {
    browser.storage.local.set({
      endpoints: Array.from(endpoints.values()),
      dynamicPatterns: Array.from(dynamicPatterns.entries()),
      lastUpdate: Date.now()
    });
  }, 400);
}

/****************************
* INTERCEPTOR PRINCIPAL (AUTO-APRENENTATGE)
****************************/

browser.webRequest.onCompleted.addListener(
  (details) => {
    if (!isInteresting(details)) return;
    
    let url;
    try { 
      url = new URL(details.url); 
    } catch { 
      return; 
    }
    
    const pathname = url.pathname;
    const normalizedPath = normalizePath(pathname, details.method);
    const key = `${details.method} ${url.origin}${normalizedPath}`;
    
    // Recollir tots els params únics
    const allParams = new Set();
    if (endpoints.has(key)) {
      endpoints.get(key).params.forEach(p => allParams.add(p));
    }
    url.searchParams.forEach(p => allParams.add(p));
    
    // Path param si aplica
    if (normalizedPath.includes('{id}')) {
      const pathParam = pathname.split('/').pop();
      if (pathParam) allParams.add(pathParam);
    }
    
    if (!endpoints.has(key)) {
      const params = Array.from(allParams);
      const sensitive = isSensitiveEndpoint(url, details.method, params);
      const tags = detectTags(url, details.method, params, details.statusCode, details.responseHeaders);
      
      endpoints.set(key, {
        method: details.method,
        url: `${url.origin}${normalizedPath}`,
        originalExamples: [pathname],
        params,
        status: details.statusCode,
        count: 1,
        sensitive,
        tags,
        detectedAt: Date.now(),
        lastSeen: Date.now()
      });
      
      // Auto-aprenentatge
      learnDynamicPattern(pathname, details.method);
      
    } else {
      const existing = endpoints.get(key);
      existing.count++;
      existing.lastSeen = Date.now();
      
      if (!existing.originalExamples.includes(pathname)) {
        existing.originalExamples.push(pathname);
      }
    }
    
    saveEndpoints();
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

/****************************
* CARREGAR PATRONS AL INICI
****************************/

browser.storage.local.get(['endpoints', 'dynamicPatterns']).then(data => {
  if (data.endpoints) {
    endpoints = new Map(
      data.endpoints.map(e => [e.method + ' ' + e.url, e])
    );
  }
  if (data.dynamicPatterns) {
    dynamicPatterns = new Map(data.dynamicPatterns);
  }
});

/****************************
* MISSATGES (clear, etc.)
****************************/

browser.runtime.onMessage.addListener((msg) => {
  if (msg?.action === "clear-endpoints") {
    endpoints.clear();
    dynamicPatterns.clear();
    browser.storage.local.set({
      endpoints: [],
      dynamicPatterns: [],
      lastUpdate: Date.now()
    });
  }
});
