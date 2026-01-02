/****************************
* CONFIG: externalitzat a `src/lib/config.js`
****************************/

// controlador principal. S'encarrega d'escoltar els esdeveniments del navegador (webRequest), 
// gestionar la memòria (l'estat dels endpoints detectats), guardar les dades (storage) 
// i coordinar l'aprenentatge de patrons.

// Load configuration constants from global `ENDPOINT_HUNTER_CONFIG` (set in config.js)
// Provide safe defaults if the config object is not present (backwards compatible).
const _CFG = globalThis.ENDPOINT_HUNTER_CONFIG || {};

const DEBUG = false;
function bgLog(...args) { if (DEBUG) console.log(...args); }

/****************************
* HELPERS
****************************/

function isSensitiveEndpoint(url, method, params, responseHeaders) {
  return globalThis.ENDPOINT_HUNTER_DETECTION?.isSensitiveEndpoint
    ? globalThis.ENDPOINT_HUNTER_DETECTION.isSensitiveEndpoint(url, method, params, _CFG)
    : false;
}

function detectTags(url, method, params, status, responseHeaders) {
  return globalThis.ENDPOINT_HUNTER_DETECTION?.detectTags
    ? globalThis.ENDPOINT_HUNTER_DETECTION.detectTags(url, method, params, status, responseHeaders, _CFG)
    : {};
}

function isInteresting(details) {
  return globalThis.ENDPOINT_HUNTER_DETECTION?.isInteresting
    ? globalThis.ENDPOINT_HUNTER_DETECTION.isInteresting(details, _CFG)
    : false;
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
    const currentParamValues = {};

    if (endpoints.has(key)) {
      endpoints.get(key).params.forEach(p => allParams.add(p));
    }
    url.searchParams.forEach((v, k) => {
      allParams.add(k);
      currentParamValues[k] = v;
    });
    
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
        latestValues: currentParamValues,
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
      existing.latestValues = { ...(existing.latestValues || {}), ...currentParamValues };
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
