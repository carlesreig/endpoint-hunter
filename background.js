// ✅ Declaració paths, params i mètodes sensibles
const SENSITIVE_PATHS = [
  "/admin","/api","/auth","/login","/logout",
  "/token","/user","/users","/account",
  "/internal","/private","/debug","/graphql"
];

const SENSITIVE_PARAMS = [
  "token","auth","key","password","pwd",
  "session","jwt","csrf"
];

const SENSITIVE_METHODS = ["PUT","DELETE","PATCH"];

// Funció per determinar si un endpoint és sensible
function isSensitiveEndpoint(url, method, params) {
  const path = url.pathname.toLowerCase();

  if (SENSITIVE_METHODS.includes(method)) return true;
  if (SENSITIVE_PATHS.some(p => path.includes(p))) return true;
  if (params.some(p => SENSITIVE_PARAMS.includes(p.toLowerCase()))) return true;

  return false;
}

// Font de veritat
let endpoints = new Map();

// Determina si la request és interessant
function isInteresting(details) {
  return details.type === "xmlhttprequest" || details.type === "fetch";
}

// Debounce helper per guardar storage (cada 500ms màx)
let saveTimeout = null;
function saveEndpoints() {
  if (saveTimeout) clearTimeout(saveTimeout);
  saveTimeout = setTimeout(() => {
    browser.storage.local.set({
      endpoints: Array.from(endpoints.values())
    });
  }, 500);
}

// Intercepta peticions
browser.webRequest.onCompleted.addListener(
  (details) => {
    if (!isInteresting(details)) return;

    const url = new URL(details.url);
    const key = `${details.method} ${url.origin}${url.pathname}`;

    if (!endpoints.has(key)) {
      const params = [...url.searchParams.keys()];

      const sensitive = isSensitiveEndpoint(url, details.method, params);

      const endpoint = {
        method: details.method,
        url: url.origin + url.pathname,
        params,
        status: details.statusCode,
        count: 1,
        sensitive,
        detectedAt: Date.now()
      };

      endpoints.set(key, endpoint);

      // Canvia icona només si és sensible
      if (sensitive) {
        browser.browserAction.setIcon({ path: "icons/icon-alert.png" });
      }
    } else {
      endpoints.get(key).count++;
    }

    // Guarda endpoints amb debounce
    saveEndpoints();
  },
  { urls: ["<all_urls>"] }
);

// Missatges del popup
browser.runtime.onMessage.addListener((msg) => {
  if (msg.action === "clear-endpoints") {
    endpoints.clear();
    browser.storage.local.set({ endpoints: [] });

    // Torna icona normal
    browser.browserAction.setIcon({ path: "icons/icon-48.png" });

    // Eliminat console.log per AMO
    // console.log("🧹 Endpoints eliminats definitivament");
  }
});
