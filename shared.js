/* Shared helpers for Endpoint Hunter UI
 * These are small pure or DOM helper functions reused by `panel.js` and `devtools.js`.
 */

// Extract base domain from hostname: example.com from www.example.com
function getBaseDomain(hostname) {
  const parts = String(hostname||'').toLowerCase().split('.');
  if (parts.length <= 2) return hostname.toLowerCase();
  return parts.slice(-2).join('.');
}

function formatParams(params) {
  if (!params || !params.length) return "-";
  return params.join(", ");
}

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

// Obtain inspected hostname using devtools APIs (works in DevTools context)
async function getInspectedHostname() {
  const candidates = [
    "window.location.hostname",
    "window.location.host",
    "document.domain",
    "window.location.href"
  ];

  function tryEval(expr) {
    return new Promise((resolve) => {
      try {
        // Callback-style
        browser.devtools.inspectedWindow.eval(expr, (result, exception) => {
          if (exception) return resolve(null);
          if (!result) return resolve(null);
          if (typeof result === 'string') return resolve(result);
          if (result && result.value) return resolve(result.value);
          return resolve(null);
        });
      } catch (err) {
        // Promise-style fallback
        try {
          const p = browser.devtools.inspectedWindow.eval(expr);
          if (p && typeof p.then === 'function') {
            p.then(res => {
              if (!res) return resolve(null);
              if (typeof res === 'string') return resolve(res);
              if (res && res.value) return resolve(res.value);
              return resolve(null);
            }).catch(() => resolve(null));
          } else {
            resolve(null);
          }
        } catch (e) {
          resolve(null);
        }
      }
    });
  }

  return new Promise(async (resolve) => {
    for (const expr of candidates) {
      const res = await tryEval(expr);
      if (res) {
        try {
          const maybeUrl = res.toString();
          if (expr === 'window.location.href' && (maybeUrl.startsWith('http') || maybeUrl.startsWith('//'))) {
            try { const u = new URL(maybeUrl); return resolve(u.hostname); } catch {};
          }
          const host = maybeUrl.split(':')[0];
          if (host) return resolve(host);
        } catch (e) {
          return resolve(res);
        }
      }
    }
    resolve(null);
  });
}

// Expose on global so legacy scripts can call them directly
window.EH = window.EH || {};
window.EH.getBaseDomain = getBaseDomain;
window.EH.formatParams = formatParams;
window.EH.createSVGIcon = createSVGIcon;
window.EH.getInspectedHostname = getInspectedHostname;
