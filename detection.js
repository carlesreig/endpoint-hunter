/* Detection helpers (pure, testable)
 * Exposes:
 * - isInteresting(details, cfg)
 * - detectTags(url, method, params, status, cfg)
 * - isSensitiveEndpoint(url, method, params, cfg)
 *
 * Uses ENDPOINT_HUNTER_CONFIG as defaults when available.
 */
(function(){
  const _CFG = globalThis.ENDPOINT_HUNTER_CONFIG || {};

  function _ensureURL(u) {
    if (u instanceof URL) return u;
    try { return new URL(String(u)); } catch (e) { return null; }
  }

  function isSensitiveEndpoint(url, method, params = [], cfg = _CFG) {
    const urlObj = _ensureURL(url);
    const path = urlObj ? urlObj.pathname.toLowerCase() : String(url).toLowerCase();
    const SENSITIVE_METHODS = cfg.SENSITIVE_METHODS || [];
    const SENSITIVE_PATHS = cfg.SENSITIVE_PATHS || [];
    const SENSITIVE_PARAMS = (cfg.SENSITIVE_PARAMS || []).map(s=>s.toLowerCase());

    if (SENSITIVE_METHODS.includes(method)) return true;
    if (SENSITIVE_PATHS.some(p => path.includes(p))) return true;
    if ((params||[]).some(p => SENSITIVE_PARAMS.includes(String(p).toLowerCase()))) return true;

    if (/\/(login|admin|auth|account)\.php$/.test(path)) return true;

    return false;
  }

  function detectTags(url, method, params = [], status = 0, cfg = _CFG) {
    const urlObj = _ensureURL(url);
    const path = urlObj ? urlObj.pathname.toLowerCase() : '';
    const lowerParams = (params||[]).map(p => String(p||'').toLowerCase());

    const values = [];
    try { for (const v of (urlObj?.searchParams?.values() || [])) values.push((v||'').toLowerCase()); } catch(e){}

    const xssValuePattern = /<\s*script|%3cscript|&lt;script|on\w+\s*=|javascript:|%3c|%3e|<[^>]+>/i;
    const sqliValuePattern = /('|")\s*(or|and)\s+\d+\s*=\s*\d+|--|\/\*|\bunion\b|\bselect\b|\bdrop\b|\binsert\b/i;

    const valueLooksLikeXss = values.some(v => xssValuePattern.test(v));
    const valueLooksLikeSqli = values.some(v => sqliValuePattern.test(v));

    const TAG_RULES = cfg.TAG_RULES || {};
    const xssParams = (TAG_RULES.xss?.params || []).map(p => p.toLowerCase());
    const xssMethods = TAG_RULES.xss?.methods || [];
    const sqliParams = (TAG_RULES.sqli?.params || []).map(p => p.toLowerCase());
    const sqliMethods = TAG_RULES.sqli?.methods || [];
    const lfiParams = (TAG_RULES.lfi?.params || []).map(p => p.toLowerCase());
    const lfiMethods = TAG_RULES.lfi?.methods || [];
    const idorParams = (TAG_RULES.idor?.params || []).map(p => p.toLowerCase());
    const idorMethods = TAG_RULES.idor?.methods || [];
    const authPaths = TAG_RULES.auth?.paths || [];

    const xssDetected = (xssMethods.includes(method) && (lowerParams.some(p => xssParams.includes(p)) || valueLooksLikeXss || path.includes('search') || path.includes('query')));
    const sqliDetected = (sqliMethods.includes(method) && (lowerParams.some(p => sqliParams.includes(p)) || valueLooksLikeSqli));


    return {
      xss: !!xssDetected,
      sqli: !!sqliDetected,
      lfi: !!(TAG_RULES.lfi.methods.includes(method) && lowerParams.some(p => TAG_RULES.lfi.params.includes(p))),
      idor: !!(TAG_RULES.idor.methods.includes(method) && (lowerParams.some(p => TAG_RULES.idor.params.includes(p)) || /\d+/.test(path))),
      auth: !!(TAG_RULES.auth.paths.some(p => path.includes(p)) || status === 401 || status === 403)
    };
  }

  function isInteresting(details = {}, cfg = _CFG) {
    const urlStr = details.url || details.
    url || '';
    const type = details.type || '';
    const method = details.method || 'GET';
    const urlLower = String(urlStr).toLowerCase();

    const IGNORED_EXTENSIONS = cfg.IGNORED_EXTENSIONS || ['.jpg','.jpeg','.png','.gif','.svg','.webp','.woff','.ttf','.ico'];
    if (IGNORED_EXTENSIONS.some(ext => urlLower.includes(ext))) return false;

    if (urlLower.includes('.php')) return true;
    if (type === 'xmlhttprequest' || type === 'fetch') return true;
    if (urlLower.includes('.css') && type !== 'xmlhttprequest') return false;
    if (urlLower.includes('.js') && (type === 'xmlhttprequest' || urlLower.includes('config') || urlLower.includes('api') || urlLower.includes('admin') || (!urlLower.includes('/static/') && !urlLower.includes('/assets/')))) return true;

    return false;
  }

  // Expose
  const DET = {
    isInteresting,
    detectTags,
    isSensitiveEndpoint
  };

  globalThis.ENDPOINT_HUNTER_DETECTION = DET;
  if (typeof module !== 'undefined' && module.exports) module.exports = DET;
})();