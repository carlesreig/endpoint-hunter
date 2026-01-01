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

    if (/\/(?:.*[-_])?(login|admin|auth|account).*\.(php|asp|aspx|jsp|jspx|action|do|cgi)$/.test(path)) return true;

    return false;
  }

  function detectTags(url, method, params = [], status = 0, responseHeaders = [], cfg = _CFG) {
    const urlObj = _ensureURL(url);
    const path = urlObj ? urlObj.pathname.toLowerCase() : '';
    const lowerParams = (params||[]).map(p => String(p||'').toLowerCase());

    // Helper per obtenir headers de forma segura i case-insensitive
    const getHeader = (name) => {
      if (!responseHeaders || !Array.isArray(responseHeaders)) return '';
      const h = responseHeaders.find(x => x.name && x.name.toLowerCase() === name.toLowerCase());
      return h ? (h.value || '').toLowerCase() : '';
    };
    const contentType = getHeader('content-type');
    const csp = getHeader('content-security-policy');
    const contentDisposition = getHeader('content-disposition');
    const location = getHeader('location');
    const wwwAuth = getHeader('www-authenticate');

    const values = [];
    try { for (const v of (urlObj?.searchParams?.values() || [])) values.push((v||'').toLowerCase()); } catch(e){}

    const xssValuePattern = /<\s*script|%3cscript|&lt;script|on\w+\s*=|javascript:|%3c|%3e|<[^>]+>/i;
    const sqliValuePattern = /('|")\s*(or|and)\s+\d+\s*=\s*\d+|--|\/\*|\bunion\b|\bselect\b|\bdrop\b|\binsert\b|\bupdate\b|\bdelete\b|\bbenchmark\b|\bsleep\b/i;
    const lfiValuePattern = /(\.\.[\/\\])|(\/etc\/(passwd|shadow|group|hosts))|(c:\\windows)|(\bboot\.ini\b)/i;
    const rceValuePattern = /(;|\||&|`|\$\(|\b(system|exec|shell_exec|passthru|cmd|powershell)\b)/i;
    const ssrfValuePattern = /(https?|ftp|file|gopher|dict|ldap|tftp):\/\//i;

    const valueLooksLikeXss = values.some(v => xssValuePattern.test(v));
    const valueLooksLikeSqli = values.some(v => sqliValuePattern.test(v));
    const valueLooksLikeLfi = values.some(v => lfiValuePattern.test(v));
    const valueLooksLikeRce = values.some(v => rceValuePattern.test(v));
    const valueLooksLikeSsrf = values.some(v => ssrfValuePattern.test(v));

    const TAG_RULES = cfg.TAG_RULES || {};
    const xssParams = (TAG_RULES.xss?.params || []).map(p => p.toLowerCase());
    const xssMethods = TAG_RULES.xss?.methods || [];
    const sqliParams = (TAG_RULES.sqli?.params || []).map(p => p.toLowerCase());
    const sqliMethods = TAG_RULES.sqli?.methods || [];
    const lfiParams = (TAG_RULES.lfi?.params || []).map(p => p.toLowerCase());
    const lfiPaths = (TAG_RULES.lfi?.paths || []).map(p => p.toLowerCase());
    const lfiMethods = TAG_RULES.lfi?.methods || [];
    const idorParams = (TAG_RULES.idor?.params || []).map(p => p.toLowerCase());
    const idorMethods = TAG_RULES.idor?.methods || [];
    const rceParams = (TAG_RULES.rce?.params || []).map(p => p.toLowerCase());
    const rceMethods = TAG_RULES.rce?.methods || [];
    const ssrfParams = (TAG_RULES.ssrf?.params || []).map(p => p.toLowerCase());
    const ssrfMethods = TAG_RULES.ssrf?.methods || [];
    const authPaths = TAG_RULES.auth?.paths || [];
    const authMethods = TAG_RULES.auth?.methods || [];
    const authParams = (TAG_RULES.auth?.params || []).map(p => p.toLowerCase());

    // XSS: Params típics + HTML + CSP dèbil
    const isHtml = contentType.includes('text/html');
    const isWeakCsp = !csp || csp.includes('unsafe-inline') || csp.includes('unsafe-eval');
    const xssParamMatch = lowerParams.some(p => xssParams.includes(p));
    const xssContext = isHtml && isWeakCsp;
    const xssDetected = xssMethods.includes(method) && (
      valueLooksLikeXss || // Payload explícit
      (xssParamMatch && xssContext) || // Param típic en context vulnerable
      ((path.includes('search') || path.includes('query')) && xssContext)
    );

    const sqliDetected = (sqliMethods.includes(method) && (lowerParams.some(p => sqliParams.includes(p)) || valueLooksLikeSqli));
    
    // LFI: Params o Paths sospitosos + Headers de fitxer
    const lfiHeaderMatch = contentType.includes('application/octet-stream') || contentDisposition.includes('attachment');
    const lfiDetected = lfiMethods.includes(method) && (
      lowerParams.some(p => lfiParams.includes(p)) || 
      valueLooksLikeLfi ||
      (lfiPaths.some(p => path.includes(p)) && lfiHeaderMatch)
    );

    // RCE: Context d'error o text pla per evitar falsos positius en params genèrics
    const rceParamMatch = lowerParams.some(p => rceParams.includes(p));
    const rceContext = contentType.includes('text/plain') || status >= 500;
    const rceDetected = rceMethods.includes(method) && (
      valueLooksLikeRce ||
      (rceParamMatch && rceContext) // Només marquem param genèric si el context és sospitós
    );

    // SSRF: Param + Redirect (Location)
    const ssrfDetected = ssrfMethods.includes(method) && (
      valueLooksLikeSsrf || 
      lowerParams.some(p => ssrfParams.includes(p)) // Mantenim param match com a base, headers són bonus
    );

    // Auth: Mètodes sensibles, 403 o falta de header WWW-Authenticate
    const authDetected = (
      authPaths.some(p => path.includes(p)) || 
      authMethods.includes(method) || 
      lowerParams.some(p => authParams.includes(p)) ||
      status === 403 || 
      (status === 401 && !wwwAuth)
    );


    return {
      xss: !!xssDetected,
      sqli: !!sqliDetected,
      lfi: !!lfiDetected,
      idor: !!(idorMethods.includes(method) && (lowerParams.some(p => idorParams.includes(p)) || /\d+/.test(path))),
      auth: !!authDetected,
      rce: !!rceDetected,
      ssrf: !!ssrfDetected
    };
  }

  function isInteresting(details = {}, cfg = _CFG) {
    const urlStr = details.url || details.
    url || '';
    const type = details.type || '';
    const method = details.method || 'GET';
    const urlLower = String(urlStr).toLowerCase();

    const IGNORED_EXTENSIONS = cfg.IGNORED_EXTENSIONS || ['.jpg','.jpeg','.png','.gif','.svg','.webp','.woff','.ttf','.m4s','.ico'];
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