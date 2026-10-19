/* InspectorKit · auditoría de cabeceras HTTP de respuesta. Sin DOM: funciona igual en Node.
   Entrada: el texto que da `curl -I`, las DevTools (copiar cabeceras de respuesta) o Burp.
   Cada hallazgo lleva una clave estable (para traducir) y un nivel: ok, info, warn, bad. */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.IKHeaders = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // Separa las respuestas (curl -L muestra una por salto) y se queda con la última.
  function parse(raw) {
    const text = String(raw || '').replace(/\r/g, '');
    const blocks = [];
    let cur = null;
    for (const line0 of text.split('\n')) {
      const line = line0.replace(/^[<>]\s?/, '').trimEnd(); // también acepta `curl -v`
      const st = line.match(/^HTTP\/(\d(?:\.\d)?)\s+(\d{3})\s*(.*)$/i);
      if (st) { cur = { version: st[1], status: +st[2], reason: st[3], headers: [] }; blocks.push(cur); continue; }
      if (!line.trim()) { continue; }
      // Formato «nombre: valor». Las DevTools a veces ponen el nombre en minúsculas o con «:» delante (HTTP/2).
      const m = line.match(/^(:?[A-Za-z0-9!#$%&'*+.^_`|~-]+)\s*:\s?(.*)$/);
      if (!m) continue;
      if (!cur) { cur = { version: null, status: null, reason: '', headers: [] }; blocks.push(cur); }
      if (m[1] === ':status') { cur.status = +m[2]; continue; }
      if (m[1].startsWith(':')) continue;
      cur.headers.push({ name: m[1], value: m[2].trim() });
    }
    const withHeaders = blocks.filter(b => b.headers.length);
    const last = withHeaders[withHeaders.length - 1] || null;
    return { blocks, last, redirects: blocks.length > 1 ? blocks.slice(0, -1).map(b => b.status).filter(Boolean) : [] };
  }

  function getAll(h, name) { name = name.toLowerCase(); return h.filter(x => x.name.toLowerCase() === name).map(x => x.value); }
  function get(h, name) { const v = getAll(h, name); return v.length ? v.join(', ') : null; }

  function parseCSP(v) {
    const dirs = {};
    for (const part of String(v).split(';')) {
      const t = part.trim().split(/\s+/).filter(Boolean);
      if (!t.length) continue;
      const name = t[0].toLowerCase();
      if (!(name in dirs)) dirs[name] = t.slice(1);
    }
    return dirs;
  }

  function analyzeCSP(v, findings, reportOnly) {
    const d = parseCSP(v);
    const src = d['script-src'] || d['default-src'];
    const add = (level, key, vars) => findings.push({ header: reportOnly ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy', level, key, vars });
    if (!src) add('warn', 'csp.noScriptSrc');
    else {
      const hasNonceHash = src.some(s => /^'(nonce-|sha(256|384|512)-)/i.test(s));
      const strictDyn = src.includes("'strict-dynamic'");
      if (src.includes("'unsafe-inline'") && !hasNonceHash) add('bad', 'csp.unsafeInline');
      if (src.includes("'unsafe-eval'")) add('warn', 'csp.unsafeEval');
      if (!strictDyn && src.some(s => s === '*' || s === 'http:' || s === 'https:' || s === 'data:' || s === 'blob:')) add('bad', 'csp.wildcard', { v: src.filter(s => ['*', 'http:', 'https:', 'data:', 'blob:'].includes(s)).join(' ') });
      if (!strictDyn && src.some(s => /^(https?:\/\/)?\*\./.test(s))) add('warn', 'csp.wildSub');
    }
    const obj = d['object-src'] || d['default-src'];
    if (!obj || !(obj.length === 1 && obj[0] === "'none'")) add('warn', 'csp.objectSrc');
    if (!d['base-uri']) add('warn', 'csp.baseUri');
    if (!d['frame-ancestors']) add('info', 'csp.frameAncestors');
    if (!d['form-action']) add('info', 'csp.formAction');
    if (d['report-uri'] && !d['report-to']) add('info', 'csp.reportUri');
    return d;
  }

  function parseCookie(v) {
    const parts = v.split(';').map(s => s.trim());
    const [nv, ...attrs] = parts;
    const eq = nv.indexOf('=');
    const c = { name: eq >= 0 ? nv.slice(0, eq) : nv, secure: false, httpOnly: false, sameSite: null, domain: null, path: null, expires: null, maxAge: null };
    for (const a of attrs) {
      const [k, ...rest] = a.split('=');
      const key = k.trim().toLowerCase(), val = rest.join('=').trim();
      if (key === 'secure') c.secure = true;
      else if (key === 'httponly') c.httpOnly = true;
      else if (key === 'samesite') c.sameSite = val.toLowerCase();
      else if (key === 'domain') c.domain = val;
      else if (key === 'path') c.path = val;
      else if (key === 'expires') c.expires = val;
      else if (key === 'max-age') c.maxAge = val;
    }
    c.issues = [];
    const sessionish = /sess|sid|auth|token|jwt|login|remember|csrf|xsrf/i.test(c.name);
    if (!c.secure) c.issues.push({ level: sessionish ? 'bad' : 'warn', key: 'cookie.noSecure' });
    if (!c.httpOnly && !/csrf|xsrf/i.test(c.name)) c.issues.push({ level: sessionish ? 'bad' : 'info', key: 'cookie.noHttpOnly' });
    if (!c.sameSite) c.issues.push({ level: 'info', key: 'cookie.noSameSite' });
    else if (c.sameSite === 'none' && !c.secure) c.issues.push({ level: 'bad', key: 'cookie.noneInsecure' });
    if (c.name.startsWith('__Host-') && (!c.secure || c.domain || c.path !== '/')) c.issues.push({ level: 'bad', key: 'cookie.hostPrefix' });
    if (c.name.startsWith('__Secure-') && !c.secure) c.issues.push({ level: 'bad', key: 'cookie.securePrefix' });
    c.sessionish = sessionish;
    return c;
  }

  // Puntuación: se parte de 100 y cada ausencia o error resta (los pesos siguen el criterio de
  // securityheaders.com y de la guía OWASP Secure Headers; es orientativa, no una certificación).
  const WEIGHT = { bad: 12, warn: 3, info: 0, ok: 0 };

  function analyze(raw, opts) {
    opts = opts || {};
    const parsed = parse(raw);
    if (!parsed.last) return { error: 'noHeaders' };
    const h = parsed.last.headers;
    const https = opts.https != null ? opts.https : !/^http:/i.test(opts.url || '');
    const findings = [];
    const add = (header, level, key, vars) => findings.push({ header, level, key, vars });

    // HSTS
    const hsts = get(h, 'Strict-Transport-Security');
    if (!https) add('Strict-Transport-Security', 'bad', 'hsts.http');
    else if (!hsts) add('Strict-Transport-Security', 'bad', 'hsts.missing');
    else {
      const ma = (hsts.match(/max-age\s*=\s*"?(\d+)/i) || [])[1];
      const age = ma == null ? null : +ma;
      if (age == null) add('Strict-Transport-Security', 'bad', 'hsts.noMaxAge');
      else if (age === 0) add('Strict-Transport-Security', 'bad', 'hsts.zero');
      else if (age < 15552000) add('Strict-Transport-Security', 'warn', 'hsts.short', { days: Math.round(age / 86400) });
      else add('Strict-Transport-Security', 'ok', 'hsts.ok', { days: Math.round(age / 86400) });
      if (age && !/includesubdomains/i.test(hsts)) add('Strict-Transport-Security', 'info', 'hsts.noSub');
      if (/preload/i.test(hsts)) add('Strict-Transport-Security', 'info', 'hsts.preload');
    }

    // CSP
    const csp = get(h, 'Content-Security-Policy');
    const cspRO = get(h, 'Content-Security-Policy-Report-Only');
    let cspDirs = null;
    if (csp) {
      const before = findings.length;
      cspDirs = analyzeCSP(csp, findings, false);
      if (!findings.slice(before).some(f => f.level === 'bad')) add('Content-Security-Policy', 'ok', 'csp.ok');
    } else if (cspRO) {
      add('Content-Security-Policy', 'bad', 'csp.reportOnly');
      analyzeCSP(cspRO, findings, true);
    } else add('Content-Security-Policy', 'bad', 'csp.missing');

    // Clickjacking: XFO o CSP frame-ancestors
    const xfo = get(h, 'X-Frame-Options');
    const fa = cspDirs && cspDirs['frame-ancestors'];
    if (xfo) {
      const v = xfo.trim().toUpperCase();
      if (v === 'DENY' || v === 'SAMEORIGIN') add('X-Frame-Options', 'ok', 'xfo.ok', { v });
      else if (v.startsWith('ALLOW-FROM')) add('X-Frame-Options', fa ? 'info' : 'warn', 'xfo.allowFrom');
      else add('X-Frame-Options', fa ? 'info' : 'warn', 'xfo.invalid', { v: xfo });
    } else if (fa) add('X-Frame-Options', 'ok', 'xfo.byCsp', { v: fa.join(' ') });
    else add('X-Frame-Options', 'bad', 'xfo.missing');

    const xcto = get(h, 'X-Content-Type-Options');
    if (!xcto) add('X-Content-Type-Options', 'warn', 'xcto.missing');
    else if (xcto.trim().toLowerCase() !== 'nosniff') add('X-Content-Type-Options', 'warn', 'xcto.invalid', { v: xcto });
    else add('X-Content-Type-Options', 'ok', 'xcto.ok');

    const rp = get(h, 'Referrer-Policy');
    if (!rp) add('Referrer-Policy', 'warn', 'rp.missing');
    else {
      const last = rp.split(',').map(s => s.trim().toLowerCase()).filter(Boolean).pop();
      if (last === 'unsafe-url' || last === 'no-referrer-when-downgrade') add('Referrer-Policy', 'warn', 'rp.weak', { v: last });
      else add('Referrer-Policy', 'ok', 'rp.ok', { v: last });
    }

    const pp = get(h, 'Permissions-Policy');
    if (pp) add('Permissions-Policy', 'ok', 'pp.ok');
    else if (get(h, 'Feature-Policy')) add('Permissions-Policy', 'info', 'pp.feature');
    else add('Permissions-Policy', 'warn', 'pp.missing');

    // X-XSS-Protection está obsoleta: lo recomendado es no enviarla o enviar «0».
    const xxp = get(h, 'X-XSS-Protection');
    if (xxp && xxp.trim() !== '0') add('X-XSS-Protection', 'info', 'xxp.legacy', { v: xxp });
    else if (xxp) add('X-XSS-Protection', 'ok', 'xxp.zero');

    // Aislamiento entre orígenes (informativo)
    const coop = get(h, 'Cross-Origin-Opener-Policy');
    if (coop) add('Cross-Origin-Opener-Policy', 'ok', 'coop.ok', { v: coop });
    else add('Cross-Origin-Opener-Policy', 'info', 'coop.missing');
    const corp = get(h, 'Cross-Origin-Resource-Policy');
    if (corp) add('Cross-Origin-Resource-Policy', 'ok', 'corp.ok', { v: corp });

    // CORS
    const acao = get(h, 'Access-Control-Allow-Origin');
    const acac = get(h, 'Access-Control-Allow-Credentials');
    if (acao) {
      if (acao.trim() === '*' && acac && /true/i.test(acac)) add('Access-Control-Allow-Origin', 'bad', 'cors.starCred');
      else if (acao.trim() === 'null') add('Access-Control-Allow-Origin', 'bad', 'cors.null');
      else if (acao.trim() === '*') add('Access-Control-Allow-Origin', 'info', 'cors.star');
      else add('Access-Control-Allow-Origin', 'info', 'cors.origin', { v: acao, cred: !!(acac && /true/i.test(acac)) });
    }

    // Fugas de información sobre el software del servidor
    const leak = (name) => { const v = get(h, name); if (v) add(name, /\d/.test(v) ? 'warn' : 'info', /\d/.test(v) ? 'leak.version' : 'leak.product', { v }); };
    ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version', 'X-Generator', 'X-Drupal-Cache', 'X-Runtime', 'X-Backend-Server', 'X-Debug-Token'].forEach(leak);

    // Cookies
    const cookies = getAll(h, 'Set-Cookie').map(parseCookie);
    for (const c of cookies) for (const i of c.issues) add('Set-Cookie', i.level, i.key, { name: c.name });

    // Caché de respuestas que fijan cookie de sesión
    const cc = get(h, 'Cache-Control');
    if (cookies.some(c => c.sessionish) && !(cc && /no-store|private/i.test(cc))) add('Cache-Control', 'warn', 'cache.session');

    let score = 100;
    for (const f of findings) score -= WEIGHT[f.level] || 0;
    score = Math.max(0, score);
    const present = (n) => !!get(h, n);
    // Nota tipo securityheaders.com: cuenta las seis cabeceras principales.
    const core = ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Permissions-Policy'];
    const have = core.filter(n => present(n) || (n === 'X-Frame-Options' && fa)).length;
    let grade = ['F', 'F', 'E', 'D', 'C', 'B', 'A'][have];
    if (have === 6 && !findings.some(f => f.level === 'bad' || f.level === 'warn')) grade = 'A+';
    if (findings.some(f => f.level === 'bad') && grade.startsWith('A')) grade = 'B';

    return { status: parsed.last.status, version: parsed.last.version, redirects: parsed.redirects, headers: h, cookies, findings, score, grade, coreHave: have, coreTotal: core.length, https };
  }

  // Cabeceras que el navegador deja leer a una página de otro origen (CORS-safelisted) sin Access-Control-Expose-Headers.
  const SAFELISTED = ['cache-control', 'content-language', 'content-length', 'content-type', 'expires', 'last-modified', 'pragma'];

  function commands(url) {
    const u = String(url || '').trim();
    if (!/^https?:\/\/[^\s"'`$;|&<>]+$/i.test(u)) return null;
    return {
      curl: `curl -sS -I -L "${u}"`,
      curlGet: `curl -sS -D - -o /dev/null -L "${u}"`,
      windows: `curl.exe -sS -I -L "${u}"`,
      powershell: `(Invoke-WebRequest -Uri "${u}" -Method Head -UseBasicParsing).RawContent`,
    };
  }

  return { parse, analyze, parseCSP, parseCookie, commands, SAFELISTED };
});
