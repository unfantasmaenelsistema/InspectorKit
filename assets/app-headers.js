/* InspectorKit · pestaña Cabeceras: auditoría de cabeceras HTTP de seguridad */
(function () {
  'use strict';
  const { t, esc } = IK;
  const H = IKHeaders;
  const $ = (id) => document.getElementById(id);

  IK.addI18n({
    es: {
      'hd.inT': 'Cabeceras HTTP de respuesta',
      'hd.why': '<b>¿Por qué hay que pegarlas?</b> Una página web no puede leer las cabeceras de otra web: el navegador bloquea la petición por CORS o, si la deja pasar, solo enseña siete cabeceras «inofensivas» (Content-Type, Cache-Control…). La versión anterior (HttpInspector) daba por «faltantes» cabeceras que sí estaban. Aquí se sacan con <code>curl</code> o con las DevTools (pestaña Red → la petición → Cabeceras de respuesta) y se pegan.',
      'hd.url': 'URL (para generar las órdenes)', 'hd.try': 'Probar desde el navegador', 'hd.paste': 'Pega aquí las cabeceras de respuesta',
      'hd.pastePh': 'HTTP/2 200\ncontent-type: text/html\nstrict-transport-security: max-age=31536000\n…\n(salida de curl -I, curl -v, DevTools o Burp)',
      'hd.go': 'Analizar', 'hd.sample': 'Ejemplo', 'hd.clear': 'Limpiar', 'hd.https': 'La respuesta llegó por HTTPS',
      'hd.cmdT': 'Órdenes para obtener las cabeceras', 'hd.cmdLinux': 'Linux / macOS / Git Bash', 'hd.cmdWin': 'Windows (cmd o PowerShell)', 'hd.cmdPs': 'PowerShell (sin curl)', 'hd.cmdGet': 'Si el servidor no responde bien a HEAD',
      'hd.badUrl': 'Escribe una URL completa que empiece por http:// o https://.',
      'hd.tryOk': 'El navegador ha recibido la respuesta, pero solo deja ver estas {n} cabeceras. Las de seguridad (HSTS, CSP, X-Frame-Options…) quedan ocultas para cualquier web de otro origen, así que esto no sirve para auditar: usa las órdenes de arriba.',
      'hd.tryFail': 'El navegador ha bloqueado la petición (lo normal: la web no permite peticiones desde otros orígenes, CORS). No significa que la web falle. Usa las órdenes de arriba.',
      'hd.noHeaders': 'No se han encontrado cabeceras en el texto. Tiene que haber líneas «Nombre: valor».',
      'hd.grade': 'Nota', 'hd.score': 'Puntuación {s}/100 · {have} de {total} cabeceras principales', 'hd.status': 'Estado HTTP {s}', 'hd.redirects': 'Redirecciones previas: {r}',
      'hd.findingsT': 'Hallazgos', 'hd.header': 'Cabecera', 'hd.finding': 'Qué pasa y qué hacer', 'hd.cookiesT': 'Cookies', 'hd.rawT': 'Cabeceras recibidas ({n})',
      'hd.c.name': 'Nombre', 'hd.c.issues': 'Problemas', 'hd.md': 'Copiar informe (Markdown)', 'hd.mdT': 'Informe de cabeceras', 'hd.note': 'La nota sigue el criterio de securityheaders.com (seis cabeceras principales) y la puntuación resta por cada problema. Es orientativa: una cabecera presente pero mal configurada también cuenta.',
      'hf.hsts.http': 'La respuesta es HTTP sin cifrar: todo viaja en claro. Sirve la web solo por HTTPS y redirige el puerto 80.',
      'hf.hsts.missing': 'Falta HSTS: un atacante en la red puede forzar la primera visita por HTTP (SSL stripping). Añade «Strict-Transport-Security: max-age=31536000; includeSubDomains».',
      'hf.hsts.noMaxAge': 'HSTS sin max-age no tiene efecto. Añade «max-age=31536000».', 'hf.hsts.zero': 'max-age=0 desactiva HSTS en los navegadores que lo tenían guardado.',
      'hf.hsts.short': 'HSTS caduca demasiado pronto (max-age ≈ {days} d); se recomiendan al menos 180 días (mejor un año).', 'hf.hsts.ok': 'HSTS activo (max-age ≈ {days} d).',
      'hf.hsts.noSub': 'No incluye includeSubDomains: los subdominios quedan fuera de la protección.', 'hf.hsts.preload': 'Pide entrar en la lista de precarga de los navegadores (hstspreload.org).',
      'hf.csp.missing': 'Falta Content-Security-Policy: no hay nada que limite qué scripts se ejecutan si se cuela un XSS. Empieza por «default-src \'self\'; object-src \'none\'; base-uri \'self\'; frame-ancestors \'self\'».',
      'hf.csp.reportOnly': 'Solo hay CSP en modo «Report-Only»: informa, pero no bloquea nada.', 'hf.csp.ok': 'CSP presente sin fallos graves en script-src.',
      'hf.csp.noScriptSrc': 'La CSP no tiene script-src ni default-src: no protege frente a XSS (seguramente solo controla el enmarcado).',
      'hf.csp.unsafeInline': '«\'unsafe-inline\'» en script-src sin nonce ni hash anula casi toda la protección frente a XSS. Usa nonces o hashes.',
      'hf.csp.unsafeEval': '«\'unsafe-eval\'» permite eval() y similares: quítalo si la aplicación no lo necesita.',
      'hf.csp.wildcard': 'script-src admite orígenes demasiado amplios ({v}): cualquiera puede alojar ahí un script.', 'hf.csp.wildSub': 'Comodines de subdominio en script-src: cualquier subdominio (incluidos los olvidados) puede servir scripts.',
      'hf.csp.objectSrc': 'Falta «object-src \'none\'»: los plugins (object/embed) siguen siendo una vía de ejecución.', 'hf.csp.baseUri': 'Falta base-uri: un <base> inyectado puede redirigir los scripts relativos. Añade «base-uri \'self\'».',
      'hf.csp.frameAncestors': 'La CSP no define frame-ancestors (se puede usar en lugar de X-Frame-Options).', 'hf.csp.formAction': 'La CSP no define form-action: los formularios pueden enviarse a cualquier sitio.',
      'hf.csp.reportUri': 'Usa report-uri, que está obsoleto; añade también report-to.',
      'hf.xfo.ok': 'Protección contra clickjacking: X-Frame-Options {v}.', 'hf.xfo.byCsp': 'Protección contra clickjacking mediante CSP frame-ancestors ({v}).',
      'hf.xfo.allowFrom': 'ALLOW-FROM está obsoleto y los navegadores modernos lo ignoran: usa CSP frame-ancestors.', 'hf.xfo.invalid': 'Valor de X-Frame-Options no válido: «{v}».',
      'hf.xfo.missing': 'Sin protección contra clickjacking: la página se puede enmarcar en otra web. Añade «X-Frame-Options: DENY» o «frame-ancestors \'self\'» en la CSP.',
      'hf.xcto.missing': 'Falta «X-Content-Type-Options: nosniff»: el navegador puede adivinar el tipo de un archivo y ejecutarlo como script.', 'hf.xcto.invalid': 'X-Content-Type-Options solo admite «nosniff» (tiene «{v}»).', 'hf.xcto.ok': 'nosniff activo.',
      'hf.rp.missing': 'Falta Referrer-Policy (los navegadores usan strict-origin-when-cross-origin por defecto, pero conviene fijarla).', 'hf.rp.weak': 'Referrer-Policy «{v}» envía la URL completa a otros sitios: puede filtrar tokens de la URL.', 'hf.rp.ok': 'Referrer-Policy: {v}.',
      'hf.pp.ok': 'Permissions-Policy presente.', 'hf.pp.feature': 'Usa Feature-Policy, la versión antigua: cámbiala por Permissions-Policy.', 'hf.pp.missing': 'Falta Permissions-Policy: limita cámara, micrófono, geolocalización… p. ej. «camera=(), microphone=(), geolocation=()».',
      'hf.xxp.legacy': 'X-XSS-Protection «{v}» está obsoleta; en navegadores antiguos el filtro llegó a abrir fallos. Lo recomendado es no enviarla o enviar «0» y usar CSP.', 'hf.xxp.zero': 'X-XSS-Protection: 0 (lo recomendado hoy).',
      'hf.coop.ok': 'Cross-Origin-Opener-Policy: {v}.', 'hf.coop.missing': 'Sin Cross-Origin-Opener-Policy: opcional, aísla la ventana de las que abra (útil contra ataques tipo XS-Leaks).', 'hf.corp.ok': 'Cross-Origin-Resource-Policy: {v}.',
      'hf.cors.starCred': 'Access-Control-Allow-Origin «*» con Allow-Credentials true: configuración inválida y señal de CORS mal hecho.', 'hf.cors.null': 'Access-Control-Allow-Origin «null»: cualquier iframe con sandbox o archivo local puede leer las respuestas.',
      'hf.cors.star': 'Access-Control-Allow-Origin «*»: cualquier web puede leer esta respuesta (bien para contenido público, mal si es privado).', 'hf.cors.origin': 'CORS permite el origen {v}. Comprueba que no refleja cualquier Origin que le manden.',
      'hf.leak.version': 'Revela software y versión ({v}): facilita buscar vulnerabilidades conocidas. Quita o generaliza la cabecera.', 'hf.leak.product': 'Revela el software del servidor ({v}).',
      'hf.cookie.noSecure': 'La cookie «{name}» no lleva Secure: puede viajar por HTTP en claro.', 'hf.cookie.noHttpOnly': 'La cookie «{name}» no lleva HttpOnly: un XSS puede leerla con JavaScript.',
      'hf.cookie.noSameSite': 'La cookie «{name}» no fija SameSite (el navegador aplica Lax por defecto; mejor declararlo).', 'hf.cookie.noneInsecure': 'La cookie «{name}» usa SameSite=None sin Secure: los navegadores la rechazan.',
      'hf.cookie.hostPrefix': 'La cookie «{name}» usa el prefijo __Host- pero no cumple sus reglas (Secure, Path=/ y sin Domain).', 'hf.cookie.securePrefix': 'La cookie «{name}» usa el prefijo __Secure- sin el atributo Secure.',
      'hf.cache.session': 'Se fija una cookie de sesión sin «Cache-Control: no-store» o «private»: una caché intermedia podría guardar la respuesta.',
    },
    en: {
      'hd.inT': 'HTTP response headers',
      'hd.why': '<b>Why paste them?</b> A web page cannot read another site\'s headers: the browser blocks the request because of CORS or, if it lets it through, only shows seven “harmless” headers (Content-Type, Cache-Control…). The previous version (HttpInspector) reported as “missing” headers that were actually there. Here you get them with <code>curl</code> or the DevTools (Network tab → the request → Response headers) and paste them.',
      'hd.url': 'URL (to build the commands)', 'hd.try': 'Try from the browser', 'hd.paste': 'Paste the response headers here',
      'hd.pastePh': 'HTTP/2 200\ncontent-type: text/html\nstrict-transport-security: max-age=31536000\n…\n(output of curl -I, curl -v, DevTools or Burp)',
      'hd.go': 'Analyse', 'hd.sample': 'Example', 'hd.clear': 'Clear', 'hd.https': 'The response came over HTTPS',
      'hd.cmdT': 'Commands to get the headers', 'hd.cmdLinux': 'Linux / macOS / Git Bash', 'hd.cmdWin': 'Windows (cmd or PowerShell)', 'hd.cmdPs': 'PowerShell (without curl)', 'hd.cmdGet': 'If the server does not answer HEAD properly',
      'hd.badUrl': 'Type a full URL starting with http:// or https://.',
      'hd.tryOk': 'The browser received the response, but only lets you see these {n} headers. The security ones (HSTS, CSP, X-Frame-Options…) are hidden from any site of another origin, so this is not useful for auditing: use the commands above.',
      'hd.tryFail': 'The browser blocked the request (the usual case: the site does not allow requests from other origins, CORS). It does not mean the site is broken. Use the commands above.',
      'hd.noHeaders': 'No headers were found in the text. There must be “Name: value” lines.',
      'hd.grade': 'Grade', 'hd.score': 'Score {s}/100 · {have} of {total} main headers', 'hd.status': 'HTTP status {s}', 'hd.redirects': 'Previous redirects: {r}',
      'hd.findingsT': 'Findings', 'hd.header': 'Header', 'hd.finding': 'What is wrong and what to do', 'hd.cookiesT': 'Cookies', 'hd.rawT': 'Headers received ({n})',
      'hd.c.name': 'Name', 'hd.c.issues': 'Issues', 'hd.md': 'Copy report (Markdown)', 'hd.mdT': 'Headers report', 'hd.note': 'The grade follows securityheaders.com (six main headers) and the score drops with every issue. It is indicative: a header that is present but badly configured also counts.',
      'hf.hsts.http': 'The response is unencrypted HTTP: everything travels in clear text. Serve the site over HTTPS only and redirect port 80.',
      'hf.hsts.missing': 'HSTS is missing: an attacker on the network can force the first visit over HTTP (SSL stripping). Add “Strict-Transport-Security: max-age=31536000; includeSubDomains”.',
      'hf.hsts.noMaxAge': 'HSTS without max-age has no effect. Add “max-age=31536000”.', 'hf.hsts.zero': 'max-age=0 turns HSTS off in browsers that had it stored.',
      'hf.hsts.short': 'HSTS expires too soon (max-age ≈ {days} d); at least 180 days is recommended (a year is better).', 'hf.hsts.ok': 'HSTS active (max-age ≈ {days} d).',
      'hf.hsts.noSub': 'includeSubDomains is missing: subdomains are left unprotected.', 'hf.hsts.preload': 'Asks to be in the browsers\' preload list (hstspreload.org).',
      'hf.csp.missing': 'Content-Security-Policy is missing: nothing limits which scripts run if an XSS slips in. Start with “default-src \'self\'; object-src \'none\'; base-uri \'self\'; frame-ancestors \'self\'”.',
      'hf.csp.reportOnly': 'There is only a “Report-Only” CSP: it reports, but blocks nothing.', 'hf.csp.ok': 'CSP present with no serious script-src flaws.',
      'hf.csp.noScriptSrc': 'The CSP has no script-src or default-src: it does not protect against XSS (it probably only controls framing).',
      'hf.csp.unsafeInline': '“\'unsafe-inline\'” in script-src without a nonce or hash cancels almost all XSS protection. Use nonces or hashes.',
      'hf.csp.unsafeEval': '“\'unsafe-eval\'” allows eval() and the like: remove it if the application does not need it.',
      'hf.csp.wildcard': 'script-src allows overly broad sources ({v}): anyone can host a script there.', 'hf.csp.wildSub': 'Subdomain wildcards in script-src: any subdomain (including forgotten ones) can serve scripts.',
      'hf.csp.objectSrc': '“object-src \'none\'” is missing: plugins (object/embed) remain an execution path.', 'hf.csp.baseUri': 'base-uri is missing: an injected <base> can redirect relative scripts. Add “base-uri \'self\'”.',
      'hf.csp.frameAncestors': 'The CSP does not set frame-ancestors (it can replace X-Frame-Options).', 'hf.csp.formAction': 'The CSP does not set form-action: forms can be submitted anywhere.',
      'hf.csp.reportUri': 'It uses report-uri, which is deprecated; add report-to as well.',
      'hf.xfo.ok': 'Clickjacking protection: X-Frame-Options {v}.', 'hf.xfo.byCsp': 'Clickjacking protection via CSP frame-ancestors ({v}).',
      'hf.xfo.allowFrom': 'ALLOW-FROM is obsolete and modern browsers ignore it: use CSP frame-ancestors.', 'hf.xfo.invalid': 'Invalid X-Frame-Options value: “{v}”.',
      'hf.xfo.missing': 'No clickjacking protection: the page can be framed by another site. Add “X-Frame-Options: DENY” or “frame-ancestors \'self\'” in the CSP.',
      'hf.xcto.missing': '“X-Content-Type-Options: nosniff” is missing: the browser may guess a file type and run it as a script.', 'hf.xcto.invalid': 'X-Content-Type-Options only accepts “nosniff” (it has “{v}”).', 'hf.xcto.ok': 'nosniff active.',
      'hf.rp.missing': 'Referrer-Policy is missing (browsers default to strict-origin-when-cross-origin, but it is better to set it).', 'hf.rp.weak': 'Referrer-Policy “{v}” sends the full URL to other sites: it can leak tokens in the URL.', 'hf.rp.ok': 'Referrer-Policy: {v}.',
      'hf.pp.ok': 'Permissions-Policy present.', 'hf.pp.feature': 'It uses Feature-Policy, the old version: replace it with Permissions-Policy.', 'hf.pp.missing': 'Permissions-Policy is missing: restrict camera, microphone, geolocation… e.g. “camera=(), microphone=(), geolocation=()”.',
      'hf.xxp.legacy': 'X-XSS-Protection “{v}” is obsolete; in old browsers the filter even introduced bugs. The recommendation is not to send it, or send “0”, and use CSP.', 'hf.xxp.zero': 'X-XSS-Protection: 0 (today\'s recommendation).',
      'hf.coop.ok': 'Cross-Origin-Opener-Policy: {v}.', 'hf.coop.missing': 'No Cross-Origin-Opener-Policy: optional, it isolates the window from the ones it opens (useful against XS-Leaks).', 'hf.corp.ok': 'Cross-Origin-Resource-Policy: {v}.',
      'hf.cors.starCred': 'Access-Control-Allow-Origin “*” with Allow-Credentials true: an invalid configuration and a sign of broken CORS.', 'hf.cors.null': 'Access-Control-Allow-Origin “null”: any sandboxed iframe or local file can read the responses.',
      'hf.cors.star': 'Access-Control-Allow-Origin “*”: any site can read this response (fine for public content, bad if private).', 'hf.cors.origin': 'CORS allows the origin {v}. Check that it does not reflect any Origin sent to it.',
      'hf.leak.version': 'Reveals software and version ({v}): it makes it easier to look up known vulnerabilities. Remove or generalise the header.', 'hf.leak.product': 'Reveals the server software ({v}).',
      'hf.cookie.noSecure': 'Cookie “{name}” lacks Secure: it can travel over plain HTTP.', 'hf.cookie.noHttpOnly': 'Cookie “{name}” lacks HttpOnly: an XSS can read it with JavaScript.',
      'hf.cookie.noSameSite': 'Cookie “{name}” does not set SameSite (browsers apply Lax by default; better to declare it).', 'hf.cookie.noneInsecure': 'Cookie “{name}” uses SameSite=None without Secure: browsers reject it.',
      'hf.cookie.hostPrefix': 'Cookie “{name}” uses the __Host- prefix but breaks its rules (Secure, Path=/ and no Domain).', 'hf.cookie.securePrefix': 'Cookie “{name}” uses the __Secure- prefix without the Secure attribute.',
      'hf.cache.session': 'A session cookie is set without “Cache-Control: no-store” or “private”: an intermediate cache could store the response.',
    },
  });

  const SAMPLE = `HTTP/1.1 301 Moved Permanently
Location: https://tienda.example.com/

HTTP/2 200
date: Mon, 19 Oct 2026 10:00:00 GMT
content-type: text/html; charset=UTF-8
server: Apache/2.4.49 (Unix) PHP/7.4.3
x-powered-by: PHP/7.4.3
strict-transport-security: max-age=86400
content-security-policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.example.net *.googleapis.com
x-xss-protection: 1; mode=block
access-control-allow-origin: *
set-cookie: PHPSESSID=8f2a9c1e5b7d; path=/
set-cookie: idioma=es; path=/; Secure; SameSite=Lax
cache-control: max-age=600`;

  let lastReport = null;

  function renderCmds() {
    const box = $('hdCmds');
    const u = $('hdUrl').value.trim();
    if (!u) { box.innerHTML = ''; return; }
    const c = H.commands(u);
    if (!c) { box.innerHTML = `<div class="notice warn">${esc(t('hd.badUrl'))}</div>`; return; }
    $('hdHttps') && ($('hdHttps').checked = !/^http:/i.test(u));
    const row = (label, cmd) => `<div class="cmd"><span class="label">${esc(label)}</span><div class="cmd-line"><pre class="out">${esc(cmd)}</pre><button class="btn ghost small" type="button" data-copy="${esc(cmd)}">${esc(t('c.copy'))}</button></div></div>`;
    box.innerHTML = `<div class="panel-title" style="margin-top:4px">${esc(t('hd.cmdT'))}</div><div class="cmds">
      ${row(t('hd.cmdLinux'), c.curl)}${row(t('hd.cmdWin'), c.windows)}${row(t('hd.cmdPs'), c.powershell)}${row(t('hd.cmdGet'), c.curlGet)}</div>`;
  }

  async function tryBrowser() {
    const u = $('hdUrl').value.trim();
    const out = $('hdTryOut');
    if (!H.commands(u)) { out.innerHTML = `<div class="notice warn" style="margin-top:10px">${esc(t('hd.badUrl'))}</div>`; return; }
    out.innerHTML = `<p class="muted" style="margin-top:10px"><span class="spin"></span></p>`;
    try {
      const r = await fetch(u, { mode: 'cors', credentials: 'omit', redirect: 'follow', cache: 'no-store' });
      const list = [...r.headers.entries()];
      out.innerHTML = `<div class="notice warn" style="margin-top:10px">${esc(t('hd.tryOk', { n: list.length }))}</div>
        <pre class="out" style="margin-top:8px">${esc(list.map(([k, v]) => k + ': ' + v).join('\n'))}</pre>`;
    } catch (e) {
      out.innerHTML = `<div class="notice warn" style="margin-top:10px">${esc(t('hd.tryFail'))}</div>`;
    }
  }

  const hf = (f) => t('hf.' + f.key, f.vars);
  const lvl = (l) => `<span class="lvl ${l}">${esc(t('lvl.' + l))}</span>`;
  const ORDER = { bad: 0, warn: 1, info: 2, ok: 3 };

  function analyze() {
    const raw = $('hdRaw').value;
    const out = $('hdOut');
    if (!raw.trim()) { out.innerHTML = ''; lastReport = null; return; }
    const u = $('hdUrl').value.trim();
    const r = H.analyze(raw, { https: $('hdHttps') ? $('hdHttps').checked : true, url: u });
    if (r.error) { out.innerHTML = `<div class="notice warn">${esc(t('hd.noHeaders'))}</div>`; lastReport = null; return; }
    lastReport = r;
    const findings = r.findings.slice().sort((a, b) => ORDER[a.level] - ORDER[b.level]);
    const cookies = r.cookies.map(c => `<tr><td class="mono">${esc(c.name)}</td>
      <td>${c.secure ? '✔' : '✘'}</td><td>${c.httpOnly ? '✔' : '✘'}</td><td class="mono">${esc(c.sameSite || '—')}</td>
      <td>${c.issues.map(i => `<div>${lvl(i.level)} ${esc(t('hf.' + i.key, { name: c.name }))}</div>`).join('') || '<span class="lvl ok">' + esc(t('lvl.ok')) + '</span>'}</td></tr>`).join('');
    out.innerHTML = `
      <section class="panel">
        <div style="display:flex;gap:16px;align-items:center;flex-wrap:wrap">
          <div class="grade ${r.grade[0]}" aria-label="${esc(t('hd.grade'))} ${esc(r.grade)}">${esc(r.grade)}</div>
          <div style="flex:1 1 240px;min-width:0">
            <div class="h2">${esc(u || t('hd.inT'))}</div>
            <p>${esc(t('hd.score', { s: r.score, have: r.coreHave, total: r.coreTotal }))}${r.status ? ' · ' + esc(t('hd.status', { s: r.status })) : ''}</p>
            ${r.redirects.length ? `<p class="muted small">${esc(t('hd.redirects', { r: r.redirects.join(' → ') }))}</p>` : ''}
            <div class="bar ${r.score >= 80 ? 'ok' : r.score >= 50 ? 'warn' : 'bad'}" style="margin-top:6px"><i style="width:${r.score}%"></i></div>
          </div>
          <button class="btn ghost small" type="button" id="hdMd">${esc(t('hd.md'))}</button>
        </div>
        <p class="muted small" style="margin-top:10px">${esc(t('hd.note'))}</p>
      </section>
      <section class="panel">
        <div class="panel-title">${esc(t('hd.findingsT'))}</div>
        <div class="tbl-wrap"><table class="tbl"><thead><tr><th style="width:90px"></th><th>${esc(t('hd.header'))}</th><th>${esc(t('hd.finding'))}</th></tr></thead><tbody>
          ${findings.map(f => `<tr><td>${lvl(f.level)}</td><td class="mono">${esc(f.header)}</td><td>${esc(hf(f))}</td></tr>`).join('')}
        </tbody></table></div>
      </section>
      ${r.cookies.length ? `<section class="panel"><div class="panel-title">${esc(t('hd.cookiesT'))}</div><div class="tbl-wrap"><table class="tbl"><thead><tr><th>${esc(t('hd.c.name'))}</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th><th>${esc(t('hd.c.issues'))}</th></tr></thead><tbody>${cookies}</tbody></table></div></section>` : ''}
      <details class="sec"><summary>${esc(t('hd.rawT', { n: r.headers.length }))}</summary><div class="body">
        <div class="tbl-wrap"><table class="tbl"><tbody>${r.headers.map(h => `<tr><td class="k mono">${esc(h.name)}</td><td class="mono">${esc(h.value)}</td></tr>`).join('')}</tbody></table></div>
      </div></details>`;
    $('hdMd').onclick = () => IK.copyText(markdown(r, u));
  }

  function markdown(r, u) {
    const L = { bad: '🔴', warn: '🟠', info: '🔵', ok: '🟢' };
    const lines = [`## ${t('hd.mdT')}${u ? ' · ' + u : ''}`, '', `**${t('hd.grade')}: ${r.grade}** · ${t('hd.score', { s: r.score, have: r.coreHave, total: r.coreTotal })}`, '',
      `| | ${t('hd.header')} | ${t('hd.finding')} |`, '|---|---|---|'];
    for (const f of r.findings.slice().sort((a, b) => ORDER[a.level] - ORDER[b.level])) lines.push(`| ${L[f.level]} ${t('lvl.' + f.level)} | \`${f.header}\` | ${hf(f).replace(/\|/g, '\\|')} |`);
    lines.push('', `_InspectorKit · https://unfantasmaenelsistema.github.io/InspectorKit/#cabeceras_`);
    return lines.join('\n');
  }

  document.addEventListener('DOMContentLoaded', () => {
    // Casilla HTTPS junto al botón de analizar
    const go = $('hdGo');
    const lab = document.createElement('label');
    lab.className = 'check'; lab.innerHTML = `<input type="checkbox" id="hdHttps" checked> <span data-t="hd.https">${esc(t('hd.https'))}</span>`;
    go.parentNode.appendChild(lab);
    $('hdUrl').addEventListener('input', renderCmds);
    $('hdTry').addEventListener('click', tryBrowser);
    go.addEventListener('click', analyze);
    $('hdHttps').addEventListener('change', analyze);
    $('hdSample').addEventListener('click', () => { $('hdRaw').value = SAMPLE; $('hdUrl').value = 'https://tienda.example.com/'; renderCmds(); analyze(); });
    $('hdClear').addEventListener('click', () => { $('hdRaw').value = ''; $('hdOut').innerHTML = ''; $('hdTryOut').innerHTML = ''; lastReport = null; });
    $('hdRaw').addEventListener('paste', () => setTimeout(analyze, 0));
    document.querySelector('[data-tab="cabeceras"]').addEventListener('click', (e) => { const c = e.target.closest('[data-copy]'); if (c) IK.copyText(c.dataset.copy); });
    document.addEventListener('ik:lang', () => { renderCmds(); if (lastReport) analyze(); });
  });
})();
