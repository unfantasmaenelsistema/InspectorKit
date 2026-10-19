/* InspectorKit · núcleo común: marca, idioma, tema, pestañas, «Enviar a…» y utilidades. Sin dependencias. */
(function () {
  'use strict';

  const WEB = 'https://www.unfantasmaenelsistema.com';
  const REPO = 'https://github.com/unfantasmaenelsistema/InspectorKit';
  const TABS = ['inicio', 'archivo', 'hash', 'cifrados', 'cabeceras'];

  // ───────────────────────── Almacenamiento ─────────────────────────
  const PREFIX = 'ik_';
  const store = {
    get(k) { try { return localStorage.getItem(PREFIX + k); } catch (e) { return null; } },
    set(k, v) { try { if (v == null || v === '') localStorage.removeItem(PREFIX + k); else localStorage.setItem(PREFIX + k, v); } catch (e) { /* modo privado */ } },
  };

  // ───────────────────────── Idioma ─────────────────────────
  const DICT = { es: {}, en: {} };
  let lang = store.get('lang') || ((navigator.language || 'es').toLowerCase().startsWith('es') ? 'es' : 'en');
  if (!DICT[lang]) lang = 'es';
  function addI18n(d) { for (const l of Object.keys(DICT)) Object.assign(DICT[l], d[l] || {}); }
  function t(key, vars) {
    let s = DICT[lang][key];
    if (s == null) s = DICT.es[key];
    if (s == null) return key;
    if (vars) s = s.replace(/\{(\w+)\}/g, (m, k) => (vars[k] != null ? vars[k] : m));
    return s;
  }
  function has(key) { return DICT[lang][key] != null || DICT.es[key] != null; }
  function applyI18n(root) {
    root = root || document;
    root.querySelectorAll('[data-t]').forEach(el => { el.textContent = t(el.dataset.t); });
    root.querySelectorAll('[data-t-html]').forEach(el => { el.innerHTML = t(el.dataset.tHtml); });
    root.querySelectorAll('[data-t-ph]').forEach(el => { el.placeholder = t(el.dataset.tPh); });
    root.querySelectorAll('[data-t-title]').forEach(el => { el.title = t(el.dataset.tTitle); });
    root.querySelectorAll('[data-t-aria]').forEach(el => { el.setAttribute('aria-label', t(el.dataset.tAria)); });
    document.documentElement.lang = lang;
    document.title = (current && current !== 'inicio' ? t('nav.' + current) + ' · ' : '') + 'InspectorKit · Un Fantasma en el Sistema';
  }
  function setLang(l) {
    if (!DICT[l] || l === lang) return;
    lang = l; store.set('lang', l);
    applyI18n(); renderChrome();
    document.dispatchEvent(new CustomEvent('ik:lang', { detail: l }));
  }

  // ───────────────────────── Tema ─────────────────────────
  function theme() { return document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark'; }
  function setTheme(th) {
    document.documentElement.setAttribute('data-theme', th);
    store.set('theme', th); renderChrome();
    document.dispatchEvent(new CustomEvent('ik:theme', { detail: th }));
  }

  // ───────────────────────── Utilidades ─────────────────────────
  function esc(s) {
    if (s == null) return '';
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
  let toastTimer;
  function toast(msg, ms) {
    let el = document.getElementById('ikToast');
    if (!el) { el = document.createElement('div'); el.id = 'ikToast'; el.className = 'toast'; el.setAttribute('role', 'status'); el.setAttribute('aria-live', 'polite'); document.body.appendChild(el); }
    el.textContent = msg; el.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.remove('show'), ms || 2600);
  }
  function download(name, content, type) {
    const blob = content instanceof Blob ? content : new Blob([content], { type: type || 'application/octet-stream' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = name;
    document.body.appendChild(a); a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1500);
  }
  async function copyText(text) {
    let ok = false;
    try { await navigator.clipboard.writeText(text); ok = true; } catch (e) {
      const ta = document.createElement('textarea');
      ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
      document.body.appendChild(ta); ta.select();
      try { ok = document.execCommand('copy'); } catch (e2) { /* nada */ }
      ta.remove();
    }
    toast(ok ? t('c.copied') : t('c.copyFail'));
    return ok;
  }
  function size(n) {
    if (n < 1024) return n + ' B';
    const u = ['KB', 'MB', 'GB']; let i = -1;
    do { n /= 1024; i++; } while (n >= 1024 && i < 2);
    return n.toFixed(n < 10 ? 2 : 1).replace('.', lang === 'es' ? ',' : '.') + ' ' + u[i];
  }
  const num = (n) => Number(n).toLocaleString(lang === 'es' ? 'es-ES' : 'en-GB');
  const hex = (n, w) => '0x' + Number(n).toString(16).toUpperCase().padStart(w || 0, '0');
  function readFile(file) {
    return new Promise((res, rej) => {
      if (file.arrayBuffer) { file.arrayBuffer().then(b => res(new Uint8Array(b)), rej); return; }
      const r = new FileReader();
      r.onload = () => res(new Uint8Array(r.result)); r.onerror = () => rej(r.error);
      r.readAsArrayBuffer(file);
    });
  }
  // Zona de arrastre: clic, arrastrar o pegar un archivo.
  function dropzone(el, onFile) {
    const input = el.querySelector('input[type=file]');
    el.addEventListener('click', (e) => { if (e.target !== input) input.click(); });
    el.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } });
    input.addEventListener('change', () => { if (input.files[0]) onFile(input.files[0]); input.value = ''; });
    el.addEventListener('dragover', (e) => { e.preventDefault(); el.classList.add('over'); });
    el.addEventListener('dragleave', () => el.classList.remove('over'));
    el.addEventListener('drop', (e) => { e.preventDefault(); el.classList.remove('over'); const f = e.dataTransfer.files[0]; if (f) onFile(f); });
  }
  function errText(e) {
    const code = e && e.code ? 'err.' + e.code : null;
    if (code && has(code)) return t(code, e.vars);
    return t('err.generic', { m: (e && e.message) || String(e) });
  }

  // ───────────────────────── Pestañas y «Enviar a…» ─────────────────────────
  let current = null;
  const handlers = {};
  const pending = {};
  function onReceive(tab, fn) { handlers[tab] = fn; if (pending[tab]) { const p = pending[tab]; delete pending[tab]; fn(p); } }
  function send(tab, payload) {
    if (handlers[tab]) handlers[tab](payload); else pending[tab] = payload;
    go(tab);
  }
  function go(tab) {
    if (location.hash !== '#' + tab) location.hash = tab; else show(tab);
  }
  function show(tab) {
    if (!TABS.includes(tab)) tab = 'inicio';
    current = tab;
    document.querySelectorAll('[data-tab]').forEach(s => { s.hidden = s.dataset.tab !== tab; });
    renderChrome(); applyI18n();
    document.dispatchEvent(new CustomEvent('ik:tab', { detail: tab }));
    window.scrollTo({ top: 0 });
  }
  window.addEventListener('hashchange', () => show(location.hash.slice(1)));

  // ───────────────────────── Textos comunes ─────────────────────────
  addI18n({
    es: {
      'brand.sub': 'UN FANTASMA EN EL SISTEMA · INSPECCIÓN FORENSE',
      'nav.inicio': 'Inicio', 'nav.archivo': 'Archivo', 'nav.hash': 'Hash', 'nav.cifrados': 'Cifrados', 'nav.cabeceras': 'Cabeceras',
      'chip.themeTitle': 'Cambiar entre tema claro y oscuro', 'chip.langTitle': 'Switch to English',
      'foot.text': 'Gratis y de código abierto. Todo se analiza en tu navegador: nada sale de él.',
      'foot.source': 'Código fuente',
      'c.copy': 'Copiar', 'c.copied': 'Copiado al portapapeles', 'c.copyFail': 'No se pudo copiar', 'c.download': 'Descargar', 'c.analyze': 'Analizar',
      'c.toCipher': '→ Cifrados', 'c.toHash': '→ Hash', 'c.toFile': '→ Archivo', 'c.yes': 'Sí', 'c.no': 'No', 'c.none': 'Nada', 'c.more': 'Mostrar más',
      'lvl.ok': 'bien', 'lvl.info': 'info', 'lvl.warn': 'aviso', 'lvl.bad': 'grave',
      'err.generic': 'Error: {m}',
    },
    en: {
      'brand.sub': 'UN FANTASMA EN EL SISTEMA · FORENSIC INSPECTION',
      'nav.inicio': 'Home', 'nav.archivo': 'File', 'nav.hash': 'Hash', 'nav.cifrados': 'Ciphers', 'nav.cabeceras': 'Headers',
      'chip.themeTitle': 'Switch between light and dark theme', 'chip.langTitle': 'Cambiar a español',
      'foot.text': 'Free and open source. Everything is analysed in your browser: nothing leaves it.',
      'foot.source': 'Source code',
      'c.copy': 'Copy', 'c.copied': 'Copied to clipboard', 'c.copyFail': 'Could not copy', 'c.download': 'Download', 'c.analyze': 'Analyse',
      'c.toCipher': '→ Ciphers', 'c.toHash': '→ Hash', 'c.toFile': '→ File', 'c.yes': 'Yes', 'c.no': 'No', 'c.none': 'Nothing', 'c.more': 'Show more',
      'lvl.ok': 'good', 'lvl.info': 'info', 'lvl.warn': 'warning', 'lvl.bad': 'serious',
      'err.generic': 'Error: {m}',
    },
  });

  function renderChrome() {
    const top = document.getElementById('ikTop');
    if (top) {
      top.innerHTML = `
        <a class="ik-brand" href="#inicio">
          <img src="assets/ghost.png" alt="Un Fantasma en el Sistema" width="42" height="42">
          <span><b>INSPECTOR<span>KIT</span></b><small>${esc(t('brand.sub'))}</small></span>
        </a>
        <nav class="ik-nav" aria-label="InspectorKit">
          ${TABS.map(id => `<a href="#${id}"${id === current ? ' aria-current="page"' : ''}>${esc(t('nav.' + id))}</a>`).join('')}
        </nav>
        <div class="ik-controls">
          <a class="chip" href="${WEB}" target="_blank" rel="noopener">[ WEB ]</a>
          <button class="chip" id="ikLangBtn" type="button" title="${esc(t('chip.langTitle'))}">${lang === 'es' ? 'EN' : 'ES'}</button>
          <button class="chip" id="ikThemeBtn" type="button" title="${esc(t('chip.themeTitle'))}" aria-label="${esc(t('chip.themeTitle'))}">${theme() === 'dark' ? '☀' : '☾'}</button>
        </div>`;
      top.querySelector('#ikLangBtn').onclick = () => setLang(lang === 'es' ? 'en' : 'es');
      top.querySelector('#ikThemeBtn').onclick = () => setTheme(theme() === 'dark' ? 'light' : 'dark');
    }
    const foot = document.getElementById('ikFoot');
    if (foot) {
      foot.innerHTML = `
        <span>© ${new Date().getFullYear()} Un Fantasma en el Sistema · ${esc(t('foot.text'))}</span>
        <span class="links">
          <a href="${WEB}" target="_blank" rel="noopener">unfantasmaenelsistema.com</a>
          <a href="${REPO}" target="_blank" rel="noopener">${esc(t('foot.source'))} (MIT)</a>
        </span>`;
    }
  }

  window.IK = { store, t, has, addI18n, applyI18n, setLang, lang: () => lang, theme, setTheme, esc, toast, download, copyText, size, num, hex, readFile, dropzone, errText, send, onReceive, go, tab: () => current };

  document.addEventListener('DOMContentLoaded', () => { show(location.hash.slice(1) || 'inicio'); });
})();
