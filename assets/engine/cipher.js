/* InspectorKit · motor de codificaciones y cifrados clásicos. Sin DOM: funciona igual en Node.
   El valor que circula entre operaciones son bytes (Uint8Array); las operaciones de texto
   lo leen como UTF-8 y devuelven UTF-8. Así una cadena Base64 → XOR no pierde bytes. */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.IKCipher = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const te = new TextEncoder();
  const tdFatal = new TextDecoder('utf-8', { fatal: true });
  const utf8 = (s) => te.encode(s);

  // Bytes → texto. Si no es UTF-8 válido se lee byte a byte (latin-1) y se marca como binario.
  function bytesToText(b) {
    try { return { text: tdFatal.decode(b), binary: false }; } catch (e) {
      let s = '';
      for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
      return { text: s, binary: true };
    }
  }
  const asText = (b) => bytesToText(b).text;
  const hexOf = (b) => Array.from(b, x => x.toString(16).padStart(2, '0')).join(' ');

  class OpError extends Error { constructor(code, vars) { super(code); this.code = code; this.vars = vars || {}; } }
  const fail = (code, vars) => { throw new OpError(code, vars); };

  // ───────────────────────── Codificaciones ─────────────────────────
  const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  function b64enc(b) {
    let out = '';
    for (let i = 0; i < b.length; i += 3) {
      const n = (b[i] << 16) | ((b[i + 1] || 0) << 8) | (b[i + 2] || 0);
      out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63] + (i + 1 < b.length ? B64[(n >> 6) & 63] : '=') + (i + 2 < b.length ? B64[n & 63] : '=');
    }
    return out;
  }
  function b64dec(s) {
    let t = s.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
    if (!t || /[^A-Za-z0-9+/]/.test(t) || t.length % 4 === 1) fail('badB64');
    const out = [];
    let bits = 0, val = 0;
    for (const c of t) { val = (val << 6) | B64.indexOf(c); bits += 6; if (bits >= 8) { bits -= 8; out.push((val >> bits) & 255); } }
    return Uint8Array.from(out);
  }

  const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  function b32enc(b) {
    let out = '', bits = 0, val = 0;
    for (const x of b) { val = (val << 8) | x; bits += 8; while (bits >= 5) { bits -= 5; out += B32[(val >> bits) & 31]; } }
    if (bits) out += B32[(val << (5 - bits)) & 31];
    while (out.length % 8) out += '=';
    return out;
  }
  function b32dec(s) {
    const t = s.replace(/\s+/g, '').replace(/=+$/, '').toUpperCase();
    if (!t || /[^A-Z2-7]/.test(t)) fail('badB32');
    const out = [];
    let bits = 0, val = 0;
    for (const c of t) { val = ((val << 5) | B32.indexOf(c)) & 0xffff; bits += 5; if (bits >= 8) { bits -= 8; out.push((val >> bits) & 255); } }
    return Uint8Array.from(out);
  }

  const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  function b58enc(b) {
    let n = 0n;
    for (const x of b) n = n * 256n + BigInt(x);
    let out = '';
    while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n; }
    for (const x of b) { if (x === 0) out = '1' + out; else break; }
    return out;
  }
  function b58dec(s) {
    const t = s.trim();
    if (!t || /[^1-9A-HJ-NP-Za-km-z]/.test(t)) fail('badB58');
    let n = 0n;
    for (const c of t) n = n * 58n + BigInt(B58.indexOf(c));
    const out = [];
    while (n > 0n) { out.unshift(Number(n % 256n)); n /= 256n; }
    for (const c of t) { if (c === '1') out.unshift(0); else break; }
    return Uint8Array.from(out);
  }

  function a85enc(b) {
    let out = '';
    for (let i = 0; i < b.length; i += 4) {
      const chunk = [b[i], b[i + 1] || 0, b[i + 2] || 0, b[i + 3] || 0];
      const len = Math.min(4, b.length - i);
      let n = ((chunk[0] << 24) | (chunk[1] << 16) | (chunk[2] << 8) | chunk[3]) >>> 0;
      if (n === 0 && len === 4) { out += 'z'; continue; }
      const c = [];
      for (let k = 0; k < 5; k++) { c.unshift(String.fromCharCode(33 + (n % 85))); n = Math.floor(n / 85); }
      out += c.slice(0, len + 1).join('');
    }
    return '<~' + out + '~>';
  }
  function a85dec(s) {
    let t = s.trim();
    if (t.startsWith('<~')) t = t.slice(2);
    if (t.endsWith('~>')) t = t.slice(0, -2);
    t = t.replace(/\s+/g, '');
    if (!t || /[^!-uz]/.test(t)) fail('badA85');
    const out = [];
    let group = [];
    const flush = (g, pad) => {
      while (g.length < 5) g.push(84);
      let n = 0;
      for (const v of g) n = n * 85 + v;
      if (n > 0xffffffff) fail('badA85');
      const bytes = [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255];
      out.push(...bytes.slice(0, 4 - pad));
    };
    for (const c of t) {
      if (c === 'z') { if (group.length) fail('badA85'); out.push(0, 0, 0, 0); continue; }
      group.push(c.charCodeAt(0) - 33);
      if (group.length === 5) { flush(group, 0); group = []; }
    }
    if (group.length === 1) fail('badA85');
    if (group.length) flush(group, 5 - group.length);
    return Uint8Array.from(out);
  }

  function hexdec(s) {
    const t = s.replace(/0x/gi, '').replace(/\\x/gi, '').replace(/[\s:,;-]+/g, '');
    if (!t || /[^0-9a-f]/i.test(t) || t.length % 2) fail('badHex');
    const out = new Uint8Array(t.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(t.substr(i * 2, 2), 16);
    return out;
  }
  const hexenc = (b) => Array.from(b, x => x.toString(16).padStart(2, '0')).join('');

  function bindec(s) {
    const t = s.replace(/[\s,;]+/g, ' ').trim();
    if (!t || /[^01 ]/.test(t)) fail('badBin');
    const groups = t.includes(' ') ? t.split(' ') : t.match(/.{1,8}/g);
    if (!t.includes(' ') && t.length % 8) fail('badBin');
    return Uint8Array.from(groups.map(g => { if (g.length > 8) fail('badBin'); return parseInt(g, 2); }));
  }
  const binenc = (b) => Array.from(b, x => x.toString(2).padStart(8, '0')).join(' ');

  function decdec(s) {
    const t = s.trim();
    if (!t || /[^0-9\s,;]/.test(t)) fail('badDec');
    return Uint8Array.from(t.split(/[\s,;]+/).filter(Boolean).map(n => { const v = parseInt(n, 10); if (v > 255) fail('badDec'); return v; }));
  }
  const decenc = (b) => Array.from(b).join(' ');

  function urlenc(b) {
    let out = '';
    for (const x of b) {
      const c = String.fromCharCode(x);
      out += /[A-Za-z0-9\-_.~]/.test(c) ? c : '%' + x.toString(16).toUpperCase().padStart(2, '0');
    }
    return out;
  }
  function urldec(b) {
    const s = asText(b);
    if (!/%[0-9a-f]{2}/i.test(s)) fail('badUrl');
    const out = [];
    const raw = utf8(s);
    for (let i = 0; i < raw.length; i++) {
      if (raw[i] === 37 && i + 2 < raw.length && /^[0-9a-f]{2}$/i.test(String.fromCharCode(raw[i + 1], raw[i + 2]))) {
        out.push(parseInt(String.fromCharCode(raw[i + 1], raw[i + 2]), 16)); i += 2;
      } else out.push(raw[i]);
    }
    return Uint8Array.from(out);
  }

  const ENT = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', aacute: 'á', eacute: 'é', iacute: 'í', oacute: 'ó', uacute: 'ú',
    Aacute: 'Á', Eacute: 'É', Iacute: 'Í', Oacute: 'Ó', Uacute: 'Ú', ntilde: 'ñ', Ntilde: 'Ñ', uuml: 'ü', Uuml: 'Ü', iquest: '¿', iexcl: '¡', copy: '©', reg: '®', euro: '€' };
  function htmldec(s) {
    if (!/&(#\d+|#x[0-9a-f]+|[a-z]+);/i.test(s)) fail('badHtml');
    return s.replace(/&(#\d+|#x[0-9a-f]+|[a-z]+);/gi, (m, e) => {
      if (e[0] === '#') { const cp = e[1].toLowerCase() === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10); return cp <= 0x10ffff ? String.fromCodePoint(cp) : m; }
      return ENT[e] != null ? ENT[e] : m;
    });
  }
  const htmlenc = (s) => Array.from(s, c => {
    if (c === '&') return '&amp;'; if (c === '<') return '&lt;'; if (c === '>') return '&gt;'; if (c === '"') return '&quot;'; if (c === "'") return '&#39;';
    const cp = c.codePointAt(0); return cp > 126 ? '&#' + cp + ';' : c;
  }).join('');

  const MORSE = { A: '.-', B: '-...', C: '-.-.', D: '-..', E: '.', F: '..-.', G: '--.', H: '....', I: '..', J: '.---', K: '-.-', L: '.-..', M: '--', N: '-.',
    'Ñ': '--.--', O: '---', P: '.--.', Q: '--.-', R: '.-.', S: '...', T: '-', U: '..-', V: '...-', W: '.--', X: '-..-', Y: '-.--', Z: '--..',
    0: '-----', 1: '.----', 2: '..---', 3: '...--', 4: '....-', 5: '.....', 6: '-....', 7: '--...', 8: '---..', 9: '----.',
    '.': '.-.-.-', ',': '--..--', '?': '..--..', "'": '.----.', '!': '-.-.--', '/': '-..-.', '(': '-.--.', ')': '-.--.-', '&': '.-...',
    ':': '---...', ';': '-.-.-.', '=': '-...-', '+': '.-.-.', '-': '-....-', '_': '..--.-', '"': '.-..-.', '$': '...-..-', '@': '.--.-.' };
  const MORSE_R = Object.fromEntries(Object.entries(MORSE).map(([k, v]) => [v, k]));
  function morsedec(s) {
    const t = s.replace(/[·•∙]/g, '.').replace(/[_−–—]/g, '-').trim();
    if (!t || /[^.\-\s/|]/.test(t)) fail('badMorse');
    return t.split(/\s*[/|]\s*|\s{3,}|\n+/).map(w => w.trim().split(/\s+/).filter(Boolean).map(code => {
      if (MORSE_R[code] == null) fail('badMorseCode', { code });
      return MORSE_R[code];
    }).join('')).join(' ');
  }
  const foldAccents = (s) => s.normalize('NFD').replace(/[̀-ͯ]/g, '').normalize('NFC');
  function morseenc(s) {
    return s.toUpperCase().split(/\s+/).filter(Boolean).map(w => Array.from(w).map(c => {
      const k = c === 'Ñ' ? c : foldAccents(c);
      return MORSE[k] || '';
    }).filter(Boolean).join(' ')).join(' / ');
  }

  // Bacon: variante de 26 letras (cada letra su código) o la clásica de 24 (I=J, U=V).
  function baconAlphabet(v24) {
    const letters = v24 ? 'ABCDEFGHIKLMNOPQRSTUWXYZ' : 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const map = {};
    Array.from(letters).forEach((c, i) => { map[c] = i.toString(2).padStart(5, '0').replace(/0/g, 'A').replace(/1/g, 'B'); });
    if (v24) { map.J = map.I; map.V = map.U; }
    return map;
  }
  function bacondec(s, p) {
    const t = s.toUpperCase().replace(/0/g, 'A').replace(/1/g, 'B').replace(/[^AB]/g, '');
    if (!t || t.length % 5) fail('badBacon');
    const rev = {};
    for (const [k, v] of Object.entries(baconAlphabet(p.v24))) if (!rev[v]) rev[v] = k;
    return t.match(/.{5}/g).map(g => rev[g] || '?').join('');
  }
  function baconenc(s, p) {
    const map = baconAlphabet(p.v24);
    return Array.from(foldAccents(s).toUpperCase()).filter(c => map[c]).map(c => map[c]).join(' ');
  }

  // ───────────────────────── Clásicos ─────────────────────────
  // Desplaza solo A-Z y a-z; el resto (espacios, ñ, acentos, signos) pasa tal cual.
  function shiftText(s, n) {
    n = ((n % 26) + 26) % 26;
    return s.replace(/[A-Za-z]/g, c => { const b = c <= 'Z' ? 65 : 97; return String.fromCharCode((c.charCodeAt(0) - b + n) % 26 + b); });
  }
  const rot47 = (s) => s.replace(/[!-~]/g, c => String.fromCharCode(33 + (c.charCodeAt(0) - 33 + 47) % 94));
  const atbash = (s) => s.replace(/[A-Za-z]/g, c => { const b = c <= 'Z' ? 65 : 97; return String.fromCharCode(25 - (c.charCodeAt(0) - b) + b); });

  function cleanKey(k) {
    const t = foldAccents(String(k || '')).toUpperCase().replace(/[^A-Z]/g, '');
    if (!t) fail('needKey');
    return t;
  }
  function vigenere(s, key, decrypt) {
    const k = cleanKey(key);
    let j = 0;
    return s.replace(/[A-Za-z]/g, c => { const n = k.charCodeAt(j++ % k.length) - 65; return shiftText(c, decrypt ? -n : n); });
  }

  const gcd = (a, b) => (b ? gcd(b, a % b) : a);
  const modInv = (a, m) => { for (let x = 1; x < m; x++) if ((a * x) % m === 1) return x; return null; };
  function affine(s, a, b, decrypt) {
    a = parseInt(a, 10); b = parseInt(b, 10);
    if (!Number.isFinite(a) || !Number.isFinite(b) || gcd(((a % 26) + 26) % 26, 26) !== 1) fail('badAffine');
    const ai = modInv(((a % 26) + 26) % 26, 26);
    return s.replace(/[A-Za-z]/g, c => {
      const base = c <= 'Z' ? 65 : 97;
      const x = c.charCodeAt(0) - base;
      const y = decrypt ? (ai * (x - b)) % 26 : (a * x + b) % 26;
      return String.fromCharCode(((y % 26) + 26) % 26 + base);
    });
  }

  // Rail fence (zigzag) sobre todos los caracteres.
  function railPattern(n, rails) {
    const pat = [];
    let r = 0, dir = 1;
    for (let i = 0; i < n; i++) { pat.push(r); if (rails > 1) { if (r === 0) dir = 1; else if (r === rails - 1) dir = -1; r += dir; } }
    return pat;
  }
  function railEnc(s, rails) {
    rails = parseInt(rails, 10);
    if (!(rails >= 2)) fail('badRails');
    const ch = Array.from(s), pat = railPattern(ch.length, rails);
    let out = '';
    for (let r = 0; r < rails; r++) ch.forEach((c, i) => { if (pat[i] === r) out += c; });
    return out;
  }
  function railDec(s, rails) {
    rails = parseInt(rails, 10);
    if (!(rails >= 2)) fail('badRails');
    const ch = Array.from(s), pat = railPattern(ch.length, rails);
    const order = [];
    for (let r = 0; r < rails; r++) pat.forEach((p, i) => { if (p === r) order.push(i); });
    const out = new Array(ch.length);
    order.forEach((pos, k) => { out[pos] = ch[k]; });
    return out.join('');
  }

  // Escítala: se escribe en filas de «cols» caracteres y se lee por columnas.
  // Al descifrar, las primeras (n mod cols) columnas tienen una letra más (el fallo del original).
  function scytaleEnc(s, cols) {
    cols = parseInt(cols, 10);
    if (!(cols >= 2)) fail('badScytale');
    const ch = Array.from(s);
    let out = '';
    for (let c = 0; c < cols; c++) for (let i = c; i < ch.length; i += cols) out += ch[i];
    return out;
  }
  function scytaleDec(s, cols) {
    cols = parseInt(cols, 10);
    if (!(cols >= 2)) fail('badScytale');
    const ch = Array.from(s), n = ch.length;
    const rows = Math.ceil(n / cols), full = n % cols || cols;
    const out = new Array(n);
    let k = 0;
    for (let c = 0; c < cols; c++) {
      const len = c < full ? rows : rows - 1;
      for (let r = 0; r < len; r++) out[r * cols + c] = ch[k++];
    }
    return out.join('');
  }

  function polySquare(key) {
    const base = 'ABCDEFGHIKLMNOPQRSTUVWXYZ';
    const k = foldAccents(String(key || '')).toUpperCase().replace(/J/g, 'I').replace(/[^A-Z]/g, '');
    let sq = '';
    for (const c of k + base) if (!sq.includes(c)) sq += c;
    return sq;
  }
  function polyDec(s, p) {
    const sq = polySquare(p.key);
    const words = s.trim().split(/\s*\/\s*|\s{2,}|\n+/);
    if (!/\d/.test(s) || /[^\d\s/,;-]/.test(s)) fail('badPoly');
    return words.map(w => {
      const d = w.replace(/\D/g, '');
      if (d.length % 2) fail('badPolyLen');
      let out = '';
      for (let i = 0; i < d.length; i += 2) {
        const r = +d[i], c = +d[i + 1];
        if (r < 1 || r > 5 || c < 1 || c > 5) fail('badPolyPair', { pair: d.substr(i, 2) });
        out += sq[(r - 1) * 5 + (c - 1)];
      }
      return out;
    }).join(' ');
  }
  function polyEnc(s, p) {
    const sq = polySquare(p.key);
    return foldAccents(s).toUpperCase().replace(/J/g, 'I').split(/\s+/).filter(Boolean).map(w =>
      Array.from(w).filter(c => sq.includes(c)).map(c => { const i = sq.indexOf(c); return `${Math.floor(i / 5) + 1}${i % 5 + 1}`; }).join(' ')
    ).filter(Boolean).join(' / ');
  }

  function playfairPairs(t) {
    const pairs = [];
    for (let i = 0; i < t.length;) {
      const a = t[i], b = t[i + 1];
      if (b == null) { pairs.push([a, a === 'X' ? 'Q' : 'X']); i += 1; }
      else if (a === b) { pairs.push([a, a === 'X' ? 'Q' : 'X']); i += 1; }
      else { pairs.push([a, b]); i += 2; }
    }
    return pairs;
  }
  function playfair(s, key, decrypt, clean) {
    if (!String(key || '').trim()) fail('needKey');
    const sq = polySquare(key);
    const pos = (c) => { const i = sq.indexOf(c); return [Math.floor(i / 5), i % 5]; };
    const t = foldAccents(s).toUpperCase().replace(/J/g, 'I').replace(/[^A-Z]/g, '');
    if (!t) fail('empty');
    if (decrypt && t.length % 2) fail('badPlayfairLen');
    const pairs = decrypt ? t.match(/../g).map(p => [p[0], p[1]]) : playfairPairs(t);
    const d = decrypt ? 4 : 1;
    let out = '';
    for (const [a, b] of pairs) {
      const [r1, c1] = pos(a), [r2, c2] = pos(b);
      if (r1 === r2) out += sq[r1 * 5 + (c1 + d) % 5] + sq[r2 * 5 + (c2 + d) % 5];
      else if (c1 === c2) out += sq[((r1 + d) % 5) * 5 + c1] + sq[((r2 + d) % 5) * 5 + c2];
      else out += sq[r1 * 5 + c2] + sq[r2 * 5 + c1];
    }
    if (decrypt && clean) out = out.replace(/(.)X(?=\1)/g, '$1').replace(/X$/, '');
    return out;
  }

  function parseKeyBytes(key, fmt) {
    if (fmt === 'hex') { try { return hexdec(String(key || '')); } catch (e) { fail('badXorKey'); } }
    const k = utf8(String(key || ''));
    if (!k.length) fail('needKey');
    return k;
  }
  function xorBytes(b, k) { const out = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) out[i] = b[i] ^ k[i % k.length]; return out; }

  // ───────────────────────── Puntuación de «parece texto» ─────────────────────────
  // Frecuencias de letras (%), sin acentos: español (CORPES/RAE aprox.) e inglés.
  const FREQ = {
    es: [12.53, 1.42, 4.68, 5.86, 13.68, 0.69, 1.01, 0.70, 6.25, 0.44, 0.02, 4.97, 3.15, 6.71, 8.68, 2.51, 0.88, 6.87, 7.98, 4.63, 3.93, 0.90, 0.01, 0.22, 0.90, 0.52],
    en: [8.17, 1.49, 2.78, 4.25, 12.70, 2.23, 2.02, 6.09, 6.97, 0.15, 0.77, 4.03, 2.41, 6.75, 7.51, 1.93, 0.10, 5.99, 6.33, 9.06, 2.76, 0.98, 2.36, 0.15, 1.97, 0.07],
  };
  const IOC = { es: 0.0775, en: 0.0667 };
  const WORDS = new Set(('de la que el en y a los se del las un por con no una su para es al lo como mas o pero sus le ha me si sin sobre este ya entre cuando todo esta ser son dos tambien fue habia era muy hasta desde mi porque que solo han yo hay vez puede todos asi nos ni parte tiene el uno donde bien tiempo mismo ese ahora cada vida otro despues te otros aunque esa eso hace otra tan durante siempre dia tanto ella tres si gran menos hola mundo clave secreto mensaje bandera contrasena usuario ' +
    'the be to of and in that have it for not on with he as you do at this but his by from they we say her she or an will my one all would there their what so up out if about who get which go me when make can like time no just him know take people into year your good some could them see other than then now look only come its over think also back after use two how our work first well way even new want because any these give day most us is are was were has had flag secret password key hello world message admin user root').split(' '));
  const FLAG_RE = /[A-Za-z0-9_]{2,16}\{[^{}\s]{2,120}\}/;

  function letterCounts(s) {
    const c = new Array(26).fill(0);
    let n = 0;
    for (const ch of foldAccents(s).toUpperCase()) { const k = ch.charCodeAt(0) - 65; if (k >= 0 && k < 26) { c[k]++; n++; } }
    return { c, n };
  }
  function chi(counts, n, lang) {
    if (!n) return Infinity;
    let x = 0;
    for (let i = 0; i < 26; i++) { const e = (FREQ[lang][i] / 100) * n || 0.0001; x += (counts[i] - e) ** 2 / e; }
    return x;
  }
  function chiBest(s) { const { c, n } = letterCounts(s); return Math.min(chi(c, n, 'es'), chi(c, n, 'en')) / Math.max(n, 1); }
  function ioc(counts, n) { if (n < 2) return 0; let s = 0; for (const v of counts) s += v * (v - 1); return s / (n * (n - 1)); }

  // 0-100: legible (imprimible), con frecuencias de idioma y palabras comunes; bonus si contiene una bandera.
  function quality(s) {
    if (!s) return 0;
    const chars = Array.from(s);
    let pr = 0;
    for (const ch of chars) {
      const cp = ch.codePointAt(0);
      if ((cp >= 32 && cp < 127) || cp === 10 || cp === 13 || cp === 9 || /\p{L}/u.test(ch)) pr++;
    }
    pr /= chars.length;
    if (pr < 0.85) return Math.round(pr * 20);
    // Bandera de CTF con prefijo de letras y contenido con el juego de caracteres habitual.
    const flag = /(^|[^A-Za-z0-9])[A-Za-z][A-Za-z0-9]{1,15}\{[A-Za-z0-9_\-!@#$%.?]{2,120}\}/.test(s) ? 40 : 0;
    if (flag && chars.length < 140 && pr === 1) return Math.min(99, 60 + flag);
    const { c, n } = letterCounts(s);
    const letterRatio = n / chars.length;
    const chiN = n ? Math.min(chi(c, n, 'es'), chi(c, n, 'en')) / n : 10;
    const lang = n >= 6 ? 35 / (1 + chiN) : 0;
    const words = foldAccents(s).toLowerCase().split(/[^a-z]+/).filter(w => w.length > 0);
    const hit = words.length ? words.filter(w => WORDS.has(w)).length / words.length : 0;
    let score = pr * 25 + lang * Math.min(1, letterRatio * 1.4) + hit * 40 + flag;
    if (words.length && words.every(w => w.length > 25)) score -= 15;
    return Math.max(0, Math.min(99, Math.round(score)));
  }

  // ───────────────────────── Ataques sin clave ─────────────────────────
  function crackCaesar(s) {
    const out = [];
    for (let k = 1; k < 26; k++) { const t = shiftText(s, -k); out.push({ key: k, text: t, score: quality(t), chi: chiBest(t) }); }
    return out.sort((a, b) => b.score - a.score || a.chi - b.chi);
  }
  function crackAffine(s) {
    const out = [];
    for (const a of [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]) for (let b = 0; b < 26; b++) {
      if (a === 1 && b === 0) continue;
      const t = affine(s, a, b, true);
      out.push({ key: `a=${a}, b=${b}`, a, b, text: t, score: quality(t), chi: chiBest(t) });
    }
    return out.sort((x, y) => x.chi - y.chi).slice(0, 25).sort((x, y) => y.score - x.score || x.chi - y.chi);
  }
  function crackRail(s) {
    const out = [];
    for (let r = 2; r <= Math.min(20, Array.from(s).length - 1); r++) { const t = railDec(s, r); out.push({ key: r, text: t, score: quality(t) }); }
    return out.sort((a, b) => b.score - a.score);
  }
  function crackScytale(s) {
    const out = [];
    for (let c = 2; c <= Math.min(30, Array.from(s).length - 1); c++) { const t = scytaleDec(s, c); out.push({ key: c, text: t, score: quality(t) }); }
    return out.sort((a, b) => b.score - a.score);
  }

  // Vigenère: longitud de clave por índice de coincidencia y cada letra por chi-cuadrado.
  function crackVigenere(s, maxLen) {
    const letters = s.replace(/[^A-Za-z]/g, '').toUpperCase();
    const n = letters.length;
    if (n < 20) fail('tooShort', { min: 20 });
    maxLen = Math.min(maxLen || 20, Math.floor(n / 3));
    const lens = [];
    for (let L = 1; L <= maxLen; L++) {
      let sum = 0;
      for (let c = 0; c < L; c++) {
        const cnt = new Array(26).fill(0); let m = 0;
        for (let i = c; i < n; i += L) { cnt[letters.charCodeAt(i) - 65]++; m++; }
        sum += ioc(cnt, m);
      }
      lens.push({ L, ioc: sum / L });
    }
    const best = Math.max(...lens.map(x => x.ioc));
    // Primero las longitudes cercanas al máximo, de menor a mayor (los múltiplos de la clave también dan IoC alto).
    const candidates = lens.filter(x => x.ioc >= best * 0.9).sort((a, b) => a.L - b.L).slice(0, 3);
    for (const x of lens.slice().sort((a, b) => b.ioc - a.ioc)) { if (candidates.length >= 4) break; if (!candidates.includes(x)) candidates.push(x); }
    const results = [];
    for (const { L, ioc: ic } of candidates) {
      for (const lang of ['es', 'en']) {
        let key = '';
        for (let c = 0; c < L; c++) {
          const cnt = new Array(26).fill(0); let m = 0;
          for (let i = c; i < n; i += L) { cnt[letters.charCodeAt(i) - 65]++; m++; }
          let bestK = 0, bestChi = Infinity;
          for (let k = 0; k < 26; k++) {
            const sh = new Array(26);
            for (let i = 0; i < 26; i++) sh[i] = cnt[(i + k) % 26];
            const x = chi(sh, m, lang);
            if (x < bestChi) { bestChi = x; bestK = k; }
          }
          key += String.fromCharCode(65 + bestK);
        }
        // Una clave que se repite (ABAB) se reduce a su periodo.
        for (let p = 1; p < key.length; p++) if (key.length % p === 0 && key.slice(0, p).repeat(key.length / p) === key) { key = key.slice(0, p); break; }
        if (results.some(r => r.key === key)) continue;
        const text = vigenere(s, key, true);
        results.push({ key, length: key.length, ioc: +ic.toFixed(4), lang, text, score: quality(text), chi: chiBest(text) });
      }
    }
    return results.sort((a, b) => b.score - a.score || a.chi - b.chi);
  }

  // Puntuación por byte (frecuencia de letras y espacios): sirve para columnas sueltas, que no forman palabras.
  const BYTE_W = new Float32Array(256).fill(-20);
  for (let i = 32; i < 127; i++) BYTE_W[i] = 0.5;
  for (let i = 0; i < 26; i++) { const f = (FREQ.es[i] + FREQ.en[i]) / 2; BYTE_W[97 + i] = f; BYTE_W[65 + i] = f * 0.4; }
  BYTE_W[32] = 15; BYTE_W[10] = BYTE_W[13] = BYTE_W[9] = 1;
  for (let i = 128; i < 256; i++) BYTE_W[i] = 0;
  function byteScore(b) { let s = 0; for (let i = 0; i < b.length; i++) s += BYTE_W[b[i]]; return s / Math.max(b.length, 1); }
  function bestXorByte(col) {
    let best = 0, bestS = -Infinity;
    for (let k = 0; k < 256; k++) { let s = 0; for (let i = 0; i < col.length; i++) s += BYTE_W[col[i] ^ k]; if (s > bestS) { bestS = s; best = k; } }
    return best;
  }

  function crackXor1(b) {
    const out = [];
    for (let k = 0; k < 256; k++) {
      const r = xorBytes(b, [k]);
      const { text, binary } = bytesToText(r);
      const score = binary ? Math.min(quality(text), 30) : quality(text);
      out.push({ key: '0x' + k.toString(16).padStart(2, '0'), keyByte: k, text, score, fs: byteScore(r), bytes: r });
    }
    return out.sort((a, b2) => b2.score - a.score || b2.fs - a.fs).slice(0, 15);
  }
  // XOR de clave repetida (como en los retos de cryptopals): tamaño por distancia de Hamming normalizada.
  function crackXorRepeat(b, maxLen) {
    if (b.length < 16) fail('tooShort', { min: 16 });
    const ham = (x, y) => { let d = 0; for (let i = 0; i < x.length; i++) { let v = x[i] ^ y[i]; while (v) { d += v & 1; v >>= 1; } } return d; };
    const sizes = [];
    for (let k = 1; k <= Math.min(maxLen || 40, Math.floor(b.length / 2)); k++) {
      const blocks = Math.min(Math.floor(b.length / k) - 1, 12);
      if (blocks < 1) continue;
      let d = 0;
      for (let i = 0; i < blocks; i++) d += ham(b.subarray(i * k, i * k + k), b.subarray((i + 1) * k, (i + 2) * k)) / k;
      sizes.push({ k, d: d / blocks });
    }
    sizes.sort((x, y) => x.d - y.d);
    const results = [];
    for (const { k } of sizes.slice(0, 5)) {
      const key = new Uint8Array(k);
      for (let c = 0; c < k; c++) {
        const col = [];
        for (let i = c; i < b.length; i += k) col.push(b[i]);
        key[c] = bestXorByte(col);
      }
      let kk = key;
      for (let p = 1; p < k; p++) if (k % p === 0 && Array.from(key).every((v, i) => v === key[i % p])) { kk = key.slice(0, p); break; }
      const hexKey = hexenc(kk);
      if (results.some(r => r.keyHex === hexKey)) continue;
      const r = xorBytes(b, kk);
      const { text, binary } = bytesToText(r);
      results.push({ key: asText(kk), keyHex: hexKey, length: kk.length, text, score: binary ? Math.min(quality(text), 30) : quality(text), bytes: r });
    }
    return results.sort((x, y) => y.score - x.score);
  }

  // ───────────────────────── Catálogo de operaciones ─────────────────────────
  // kind 'bytes': fn(bytes, params) → bytes | string ; kind 'text': fn(string, params) → string
  const T = (fn) => ({ kind: 'text', fn });
  const B = (fn) => ({ kind: 'bytes', fn });
  const OPS = [
    { id: 'base64', group: 'enc', enc: B(b => b64enc(b)), dec: B(b => b64dec(asText(b))), strict: true },
    { id: 'base32', group: 'enc', enc: B(b => b32enc(b)), dec: B(b => b32dec(asText(b))), strict: true },
    { id: 'base58', group: 'enc', enc: B(b => b58enc(b)), dec: B(b => b58dec(asText(b))), strict: true },
    { id: 'ascii85', group: 'enc', enc: B(b => a85enc(b)), dec: B(b => a85dec(asText(b))), strict: true },
    { id: 'hex', group: 'enc', enc: B(b => hexenc(b)), dec: B(b => hexdec(asText(b))), strict: true },
    { id: 'binary', group: 'enc', enc: B(b => binenc(b)), dec: B(b => bindec(asText(b))), strict: true },
    { id: 'decimal', group: 'enc', enc: B(b => decenc(b)), dec: B(b => decdec(asText(b))), strict: true },
    { id: 'url', group: 'enc', enc: B(b => urlenc(b)), dec: B(b => urldec(b)), strict: true },
    { id: 'html', group: 'enc', enc: T(s => htmlenc(s)), dec: T(s => htmldec(s)), strict: true },
    { id: 'morse', group: 'enc', enc: T(s => morseenc(s)), dec: T(s => morsedec(s)), strict: true },
    { id: 'bacon', group: 'enc', params: [{ id: 'v24', type: 'check', def: false }], enc: T((s, p) => baconenc(s, p)), dec: T((s, p) => bacondec(s, p)), strict: true },
    { id: 'reverse', group: 'enc', enc: T(s => Array.from(s).reverse().join('')), dec: T(s => Array.from(s).reverse().join('')) },
    { id: 'rot13', group: 'classic', enc: T(s => shiftText(s, 13)), dec: T(s => shiftText(s, 13)) },
    { id: 'rot47', group: 'classic', enc: T(rot47), dec: T(rot47) },
    { id: 'caesar', group: 'classic', params: [{ id: 'shift', type: 'number', def: 3, min: 1, max: 25 }], enc: T((s, p) => shiftText(s, +p.shift)), dec: T((s, p) => shiftText(s, -p.shift)), crack: 'caesar' },
    { id: 'atbash', group: 'classic', enc: T(atbash), dec: T(atbash) },
    { id: 'vigenere', group: 'classic', params: [{ id: 'key', type: 'text', def: '' }], enc: T((s, p) => vigenere(s, p.key, false)), dec: T((s, p) => vigenere(s, p.key, true)), crack: 'vigenere' },
    { id: 'affine', group: 'classic', params: [{ id: 'a', type: 'number', def: 5, min: 1, max: 25 }, { id: 'b', type: 'number', def: 8, min: 0, max: 25 }], enc: T((s, p) => affine(s, p.a, p.b, false)), dec: T((s, p) => affine(s, p.a, p.b, true)), crack: 'affine' },
    { id: 'rail', group: 'classic', params: [{ id: 'rails', type: 'number', def: 3, min: 2, max: 50 }], enc: T((s, p) => railEnc(s, p.rails)), dec: T((s, p) => railDec(s, p.rails)), crack: 'rail' },
    { id: 'scytale', group: 'classic', params: [{ id: 'cols', type: 'number', def: 4, min: 2, max: 100 }], enc: T((s, p) => scytaleEnc(s, p.cols)), dec: T((s, p) => scytaleDec(s, p.cols)), crack: 'scytale' },
    { id: 'polybius', group: 'classic', params: [{ id: 'key', type: 'text', def: '' }], enc: T((s, p) => polyEnc(s, p)), dec: T((s, p) => polyDec(s, p)), strict: true },
    { id: 'playfair', group: 'classic', params: [{ id: 'key', type: 'text', def: '' }, { id: 'clean', type: 'check', def: true }], enc: T((s, p) => playfair(s, p.key, false)), dec: T((s, p) => playfair(s, p.key, true, p.clean)) },
    { id: 'xor', group: 'modern', params: [{ id: 'key', type: 'text', def: '' }, { id: 'fmt', type: 'select', def: 'text', options: ['text', 'hex'] }], enc: B((b, p) => xorBytes(b, parseKeyBytes(p.key, p.fmt))), dec: B((b, p) => xorBytes(b, parseKeyBytes(p.key, p.fmt))), crack: 'xor' },
  ];
  const OP = Object.fromEntries(OPS.map(o => [o.id, o]));

  function defaults(op) { const p = {}; for (const d of op.params || []) p[d.id] = d.def; return p; }

  // Aplica una operación. input: Uint8Array o string. Devuelve Uint8Array.
  function run(id, mode, input, params) {
    const op = OP[id];
    if (!op) fail('unknownOp');
    const impl = op[mode];
    if (!impl) fail('noMode');
    const p = Object.assign(defaults(op), params || {});
    const bytes = typeof input === 'string' ? utf8(input) : input;
    const r = impl.kind === 'text' ? impl.fn(asText(bytes), p) : impl.fn(bytes, p);
    return typeof r === 'string' ? utf8(r) : r;
  }

  function crack(kind, input) {
    const bytes = typeof input === 'string' ? utf8(input) : input;
    const s = asText(bytes);
    switch (kind) {
      case 'caesar': return crackCaesar(s);
      case 'affine': return crackAffine(s);
      case 'rail': return crackRail(s);
      case 'scytale': return crackScytale(s);
      case 'vigenere': return crackVigenere(s);
      case 'xor': {
        let data = bytes;
        try { data = hexdec(s); } catch (e) { try { data = b64dec(s); } catch (e2) { /* tal cual */ } }
        const one = crackXor1(data).map(r => Object.assign(r, { mode: 'xor1' }));
        let rep = [];
        try { rep = crackXorRepeat(data).map(r => Object.assign(r, { mode: 'xorN' })); } catch (e) { /* demasiado corto */ }
        return one.concat(rep).sort((a, b) => b.score - a.score).slice(0, 15);
      }
      default: fail('unknownOp');
    }
  }

  // «Magia»: prueba decodificadores estrictos en cadena (hasta 3 pasos) y, al final, transformaciones
  // de texto; ordena los resultados por cuánto parecen texto. Devuelve la receta de cada uno.
  function magic(input, opts) {
    opts = opts || {};
    const maxDepth = opts.depth || 3;
    const start = typeof input === 'string' ? utf8(input.trim()) : input;
    const seen = new Set();
    const results = [];
    const strict = OPS.filter(o => o.strict && o.dec && o.id !== 'bacon');
    const textOps = [['rot13', {}], ['rot47', {}], ['atbash', {}], ['reverse', {}]];
    const push = (bytes, recipe) => {
      const { text, binary } = bytesToText(bytes);
      const key = text;
      if (seen.has(key)) return false;
      seen.add(key);
      const score = binary ? Math.min(quality(text), 25) : quality(text);
      results.push({ recipe, text, binary, score, bytes });
      return true;
    };
    seen.add(asText(start));
    let frontier = [{ bytes: start, recipe: [] }];
    for (let depth = 0; depth < maxDepth && frontier.length; depth++) {
      const next = [];
      for (const node of frontier) {
        for (const op of strict) {
          let out;
          try { out = run(op.id, 'dec', node.bytes); } catch (e) { continue; }
          if (!out.length || out.length > 1e6) continue;
          const recipe = node.recipe.concat([{ id: op.id, mode: 'dec' }]);
          if (push(out, recipe) && !bytesToText(out).binary) next.push({ bytes: out, recipe });
        }
      }
      frontier = next.slice(0, 40);
    }
    // Transformaciones de texto sobre la entrada y sobre lo mejor encontrado.
    const bases = [{ bytes: start, recipe: [] }].concat(results.filter(r => !r.binary).sort((a, b) => b.score - a.score).slice(0, 6));
    for (const base of bases) {
      const s = asText(base.bytes);
      for (const [id, p] of textOps) push(run(id, 'dec', base.bytes, p), base.recipe.concat([{ id, mode: 'dec' }]));
      if (/[A-Za-z]/.test(s)) {
        const c = crackCaesar(s)[0];
        if (c && c.key !== 13) push(utf8(c.text), base.recipe.concat([{ id: 'caesar', mode: 'dec', params: { shift: c.key } }]));
      }
      if (base.recipe.length && !/[A-Za-z]{3}/.test(s)) continue;
    }
    // XOR de un byte solo si la entrada parece hex o binaria.
    try {
      const raw = hexdec(asText(start));
      const best = crackXor1(raw)[0];
      if (best && best.score > 50) push(best.bytes, [{ id: 'hex', mode: 'dec' }, { id: 'xor', mode: 'dec', params: { key: best.key.slice(2), fmt: 'hex' } }]);
    } catch (e) { /* no es hex */ }
    return results.filter(r => r.score > 0).sort((a, b) => b.score - a.score || a.recipe.length - b.recipe.length).slice(0, opts.limit || 12);
  }

  return { OPS, OP, run, crack, magic, quality, bytesToText, asText, hexOf, utf8, defaults, OpError, FLAG_RE,
    _: { b64enc, b64dec, b32enc, b32dec, b58enc, b58dec, a85enc, a85dec, hexdec, hexenc, scytaleEnc, scytaleDec, railEnc, railDec, vigenere, affine, playfair, polyEnc, polyDec, morseenc, morsedec, baconenc, bacondec, xorBytes, crackVigenere, crackXorRepeat, chiBest } };
});
