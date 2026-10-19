/* InspectorKit · análisis de archivos a nivel de bytes. Sin DOM: funciona igual en Node.
   Tipo real por firma, entropía, cadenas, indicadores (IOC), archivos incrustados, datos
   añadidos tras el fin de archivo, estructura PNG/JPEG/ZIP/PDF/PE/ELF y borrado de metadatos. */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory(root.IKHash || (typeof require === 'function' ? require('./hash.js') : null));
  else root.IKBytes = factory(root.IKHash);
})(typeof self !== 'undefined' ? self : this, function (IKHash) {
  'use strict';

  const latin1 = (b, s, e) => { let o = ''; for (let i = s || 0, n = e == null ? b.length : Math.min(e, b.length); i < n; i++) o += String.fromCharCode(b[i]); return o; };
  const at = (b, off, sig) => { if (off + sig.length > b.length) return false; for (let i = 0; i < sig.length; i++) if (sig[i] !== null && b[off + i] !== sig[i]) return false; return true; };
  const str = (s) => Array.from(s, c => c.charCodeAt(0));
  const u16le = (b, o) => b[o] | (b[o + 1] << 8);
  const u32le = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
  const u32be = (b, o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
  const u16be = (b, o) => (b[o] << 8) | b[o + 1];
  const tdUtf8 = new TextDecoder('utf-8');
  const tdUtf16le = new TextDecoder('utf-16le');

  // ───────────────────────── Descompresión (Web Streams, nativo en navegador y Node 18+) ─────────────────────────
  async function inflate(bytes, format) {
    if (typeof DecompressionStream === 'undefined') throw new Error('nostream');
    const ds = new DecompressionStream(format || 'deflate');
    const stream = new Blob([bytes]).stream().pipeThrough(ds);
    return new Uint8Array(await new Response(stream).arrayBuffer());
  }

  // ───────────────────────── Firmas ─────────────────────────
  // [desplazamiento, firma (null = cualquier byte), id, extensiones, MIME, fuerte (vale para buscar incrustados)]
  const SIGS = [
    [0, [0xFF, 0xD8, 0xFF], 'jpeg', ['jpg', 'jpeg', 'jfif'], 'image/jpeg', true],
    [0, [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], 'png', ['png'], 'image/png', true],
    [0, str('GIF87a'), 'gif', ['gif'], 'image/gif', true],
    [0, str('GIF89a'), 'gif', ['gif'], 'image/gif', true],
    [0, [0x52, 0x49, 0x46, 0x46, null, null, null, null, 0x57, 0x45, 0x42, 0x50], 'webp', ['webp'], 'image/webp', true],
    [0, [0x52, 0x49, 0x46, 0x46, null, null, null, null, 0x57, 0x41, 0x56, 0x45], 'wav', ['wav'], 'audio/wav', true],
    [0, [0x52, 0x49, 0x46, 0x46, null, null, null, null, 0x41, 0x56, 0x49, 0x20], 'avi', ['avi'], 'video/x-msvideo', true],
    [0, [0x49, 0x49, 0x2A, 0x00], 'tiff', ['tif', 'tiff', 'dng', 'cr2', 'nef', 'arw'], 'image/tiff', false],
    [0, [0x4D, 0x4D, 0x00, 0x2A], 'tiff', ['tif', 'tiff', 'nef'], 'image/tiff', false],
    [0, str('8BPS'), 'psd', ['psd'], 'image/vnd.adobe.photoshop', true],
    [0, [0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20], 'jp2', ['jp2'], 'image/jp2', true],
    [0, [0x00, 0x00, 0x01, 0x00], 'ico', ['ico'], 'image/x-icon', false],
    [0, str('BM'), 'bmp', ['bmp', 'dib'], 'image/bmp', false],
    [0, str('%PDF-'), 'pdf', ['pdf'], 'application/pdf', true],
    [0, [0x50, 0x4B, 0x03, 0x04], 'zip', ['zip'], 'application/zip', true],
    [0, [0x50, 0x4B, 0x05, 0x06], 'zip', ['zip'], 'application/zip', false],
    [0, [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07], 'rar', ['rar'], 'application/vnd.rar', true],
    [0, [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C], '7z', ['7z'], 'application/x-7z-compressed', true],
    [0, [0x1F, 0x8B, 0x08], 'gzip', ['gz', 'tgz'], 'application/gzip', false],
    [0, str('BZh'), 'bzip2', ['bz2'], 'application/x-bzip2', false],
    [0, [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00], 'xz', ['xz'], 'application/x-xz', true],
    [0, [0x28, 0xB5, 0x2F, 0xFD], 'zstd', ['zst'], 'application/zstd', false],
    [257, str('ustar'), 'tar', ['tar'], 'application/x-tar', false],
    [0, [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1], 'ole', ['doc', 'xls', 'ppt', 'msi', 'msg'], 'application/x-ole-storage', true],
    [0, str('MZ'), 'pe', ['exe', 'dll', 'sys', 'scr', 'cpl', 'ocx'], 'application/vnd.microsoft.portable-executable', false],
    [0, [0x7F, 0x45, 0x4C, 0x46], 'elf', ['', 'so', 'elf', 'bin', 'o'], 'application/x-elf', true],
    [0, [0xCF, 0xFA, 0xED, 0xFE], 'macho', ['', 'dylib'], 'application/x-mach-binary', true],
    [0, [0xCE, 0xFA, 0xED, 0xFE], 'macho', ['', 'dylib'], 'application/x-mach-binary', true],
    [0, [0xCA, 0xFE, 0xBA, 0xBE], 'cafebabe', ['class', ''], 'application/java-vm', false],
    [0, str('dex\n'), 'dex', ['dex'], 'application/vnd.android.dex', true],
    [0, [0x00, 0x61, 0x73, 0x6D], 'wasm', ['wasm'], 'application/wasm', true],
    [0, str('ID3'), 'mp3', ['mp3'], 'audio/mpeg', false],
    [0, [0xFF, 0xFB], 'mp3', ['mp3'], 'audio/mpeg', false],
    [0, [0xFF, 0xF3], 'mp3', ['mp3'], 'audio/mpeg', false],
    [0, str('OggS'), 'ogg', ['ogg', 'oga', 'ogv', 'opus'], 'audio/ogg', true],
    [0, str('fLaC'), 'flac', ['flac'], 'audio/flac', true],
    [0, [0x1A, 0x45, 0xDF, 0xA3], 'mkv', ['mkv', 'webm'], 'video/x-matroska', true],
    [0, str('SQLite format 3\0'), 'sqlite', ['sqlite', 'db', 'sqlite3'], 'application/vnd.sqlite3', true],
    [0, str('{\\rtf'), 'rtf', ['rtf'], 'application/rtf', true],
    [0, str('%!PS'), 'ps', ['ps', 'eps'], 'application/postscript', false],
    [0, [0xD4, 0xC3, 0xB2, 0xA1], 'pcap', ['pcap', 'cap'], 'application/vnd.tcpdump.pcap', true],
    [0, [0xA1, 0xB2, 0xC3, 0xD4], 'pcap', ['pcap', 'cap'], 'application/vnd.tcpdump.pcap', true],
    [0, [0x0A, 0x0D, 0x0D, 0x0A], 'pcapng', ['pcapng'], 'application/x-pcapng', false],
    [0, [0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00], 'lnk', ['lnk'], 'application/x-ms-shortcut', true],
    [0, str('!<arch>\n'), 'ar', ['deb', 'a', 'ar'], 'application/x-archive', true],
    [0, [0xED, 0xAB, 0xEE, 0xDB], 'rpm', ['rpm'], 'application/x-rpm', true],
    [0, str('MSCF'), 'cab', ['cab'], 'application/vnd.ms-cab-compressed', true],
    [0x8001, str('CD001'), 'iso', ['iso'], 'application/x-iso9660-image', false],
    [0, str('regf'), 'regf', ['dat', 'hiv', ''], 'application/x-windows-registry', true],
    [0, str('ElfFile\0'), 'evtx', ['evtx'], 'application/x-ms-evtx', true],
    [0, str('MDMP'), 'mdmp', ['dmp', 'mdmp'], 'application/x-dmp', false],
    [0, str('KDMV'), 'vmdk', ['vmdk'], 'application/x-vmdk', true],
    [0, str('wOFF'), 'woff', ['woff'], 'font/woff', true],
    [0, str('wOF2'), 'woff2', ['woff2'], 'font/woff2', true],
    [0, str('OTTO'), 'otf', ['otf'], 'font/otf', false],
    [0, str('-----BEGIN '), 'pem', ['pem', 'crt', 'cer', 'key', 'pub', ''], 'application/x-pem-file', true],
    [0, str('openssh-key-v1\0'), 'sshkey', [''], 'application/octet-stream', true],
    [0, str('#!'), 'script', ['sh', 'py', 'pl', 'rb', ''], 'text/x-script', false],
    [0, str('<?xml'), 'xml', ['xml', 'svg', 'plist', 'xaml', 'rss', 'kml', 'gpx'], 'application/xml', false],
  ];

  function ftyp(b) {
    if (!at(b, 4, str('ftyp'))) return null;
    const brand = latin1(b, 8, 12).trim();
    const compat = latin1(b, 16, Math.min(64, u32be(b, 0)));
    if (/^(heic|heix|hevc|hevx|heim|heis)$/.test(brand) || (brand === 'mif1' && /heic/.test(compat))) return { id: 'heic', ext: ['heic', 'heif'], mime: 'image/heic' };
    if (/^avi[fs]$/.test(brand) || (brand === 'mif1' && /avif/.test(compat))) return { id: 'avif', ext: ['avif'], mime: 'image/avif' };
    if (brand === 'qt') return { id: 'mov', ext: ['mov', 'qt'], mime: 'video/quicktime' };
    if (/^M4A/.test(brand)) return { id: 'm4a', ext: ['m4a'], mime: 'audio/mp4' };
    if (/^3g/.test(brand)) return { id: '3gp', ext: ['3gp', '3g2'], mime: 'video/3gpp' };
    if (brand === 'crx') return { id: 'cr3', ext: ['cr3'], mime: 'image/x-canon-cr3' };
    return { id: 'mp4', ext: ['mp4', 'm4v'], mime: 'video/mp4', brand };
  }

  // Tipo de un ZIP por su contenido (OOXML, ODF, APK, JAR, EPUB).
  function zipKind(entries) {
    const names = entries.map(e => e.name);
    const has = (p) => names.some(n => n === p || n.startsWith(p));
    if (has('word/')) return { id: 'docx', ext: ['docx', 'docm', 'dotx'], mime: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' };
    if (has('xl/')) return { id: 'xlsx', ext: ['xlsx', 'xlsm', 'xltx'], mime: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' };
    if (has('ppt/')) return { id: 'pptx', ext: ['pptx', 'pptm', 'potx'], mime: 'application/vnd.openxmlformats-officedocument.presentationml.presentation' };
    if (has('AndroidManifest.xml') && has('classes')) return { id: 'apk', ext: ['apk'], mime: 'application/vnd.android.package-archive' };
    if (has('META-INF/MANIFEST.MF')) return { id: 'jar', ext: ['jar', 'war', 'ear'], mime: 'application/java-archive' };
    if (names[0] === 'mimetype' && has('META-INF/container.xml')) return { id: 'epub', ext: ['epub'], mime: 'application/epub+zip' };
    if (names[0] === 'mimetype' && has('content.xml')) return { id: 'odf', ext: ['odt', 'ods', 'odp', 'odg'], mime: 'application/vnd.oasis.opendocument' };
    return null;
  }

  function isMostlyText(b) {
    const n = Math.min(b.length, 8192);
    if (!n) return false;
    let bad = 0;
    for (let i = 0; i < n; i++) { const x = b[i]; if (x === 0) return false; if (x < 9 || (x > 13 && x < 32)) bad++; }
    if (bad / n > 0.02) return false;
    try { new TextDecoder('utf-8', { fatal: true }).decode(b.subarray(0, n - 4 > 0 ? n - 4 : n)); return true; } catch (e) { return bad === 0 && n > 0; }
  }

  function detect(b, name) {
    let type = null;
    for (const [off, sig, id, ext, mime] of SIGS) {
      if (at(b, off, sig)) {
        if (id === 'pe') { const pe = peHeader(b); if (!pe) continue; type = { id: pe.dll ? 'dll' : 'pe', ext: pe.dll ? ['dll', 'ocx', 'cpl'] : ext, mime }; break; }
        if (id === 'bmp' && !(b.length >= 26 && u32le(b, 14) >= 12 && u32le(b, 14) <= 124)) continue;
        if (id === 'ico' && !(b.length > 6 && u16le(b, 4) > 0 && u16le(b, 4) < 256)) continue;
        if (id === 'mp3' && sig[0] === 0xFF && b.length < 4) continue;
        type = { id, ext, mime }; break;
      }
    }
    if (!type) { const f = ftyp(b); if (f) type = f; }
    if (type && type.id === 'zip') { const z = zipEntries(b); const k = z && zipKind(z.entries); if (k) type = k; }
    if (type && type.id === 'cafebabe') {
      // Mach-O universal o clase Java: en Java los bytes 4-7 son la versión (≥ 45).
      const v = u16be(b, 6); type = v >= 45 ? { id: 'class', ext: ['class'], mime: 'application/java-vm' } : { id: 'macho', ext: [''], mime: 'application/x-mach-binary' };
    }
    if (!type) {
      const head = latin1(b, 0, 512).replace(/^﻿|^\xEF\xBB\xBF/, '').trimStart().toLowerCase();
      if (/^<svg|^<\?xml[^>]*>\s*(<!--[\s\S]*?-->\s*)*<svg/.test(head)) type = { id: 'svg', ext: ['svg'], mime: 'image/svg+xml' };
      else if (/^<!doctype html|^<html/.test(head)) type = { id: 'html', ext: ['html', 'htm'], mime: 'text/html' };
      else if (/^[{[]/.test(head) && isMostlyText(b)) type = { id: 'json', ext: ['json'], mime: 'application/json' };
      else if (isMostlyText(b)) type = { id: 'text', ext: ['txt', 'csv', 'log', 'md', 'ini', 'cfg', 'conf', 'js', 'py', 'ps1', 'bat', 'sh', 'c', 'h', 'css', 'html', 'xml', 'json', 'yml', 'yaml', 'sql', 'eml', 'srt', 'vbs', 'php', 'asp', 'aspx', 'jsp', 'rs', 'go', 'java', 'ts', 'tsx', 'jsx', 'cs', 'cpp', 'reg', 'inf', 'hta', 'url', 'desktop', 'service', 'toml', 'env', 'tex', 'rtf', 'svg'], mime: 'text/plain' };
    }
    if (type && type.id === 'svg') type.ext = ['svg'];
    const ext = (String(name || '').match(/\.([A-Za-z0-9]{1,8})$/) || [])[1];
    const e = ext ? ext.toLowerCase() : '';
    const mismatch = !!(type && e && type.ext && !type.ext.includes(e) && !(type.id === 'text' && !/^(exe|dll|jpg|jpeg|png|gif|pdf|zip|docx|xlsx|pptx|mp3|mp4|rar|7z)$/.test(e)));
    return { type: type ? type.id : 'unknown', mime: type ? type.mime : 'application/octet-stream', expectedExt: type ? type.ext : [], ext: e, mismatch };
  }

  // ───────────────────────── Entropía ─────────────────────────
  function entropy(b, start, end) {
    start = start || 0; end = end == null ? b.length : end;
    const n = end - start;
    if (n <= 0) return 0;
    const f = new Uint32Array(256);
    for (let i = start; i < end; i++) f[b[i]]++;
    let h = 0;
    for (let i = 0; i < 256; i++) if (f[i]) { const p = f[i] / n; h -= p * Math.log2(p); }
    return h;
  }
  function entropyBlocks(b, count) {
    count = Math.max(1, Math.min(count || 128, b.length));
    const size = Math.ceil(b.length / count);
    const out = [];
    for (let i = 0; i < b.length; i += size) out.push({ offset: i, e: entropy(b, i, Math.min(b.length, i + size)) });
    return { size, blocks: out };
  }

  // ───────────────────────── Cadenas ─────────────────────────
  // ASCII/UTF-8 (incluye letras acentuadas) y UTF-16LE (cadenas de Windows).
  function strings(b, opts) {
    opts = opts || {};
    const min = Math.max(2, opts.min || 4);
    const max = opts.max || 200000;
    const out = [];
    const printable = (c) => (c >= 0x20 && c < 0x7F) || c === 0x09;
    if (opts.utf8 !== false) {
      let start = -1, chars = 0;
      const flush = (end) => { if (start >= 0 && chars >= min && out.length < max) out.push({ offset: start, enc: 'utf8', text: tdUtf8.decode(b.subarray(start, end)) }); start = -1; chars = 0; };
      for (let i = 0; i < b.length;) {
        const c = b[i];
        let len = 0;
        if (printable(c)) len = 1;
        else if (c >= 0xC2 && c <= 0xDF && i + 1 < b.length && (b[i + 1] & 0xC0) === 0x80) len = 2;
        else if (c >= 0xE0 && c <= 0xEF && i + 2 < b.length && (b[i + 1] & 0xC0) === 0x80 && (b[i + 2] & 0xC0) === 0x80) len = 3;
        if (len && len > 1) {
          const cp = len === 2 ? ((c & 0x1F) << 6) | (b[i + 1] & 0x3F) : ((c & 0x0F) << 12) | ((b[i + 1] & 0x3F) << 6) | (b[i + 2] & 0x3F);
          if (cp < 0xA0 || (cp >= 0xD800 && cp <= 0xDFFF) || cp === 0xFFFD) len = 0;
        }
        if (len) { if (start < 0) start = i; chars++; i += len; }
        else { flush(i); i++; }
      }
      flush(b.length);
    }
    if (opts.utf16 !== false) {
      for (const parity of [0, 1]) {
        let start = -1, chars = 0;
        const flush = (end) => { if (start >= 0 && chars >= min && out.length < max) out.push({ offset: start, enc: 'utf16le', text: tdUtf16le.decode(b.subarray(start, end)) }); start = -1; chars = 0; };
        for (let i = parity; i + 1 < b.length; i += 2) {
          const lo = b[i], hi = b[i + 1];
          const ok = (hi === 0 && printable(lo)) || (hi === 0 && lo >= 0xA0) ;
          if (ok) { if (start < 0) start = i; chars++; }
          else flush(i);
        }
        flush(b.length - ((b.length - parity) % 2));
      }
    }
    out.sort((x, y) => x.offset - y.offset);
    return { list: out, truncated: out.length >= max };
  }

  // Busca términos (o expresiones regulares) en las cadenas y cuenta TODAS las apariciones.
  function search(list, terms, opts) {
    opts = opts || {};
    const res = [];
    for (const term of terms) {
      let re;
      try { re = opts.regex ? new RegExp(term, opts.caseSensitive ? 'g' : 'gi') : new RegExp(term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), opts.caseSensitive ? 'g' : 'gi'); }
      catch (e) { res.push({ term, error: 'badRegex', count: 0, hits: [] }); continue; }
      let count = 0;
      const hits = [];
      for (const s of list) {
        re.lastIndex = 0;
        let m, local = 0;
        while ((m = re.exec(s.text))) { local++; if (m[0] === '') re.lastIndex++; if (local > 10000) break; }
        if (local) { count += local; if (hits.length < 500) hits.push({ offset: s.offset, enc: s.enc, text: s.text, n: local }); }
      }
      res.push({ term, count, strings: hits.length, hits });
    }
    return res;
  }

  function searchBytes(b, hex, max) {
    const t = String(hex || '').replace(/0x|\\x|[\s:,-]/gi, '');
    if (!t || t.length % 2 || /[^0-9a-f?]/i.test(t)) return null;
    const pat = t.match(/../g).map(p => (p === '??' ? null : parseInt(p, 16)));
    if (pat.some(x => Number.isNaN(x))) return null;
    const hits = [];
    for (let i = 0; i + pat.length <= b.length && hits.length < (max || 1000); i++) if (at(b, i, pat)) hits.push(i);
    return hits;
  }

  // ───────────────────────── Indicadores (IOC) y secretos ─────────────────────────
  const IOC_RULES = [
    ['flag', /(?<![A-Za-z0-9])[A-Za-z][A-Za-z0-9]{1,15}\{[A-Za-z0-9_\-!@#$%.?]{2,120}\}/g],
    ['privkey', /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----/g],
    ['aws', /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g],
    ['gcp', /\bAIza[0-9A-Za-z_-]{35}\b/g],
    ['github', /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b/g],
    ['slack', /\bxox[abposr]-[A-Za-z0-9-]{10,}\b/g],
    ['stripe', /\b[sr]k_live_[A-Za-z0-9]{20,}\b/g],
    ['jwt', /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g],
    ['url', /\b(?:https?|ftp):\/\/[^\s"'<>()\\\]{}|^`]{3,2000}/g],
    ['email', /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}\b/g],
    ['ipv4', /(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])/g],
    ['winpath', /\b[A-Za-z]:\\(?:[^\\\s"*?<>|:]+\\)*[^\\\s"*?<>|:]*/g],
    ['unixpath', /(?<![\w/])\/(?:etc|home|usr|var|tmp|root|opt|bin|sbin|proc|dev)\/[^\s"'<>:;,]*/g],
    ['registry', /\b(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|HKLM|HKCU|HKCR)\\[^\s"'<>]+/g],
    ['pdb', /[A-Za-z]:\\[^\s"<>|]{1,400}\.pdb\b/g],
    ['md5', /\b[a-f0-9]{32}\b/gi],
    ['sha1', /\b[a-f0-9]{40}\b/gi],
    ['sha256', /\b[a-f0-9]{64}\b/gi],
    ['base64', /(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?(?![A-Za-z0-9+/=])/g],
  ];
  const SECRET_KINDS = new Set(['privkey', 'aws', 'gcp', 'github', 'slack', 'stripe', 'jwt']);

  function privateIp(ip) {
    const [a, b2] = ip.split('.').map(Number);
    return a === 10 || a === 127 || (a === 172 && b2 >= 16 && b2 < 32) || (a === 192 && b2 === 168) || (a === 169 && b2 === 254) || a === 0 || a >= 224;
  }

  function iocs(list) {
    const found = {};
    for (const [kind] of IOC_RULES) found[kind] = new Map();
    for (const s of list) {
      for (const [kind, re] of IOC_RULES) {
        re.lastIndex = 0;
        let m;
        while ((m = re.exec(s.text))) {
          let v = m[0];
          if (kind === 'url') v = v.replace(/[.,;:!?'")\]]+$/, '');
          if (kind === 'base64') {
            if (/^[A-Za-z]+$/.test(v) || /^[0-9]+$/.test(v) || /^[a-f0-9]+$/i.test(v)) continue;
            let ok = false;
            try { const d = (typeof atob === 'function' ? atob(v) : Buffer.from(v, 'base64').toString('latin1')); let p = 0; for (const ch of d) { const c = ch.charCodeAt(0); if ((c >= 32 && c < 127) || c === 10 || c === 13 || c === 9) p++; } ok = d.length >= 8 && p / d.length > 0.9; } catch (e) { ok = false; }
            if (!ok) continue;
          }
          if (kind === 'ipv4' && /^\d+\.\d+\.\d+\.\d+$/.test(v) && /^0\./.test(v) && !/^0\.0\.0\.0$/.test(v)) continue;
          const map = found[kind];
          const cur = map.get(v);
          if (cur) cur.count++; else map.set(v, { value: v, count: 1, offset: s.offset, private: kind === 'ipv4' ? privateIp(v) : undefined });
          if (map.size > 5000) break;
        }
      }
    }
    // Un hash hex dentro de una URL o un SHA-256 que también casa como «base64» no se duplican.
    const out = {};
    for (const [kind, map] of Object.entries(found)) if (map.size) out[kind] = Array.from(map.values()).sort((a, b2) => b2.count - a.count);
    return { found: out, secrets: Object.keys(out).filter(k => SECRET_KINDS.has(k)) };
  }

  // ───────────────────────── Estructura por formato ─────────────────────────
  // JPEG: segmentos y fin real (EOI) teniendo en cuenta los datos comprimidos tras cada SOS.
  function jpegStructure(b) {
    if (!at(b, 0, [0xFF, 0xD8])) return null;
    const segs = [];
    let i = 2, end = null, width = null, height = null;
    const APPNAMES = [['JFIF\0', 'JFIF'], ['Exif\0', 'EXIF'], ['http://ns.adobe.com/xap/1.0/\0', 'XMP'], ['http://ns.adobe.com/xmp/extension/\0', 'XMP extendido'],
      ['ICC_PROFILE\0', 'Perfil ICC'], ['Photoshop 3.0\0', 'Photoshop/IPTC'], ['Adobe', 'Adobe'], ['Ducky', 'Ducky'], ['MPF\0', 'MPF (multi-imagen)']];
    const comments = [];
    while (i < b.length - 1) {
      if (b[i] !== 0xFF) { i++; continue; }
      const m = b[i + 1];
      if (m === 0xFF) { i++; continue; }
      if (m === 0xD9) { end = i + 2; segs.push({ marker: 'EOI', offset: i, length: 2 }); break; }
      if (m === 0x01 || (m >= 0xD0 && m <= 0xD7)) { i += 2; continue; }
      if (i + 4 > b.length) break;
      const len = u16be(b, i + 2);
      const seg = { marker: markerName(m), code: m, offset: i, length: len + 2 };
      if (m >= 0xE0 && m <= 0xEF) {
        const id = latin1(b, i + 4, i + 4 + 40);
        const hit = APPNAMES.find(([p]) => id.startsWith(p));
        seg.app = hit ? hit[1] : id.replace(/[^\x20-\x7e].*$/, '').slice(0, 20) || '?';
      }
      if (m === 0xFE) { const c = tdUtf8.decode(b.subarray(i + 4, i + 2 + len)); seg.text = c; comments.push(c); }
      if ((m >= 0xC0 && m <= 0xC3) || (m >= 0xC5 && m <= 0xC7) || (m >= 0xC9 && m <= 0xCB) || (m >= 0xCD && m <= 0xCF)) { height = u16be(b, i + 5); width = u16be(b, i + 7); seg.progressive = m === 0xC2; }
      segs.push(seg);
      i += 2 + len;
      if (m === 0xDA) {
        // Datos comprimidos: termina en el siguiente marcador que no sea relleno (FF00) ni RST.
        while (i < b.length - 1) {
          if (b[i] === 0xFF && b[i + 1] !== 0x00 && !(b[i + 1] >= 0xD0 && b[i + 1] <= 0xD7) && b[i + 1] !== 0xFF) break;
          i++;
        }
      }
    }
    return { segments: segs, end, width, height, comments, eoiFound: end != null };
  }
  function markerName(m) {
    if (m >= 0xE0 && m <= 0xEF) return 'APP' + (m - 0xE0);
    const N = { 0xC0: 'SOF0', 0xC1: 'SOF1', 0xC2: 'SOF2', 0xC3: 'SOF3', 0xC4: 'DHT', 0xDB: 'DQT', 0xDA: 'SOS', 0xDD: 'DRI', 0xFE: 'COM', 0xD8: 'SOI', 0xD9: 'EOI', 0xCC: 'DAC' };
    return N[m] || '0x' + m.toString(16).toUpperCase();
  }

  // PNG: trozos con CRC, cabecera y textos. Si el CRC de IHDR no cuadra, busca el ancho/alto reales.
  const PNG_SIG = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
  const PNG_KNOWN = new Set(['IHDR', 'PLTE', 'IDAT', 'IEND', 'tRNS', 'cHRM', 'gAMA', 'iCCP', 'sBIT', 'sRGB', 'cICP', 'mDCV', 'cLLI', 'tEXt', 'zTXt', 'iTXt', 'bKGD', 'hIST', 'pHYs', 'sPLT', 'eXIf', 'tIME', 'acTL', 'fcTL', 'fdAT', 'oFFs', 'pCAL', 'sCAL', 'gIFg', 'gIFx', 'sTER', 'dSIG', 'iDOT', 'caBX', 'vpAg', 'orNT']);
  async function pngStructure(b) {
    if (!at(b, 0, PNG_SIG)) return null;
    const chunks = [], texts = [];
    let i = 8, end = null, ihdr = null, idat = 0, idatBytes = 0;
    while (i + 12 <= b.length) {
      const len = u32be(b, i);
      const type = latin1(b, i + 4, i + 8);
      if (!/^[A-Za-z]{4}$/.test(type) || i + 12 + len > b.length) { chunks.push({ type: type.replace(/[^\x20-\x7e]/g, '?'), offset: i, length: len, broken: true }); break; }
      const crcStored = u32be(b, i + 8 + len);
      const crcCalc = IKHash.crc32Raw(b, i + 4, i + 8 + len);
      const ch = { type, offset: i, length: len, crcOk: crcStored === crcCalc, crcStored, crcCalc, known: PNG_KNOWN.has(type) };
      const data = b.subarray(i + 8, i + 8 + len);
      if (type === 'IHDR' && len === 13) {
        ihdr = { width: u32be(data, 0), height: u32be(data, 4), bitDepth: data[8], colorType: data[9], interlace: data[12], offset: i };
      }
      if (type === 'IDAT') { idat++; idatBytes += len; }
      if (type === 'tEXt') { const z = data.indexOf(0); texts.push({ type, keyword: latin1(data, 0, z), text: latin1(data, z + 1) }); }
      if (type === 'zTXt') {
        const z = data.indexOf(0);
        let text = null;
        try { text = latin1(await inflate(data.subarray(z + 2), 'deflate')); } catch (e) { text = null; }
        texts.push({ type, keyword: latin1(data, 0, z), text, error: text == null });
      }
      if (type === 'iTXt') {
        const z = data.indexOf(0);
        const comp = data[z + 1];
        let p = z + 3;
        const z2 = data.indexOf(0, p); const lang = latin1(data, p, z2); p = z2 + 1;
        const z3 = data.indexOf(0, p); p = z3 + 1;
        let text = null;
        try { text = tdUtf8.decode(comp ? await inflate(data.subarray(p), 'deflate') : data.subarray(p)); } catch (e) { text = null; }
        texts.push({ type, keyword: latin1(data, 0, z), lang, text, error: text == null });
      }
      if (type === 'tIME' && len === 7) ch.time = `${u16be(data, 0)}-${String(data[2]).padStart(2, '0')}-${String(data[3]).padStart(2, '0')} ${String(data[4]).padStart(2, '0')}:${String(data[5]).padStart(2, '0')}:${String(data[6]).padStart(2, '0')}`;
      chunks.push(ch);
      i += 12 + len;
      if (type === 'IEND') { end = i; break; }
    }
    let ihdrFix = null;
    const ih = chunks.find(c => c.type === 'IHDR');
    if (ih && !ih.crcOk && ihdr) ihdrFix = fixIhdr(b, ih.offset, ih.crcStored, ihdr);
    return { chunks, texts, ihdr, idat, idatBytes, end, ihdrFix, unknown: chunks.filter(c => !c.known && !c.broken).map(c => c.type) };
  }
  // Prueba altos (y si no, anchos; y si no, ambos hasta 4096) hasta dar con el CRC guardado.
  function fixIhdr(b, off, crcStored, ihdr) {
    const buf = Uint8Array.from(b.subarray(off + 4, off + 4 + 17));
    const setW = (w) => { buf[4] = w >>> 24; buf[5] = (w >>> 16) & 255; buf[6] = (w >>> 8) & 255; buf[7] = w & 255; };
    const setH = (h) => { buf[8] = h >>> 24; buf[9] = (h >>> 16) & 255; buf[10] = (h >>> 8) & 255; buf[11] = h & 255; };
    const test = () => IKHash.crc32Raw(buf) === crcStored;
    setW(ihdr.width);
    for (let h = 1; h <= 16384; h++) { setH(h); if (test()) return { width: ihdr.width, height: h, changed: 'height' }; }
    setH(ihdr.height);
    for (let w = 1; w <= 16384; w++) { setW(w); if (test()) return { width: w, height: ihdr.height, changed: 'width' }; }
    for (let w = 1; w <= 4096; w++) { setW(w); for (let h = 1; h <= 4096; h++) { setH(h); if (test()) return { width: w, height: h, changed: 'both' }; } }
    return { notFound: true };
  }
  function patchIhdr(b, struct, width, height) {
    const out = Uint8Array.from(b);
    const off = struct.ihdr.offset;
    const dv = new DataView(out.buffer);
    dv.setUint32(off + 8, width); dv.setUint32(off + 12, height);
    dv.setUint32(off + 8 + 13, IKHash.crc32Raw(out, off + 4, off + 8 + 13));
    return out;
  }

  // GIF: recorre bloques hasta el terminador 0x3B.
  function gifStructure(b) {
    if (!(at(b, 0, str('GIF87a')) || at(b, 0, str('GIF89a')))) return null;
    const width = u16le(b, 6), height = u16le(b, 8), flags = b[10];
    let i = 13;
    if (flags & 0x80) i += 3 * (1 << ((flags & 7) + 1));
    let frames = 0;
    const comments = [];
    const skipSub = () => { const s = i; while (i < b.length && b[i] !== 0) i += b[i] + 1; i++; return [s, i - 1]; };
    while (i < b.length) {
      const t = b[i];
      if (t === 0x3B) return { width, height, frames, comments, end: i + 1 };
      if (t === 0x21) {
        const label = b[i + 1]; i += 2;
        const [s, e] = skipSub();
        if (label === 0xFE) { let c = '', k = s; while (k < e) { const n = b[k]; c += latin1(b, k + 1, k + 1 + n); k += n + 1; } comments.push(c); }
      } else if (t === 0x2C) {
        frames++;
        const f = b[i + 9]; i += 10;
        if (f & 0x80) i += 3 * (1 << ((f & 7) + 1));
        i++; skipSub();
      } else break;
    }
    return { width, height, frames, comments, end: null };
  }

  // ZIP: directorio central (nombres, tamaños, cifrado, fechas) y fin real tras el EOCD.
  function zipEntries(b) {
    let eocd = -1;
    for (let i = b.length - 22; i >= Math.max(0, b.length - 22 - 65535); i--) if (b[i] === 0x50 && b[i + 1] === 0x4B && b[i + 2] === 0x05 && b[i + 3] === 0x06) { eocd = i; break; }
    if (eocd < 0) return null;
    const count = u16le(b, eocd + 10), cdSize = u32le(b, eocd + 12), cdOff = u32le(b, eocd + 16), commentLen = u16le(b, eocd + 20);
    const comment = latin1(b, eocd + 22, eocd + 22 + commentLen);
    const entries = [];
    // Si hay datos delante (p. ej. JPEG+ZIP), los desplazamientos del directorio están corridos.
    const shift = eocd - cdSize - cdOff;
    let p = cdOff + Math.max(0, shift);
    for (let k = 0; k < count && p + 46 <= b.length; k++) {
      if (u32le(b, p) !== 0x02014b50) break;
      const flags = u16le(b, p + 8), method = u16le(b, p + 10), time = u16le(b, p + 12), date = u16le(b, p + 14);
      const csize = u32le(b, p + 20), usize = u32le(b, p + 24), nlen = u16le(b, p + 28), xlen = u16le(b, p + 30), clen = u16le(b, p + 32);
      const local = u32le(b, p + 42) + Math.max(0, shift);
      const nameBytes = b.subarray(p + 46, p + 46 + nlen);
      const name = flags & 0x800 ? tdUtf8.decode(nameBytes) : latin1(nameBytes);
      const extra = b.subarray(p + 46 + nlen, p + 46 + nlen + xlen);
      let aes = false;
      for (let q = 0; q + 4 <= extra.length;) { const id = u16le(extra, q), sz = u16le(extra, q + 2); if (id === 0x9901) aes = true; q += 4 + sz; }
      entries.push({
        name, method, csize, usize, encrypted: !!(flags & 1), aes, local, dir: name.endsWith('/'),
        modified: `${((date >> 9) & 127) + 1980}-${String((date >> 5) & 15).padStart(2, '0')}-${String(date & 31).padStart(2, '0')} ${String((time >> 11) & 31).padStart(2, '0')}:${String((time >> 5) & 63).padStart(2, '0')}`,
        comment: clen ? latin1(b, p + 46 + nlen + xlen, p + 46 + nlen + xlen + clen) : '',
      });
      p += 46 + nlen + xlen + clen;
    }
    return { entries, comment, end: eocd + 22 + commentLen, prefix: Math.max(0, shift), eocd };
  }
  async function zipRead(b, entry) {
    const p = entry.local;
    if (u32le(b, p) !== 0x04034b50 || entry.encrypted) return null;
    const nlen = u16le(b, p + 26), xlen = u16le(b, p + 28);
    const data = b.subarray(p + 30 + nlen + xlen, p + 30 + nlen + xlen + entry.csize);
    if (entry.method === 0) return data;
    if (entry.method === 8) return inflate(data, 'deflate-raw');
    return null;
  }

  // Metadatos de documentos Office (OOXML) y OpenDocument.
  async function officeMeta(b, zip) {
    const pick = (xml, tag) => { const m = xml.match(new RegExp('<' + tag + '(?:\\s[^>]*)?>([\\s\\S]*?)</' + tag + '>')); return m ? decodeXml(m[1].trim()) : null; };
    const out = [];
    const read = async (name) => { const e = zip.entries.find(x => x.name === name); if (!e) return null; const d = await zipRead(b, e); return d ? tdUtf8.decode(d) : null; };
    const core = await read('docProps/core.xml');
    if (core) for (const [tag, key] of [['dc:title', 'title'], ['dc:subject', 'subject'], ['dc:creator', 'author'], ['cp:lastModifiedBy', 'lastModifiedBy'], ['dcterms:created', 'created'], ['dcterms:modified', 'modified'], ['cp:lastPrinted', 'lastPrinted'], ['cp:revision', 'revision'], ['cp:keywords', 'keywords'], ['dc:description', 'description'], ['cp:category', 'category']]) { const v = pick(core, tag); if (v) out.push({ key, value: v }); }
    const app = await read('docProps/app.xml');
    if (app) for (const [tag, key] of [['Application', 'application'], ['AppVersion', 'appVersion'], ['Company', 'company'], ['Manager', 'manager'], ['Template', 'template'], ['TotalTime', 'totalTime'], ['Pages', 'pages'], ['Words', 'words']]) { const v = pick(app, tag); if (v) out.push({ key, value: v }); }
    const meta = await read('meta.xml');
    if (meta) for (const [tag, key] of [['dc:title', 'title'], ['meta:initial-creator', 'author'], ['dc:creator', 'lastModifiedBy'], ['meta:creation-date', 'created'], ['dc:date', 'modified'], ['meta:generator', 'application'], ['meta:editing-cycles', 'revision'], ['meta:editing-duration', 'totalTime']]) { const v = pick(meta, tag); if (v) out.push({ key, value: v }); }
    const macros = zip.entries.some(e => /vbaProject\.bin$/i.test(e.name) || /^Basic\//.test(e.name));
    const external = [];
    for (const e of zip.entries.filter(x => /_rels\/.*\.rels$/.test(x.name)).slice(0, 40)) {
      const d = await zipRead(b, e);
      if (!d) continue;
      const x = tdUtf8.decode(d);
      const re = /Target="([^"]+)"[^>]*TargetMode="External"|TargetMode="External"[^>]*Target="([^"]+)"/g;
      let m;
      while ((m = re.exec(x))) external.push(decodeXml(m[1] || m[2]));
    }
    return { fields: out, macros, external: Array.from(new Set(external)) };
  }
  function decodeXml(s) { return s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&#(\d+);/g, (m, n) => String.fromCodePoint(+n)).replace(/&#x([0-9a-f]+);/gi, (m, n) => String.fromCodePoint(parseInt(n, 16))).replace(/&amp;/g, '&'); }

  // PDF: diccionario /Info (también dentro de flujos de objetos comprimidos), XMP y palabras clave de riesgo (como pdfid).
  function pdfString(s) {
    if (s[0] === '<') {
      const hex = s.slice(1, -1).replace(/\s+/g, '');
      const bytes = (hex.match(/../g) || []).map(h => parseInt(h, 16));
      if (bytes[0] === 0xFE && bytes[1] === 0xFF) { let o = ''; for (let i = 2; i + 1 < bytes.length; i += 2) o += String.fromCharCode((bytes[i] << 8) | bytes[i + 1]); return o; }
      return String.fromCharCode(...bytes);
    }
    let body = s.slice(1, -1), out = '';
    for (let i = 0; i < body.length; i++) {
      const c = body[i];
      if (c !== '\\') { out += c; continue; }
      const n = body[++i];
      if (n === 'n') out += '\n'; else if (n === 'r') out += '\r'; else if (n === 't') out += '\t'; else if (n === 'b') out += '\b'; else if (n === 'f') out += '\f';
      else if (/[0-7]/.test(n)) { let o = n; while (o.length < 3 && /[0-7]/.test(body[i + 1])) o += body[++i]; out += String.fromCharCode(parseInt(o, 8)); }
      else if (n === '\r' || n === '\n') { if (n === '\r' && body[i + 1] === '\n') i++; }
      else out += n;
    }
    if (out.charCodeAt(0) === 0xFE && out.charCodeAt(1) === 0xFF) { let o = ''; for (let i = 2; i + 1 < out.length; i += 2) o += String.fromCharCode((out.charCodeAt(i) << 8) | out.charCodeAt(i + 1)); return o; }
    try { if (/[\xC2-\xF4][\x80-\xBF]/.test(out)) return new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(out, c => c.charCodeAt(0))); } catch (e) { /* latin-1 */ }
    return out;
  }
  function pdfDate(v) {
    const m = String(v).match(/D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?([Z+-])?(\d{2})?'?(\d{2})?/);
    if (!m) return v;
    const [, y, mo = '01', d = '01', h = '00', mi = '00', s = '00', z, zh, zm] = m;
    return `${y}-${mo}-${d} ${h}:${mi}:${s}${z === 'Z' ? ' UTC' : z ? ` ${z}${zh || '00'}:${zm || '00'}` : ''}`;
  }
  async function pdfMeta(b) {
    const text = latin1(b);
    const fields = [];
    const scan = (src) => {
      const re = /\/(Title|Author|Subject|Keywords|Creator|Producer|CreationDate|ModDate|Trapped)\s*(\((?:\\[\s\S]|[^\\)])*\)|<[0-9A-Fa-f\s]*>|\/[A-Za-z]+)/g;
      let m;
      while ((m = re.exec(src))) {
        let v = m[2][0] === '/' ? m[2].slice(1) : pdfString(m[2]);
        if (/Date$/.test(m[1])) v = pdfDate(v);
        if (!fields.some(f => f.key === m[1] && f.value === v)) fields.push({ key: m[1], value: v });
      }
    };
    scan(text);
    // Flujos de objetos (PDF 1.5+) y de metadatos: el /Info, las páginas, el JavaScript y el XMP pueden ir comprimidos.
    const streamRe = /<<((?:(?!stream)[\s\S]){0,800}?\/Type\s*\/(ObjStm|Metadata)(?:(?!stream)[\s\S]){0,800}?)>>\s*stream\r?\n/g;
    let m, n = 0, inner = '', xmpBytes = null;
    while ((m = streamRe.exec(text)) && n < 200) {
      n++;
      const len = +(m[1].match(/\/Length\s+(\d+)(?!\s+\d+\s+R)/) || [])[1];
      const start = m.index + m[0].length;
      const end = len ? start + len : text.indexOf('endstream', start);
      if (end <= start) continue;
      let data = b.subarray(start, end);
      if (/\/FlateDecode/.test(m[1])) { try { data = await inflate(data, 'deflate'); } catch (e) { continue; } }
      else if (/\/Filter/.test(m[1])) continue;
      if (m[2] === 'Metadata') { if (!xmpBytes) xmpBytes = data; continue; }
      const t = latin1(data);
      inner += '\n' + t;
      scan(t);
    }
    const all = text + inner;
    // El XMP va en UTF-8.
    let xmp = null;
    const xi = text.indexOf('<x:xmpmeta');
    if (xi >= 0 && !xmpBytes) { const xe = text.indexOf('</x:xmpmeta>', xi); if (xe > 0) xmpBytes = b.subarray(xi, xe + 12); }
    if (xmpBytes) xmp = (tdUtf8.decode(xmpBytes).match(/<x:xmpmeta[\s\S]*?<\/x:xmpmeta>/) || [])[0] || null;
    const xmpFields = [];
    if (xmp) {
      for (const [tag, key] of [['dc:creator', 'Author'], ['xmp:CreatorTool', 'Creator'], ['pdf:Producer', 'Producer'], ['xmp:CreateDate', 'CreationDate'], ['xmp:ModifyDate', 'ModDate'], ['xmpMM:DocumentID', 'DocumentID'], ['xmpMM:InstanceID', 'InstanceID'], ['dc:title', 'Title']]) {
        const mm = xmp.match(new RegExp('<' + tag + '[^>]*>([\\s\\S]*?)</' + tag + '>')) || xmp.match(new RegExp(tag + '="([^"]*)"'));
        if (mm) { const v = decodeXml(mm[1].replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim()); if (v) xmpFields.push({ key, value: v }); }
      }
    }
    // Recuento estilo pdfid (Didier Stevens): nombres que indican contenido activo.
    const KEYS = ['/JavaScript', '/JS', '/OpenAction', '/AA', '/Launch', '/EmbeddedFile', '/URI', '/SubmitForm', '/GoToR', '/RichMedia', '/XFA', '/AcroForm', '/Encrypt', '/ObjStm', '/JBIG2Decode'];
    const counts = {};
    for (const k of KEYS) { const re = new RegExp(k.replace('/', '\\/') + '(?![A-Za-z])', 'g'); const c = (all.match(re) || []).length; if (c) counts[k] = c; }
    const pages = (all.match(/\/Type\s*\/Page(?![A-Za-z])/g) || []).length;
    const version = (text.match(/^%PDF-(\d\.\d)/) || [])[1] || null;
    const eofs = []; let k = -1;
    while ((k = text.indexOf('%%EOF', k + 1)) >= 0) eofs.push(k);
    let end = null;
    if (eofs.length) { end = eofs[eofs.length - 1] + 5; while (end < b.length && (b[end] === 0x0A || b[end] === 0x0D || b[end] === 0x20 || b[end] === 0x00)) end++; }
    return { fields, xmpFields, counts, pages, version, updates: Math.max(0, eofs.length - 1), end };
  }

  // PE (Windows): cabecera COFF, fecha de compilación, secciones con su entropía.
  function peHeader(b) {
    if (!at(b, 0, str('MZ')) || b.length < 64) return null;
    const off = u32le(b, 0x3C);
    if (off + 24 > b.length || !at(b, off, [0x50, 0x45, 0, 0])) return null;
    const machine = u16le(b, off + 4), nsec = u16le(b, off + 6), ts = u32le(b, off + 8), optSize = u16le(b, off + 20), chars = u16le(b, off + 22);
    const magic = u16le(b, off + 24);
    const MACH = { 0x14c: 'x86', 0x8664: 'x64', 0x1c0: 'ARM', 0xaa64: 'ARM64', 0x200: 'IA-64', 0x1c4: 'ARMv7' };
    const subsystem = off + 24 + 68 + 2 <= b.length ? u16le(b, off + 24 + 68) : null;
    const SUB = { 1: 'Native', 2: 'GUI', 3: 'Consola', 9: 'Windows CE', 10: 'EFI' };
    const sections = [];
    let p = off + 24 + optSize;
    for (let i = 0; i < nsec && p + 40 <= b.length; i++, p += 40) {
      const name = latin1(b, p, p + 8).replace(/\0+$/, '');
      const rsize = u32le(b, p + 16), roff = u32le(b, p + 20), vsize = u32le(b, p + 8), ch = u32le(b, p + 36);
      sections.push({ name, vsize, rsize, roff, entropy: rsize && roff < b.length ? +entropy(b, roff, Math.min(b.length, roff + rsize)).toFixed(2) : 0, exec: !!(ch & 0x20000000), write: !!(ch & 0x80000000) });
    }
    const overlayStart = sections.reduce((m, s) => Math.max(m, s.roff + s.rsize), 0);
    return {
      machine: MACH[machine] || '0x' + machine.toString(16), pe32plus: magic === 0x20b, dll: !!(chars & 0x2000), timestamp: ts,
      compiled: ts ? new Date(ts * 1000).toISOString().replace('T', ' ').slice(0, 19) + ' UTC' : null,
      subsystem: SUB[subsystem] || subsystem, sections, overlay: overlayStart && overlayStart < b.length ? { offset: overlayStart, size: b.length - overlayStart } : null,
      packed: sections.some(s => /^(UPX\d|\.aspack|\.petite|\.nsp\d|MPRESS\d|\.themida)/i.test(s.name)),
    };
  }
  function elfHeader(b) {
    if (!at(b, 0, [0x7F, 0x45, 0x4C, 0x46]) || b.length < 20) return null;
    const cls = b[4] === 2 ? 64 : 32, le = b[5] === 1;
    const u16 = (o) => (le ? u16le(b, o) : u16be(b, o));
    const TYPE = { 1: 'REL (objeto)', 2: 'EXEC (ejecutable)', 3: 'DYN (biblioteca o PIE)', 4: 'CORE (volcado)' };
    const MACH = { 3: 'x86', 62: 'x86-64', 40: 'ARM', 183: 'AArch64', 8: 'MIPS', 20: 'PowerPC', 243: 'RISC-V' };
    const t = u16(16), m = u16(18);
    return { bits: cls, endian: le ? 'little' : 'big', type: TYPE[t] || t, machine: MACH[m] || m, osabi: b[7] };
  }

  // ───────────────────────── Archivos incrustados y datos añadidos ─────────────────────────
  // Firmas «fuertes» indexadas por su primer byte (recorrer todas en cada byte sería lento en archivos grandes).
  const EMB = (() => {
    const list = SIGS.filter(s => s[5] && s[0] === 0).map(s => [s[1], s[2]])
      .concat([[[0x1F, 0x8B, 0x08, null, null, null, null, null, 0x00], 'gzip'], [str('BZh91AY&SY'), 'bzip2'], [str('MZ'), 'pe']]);
    const by = new Array(256).fill(null);
    for (const [sig, id] of list) (by[sig[0]] = by[sig[0]] || []).push([sig, id]);
    return by;
  })();
  function embedded(b, max) {
    const hits = [];
    const zipStarts = at(b, 0, [0x50, 0x4B, 0x03, 0x04]) ? [0] : [];
    for (let i = 1; i < b.length && hits.length < (max || 200); i++) {
      const cands = EMB[b[i]];
      if (!cands) continue;
      for (const [sig, id] of cands) {
        if (!at(b, i, sig)) continue;
        if (id === 'pe' && !peHeader(b.subarray(i))) continue;
        // Una entrada más de un ZIP ya visto no es un archivo nuevo.
        if (id === 'zip') { if (zipStarts.some(z => isZipEntryChain(b, z, i))) break; zipStarts.push(i); }
        hits.push({ offset: i, type: id });
        break;
      }
    }
    return hits;
  }
  function isZipEntryChain(b, first, off) {
    // Recorre cabeceras locales desde «first»; si llega a «off», es una entrada más del mismo ZIP.
    let p = first;
    for (let k = 0; k < 100000 && p < off; k++) {
      if (u32le(b, p) !== 0x04034b50) return false;
      const flags = u16le(b, p + 6), csize = u32le(b, p + 18), nlen = u16le(b, p + 26), xlen = u16le(b, p + 28);
      p += 30 + nlen + xlen + csize;
      if (flags & 8) { const dd = u32le(b, p) === 0x08074b50 ? 16 : 12; p += dd; }
    }
    return p === off;
  }

  function trailer(b, end) {
    if (end == null || end >= b.length) return null;
    const extra = b.subarray(end);
    if (extra.every(x => x === 0)) return { offset: end, size: extra.length, zeros: true };
    if (extra.length <= 2 && extra.every(x => x === 0x0A || x === 0x0D)) return null;
    return { offset: end, size: extra.length, type: detect(extra).type, entropy: +entropy(extra).toFixed(2), preview: latin1(extra, 0, 64).replace(/[^\x20-\x7e]/g, '.') };
  }

  // ───────────────────────── Borrar metadatos (sin recomprimir) ─────────────────────────
  // JPEG: fuera APP1 (EXIF/XMP), APP13 (IPTC), COM y otros APPn; se conservan JFIF (APP0), ICC (APP2) y Adobe (APP14),
  // que afectan al color. PNG: fuera tEXt/zTXt/iTXt/eXIf/tIME y trozos privados. En ambos se quita lo que va tras el final.
  function stripJpeg(b) {
    const s = jpegStructure(b);
    if (!s || !s.eoiFound) return null;
    const parts = [b.subarray(0, 2)];
    let removed = 0;
    const sos = s.segments.find(x => x.marker === 'SOS');
    for (const seg of s.segments) {
      if (seg.offset >= sos.offset) break;
      const keep = !((seg.code >= 0xE1 && seg.code <= 0xEF && !(seg.code === 0xE2 && seg.app === 'Perfil ICC') && seg.code !== 0xEE) || seg.code === 0xFE);
      if (keep) parts.push(b.subarray(seg.offset, seg.offset + seg.length)); else removed++;
    }
    parts.push(b.subarray(sos.offset, s.end));
    return { bytes: concat(parts), removed, trailing: b.length - s.end };
  }
  async function stripPng(b) {
    const s = await pngStructure(b);
    if (!s || s.end == null) return null;
    const DROP = new Set(['tEXt', 'zTXt', 'iTXt', 'eXIf', 'tIME', 'dSIG', 'caBX']);
    const parts = [b.subarray(0, 8)];
    let removed = 0;
    for (const c of s.chunks) {
      const isPrivate = c.type[1] === c.type[1].toLowerCase() && !PNG_KNOWN.has(c.type);
      if (DROP.has(c.type) || isPrivate) { removed++; continue; }
      parts.push(b.subarray(c.offset, c.offset + 12 + c.length));
    }
    return { bytes: concat(parts), removed, trailing: b.length - s.end };
  }
  function concat(parts) {
    const n = parts.reduce((a, p) => a + p.length, 0);
    const out = new Uint8Array(n);
    let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
  }

  // ───────────────────────── Volcado hexadecimal ─────────────────────────
  function hexdump(b, start, len) {
    start = Math.max(0, start || 0) & ~15;
    const end = Math.min(b.length, start + (len || 512));
    const lines = [];
    for (let o = start; o < end; o += 16) {
      let hex = '', asc = '';
      for (let i = 0; i < 16; i++) {
        if (o + i < end) { const x = b[o + i]; hex += x.toString(16).padStart(2, '0') + (i === 7 ? '  ' : ' '); asc += x >= 32 && x < 127 ? String.fromCharCode(x) : '.'; }
        else { hex += i === 7 ? '    ' : '   '; }
      }
      lines.push(o.toString(16).padStart(8, '0') + '  ' + hex + ' |' + asc + '|');
    }
    return lines.join('\n');
  }

  // ───────────────────────── Análisis completo ─────────────────────────
  async function analyze(b, name) {
    const det = detect(b, name);
    const res = { size: b.length, detect: det, entropy: +entropy(b).toFixed(3) };
    let end = null;
    try {
      if (det.type === 'jpeg') { res.jpeg = jpegStructure(b); end = res.jpeg && res.jpeg.end; }
      else if (det.type === 'png') { res.png = await pngStructure(b); end = res.png && res.png.end; }
      else if (det.type === 'gif') { res.gif = gifStructure(b); end = res.gif && res.gif.end; }
      else if (det.type === 'pdf') { res.pdf = await pdfMeta(b); end = res.pdf.end; }
      else if (det.type === 'pe' || det.type === 'dll') { res.pe = peHeader(b); }
      else if (det.type === 'elf') { res.elf = elfHeader(b); }
      else if (det.type === 'bmp') { const sz = u32le(b, 2); if (sz > 54 && sz <= b.length) end = sz; res.bmp = { width: u32le(b, 18), height: Math.abs(u32le(b, 22) | 0), bpp: u16le(b, 28), declaredSize: sz }; }
      const z = (det.type === 'zip' || ['docx', 'xlsx', 'pptx', 'apk', 'jar', 'epub', 'odf'].includes(det.type)) ? zipEntries(b) : null;
      if (z) {
        res.zip = { entries: z.entries.slice(0, 2000), total: z.entries.length, comment: z.comment, encrypted: z.entries.some(e => e.encrypted), aes: z.entries.some(e => e.aes) };
        end = z.end;
        if (['docx', 'xlsx', 'pptx', 'odf'].includes(det.type)) res.office = await officeMeta(b, z);
      }
    } catch (e) { res.structureError = String(e && e.message || e); }
    // Un ZIP pegado al final de otro archivo (JPEG+ZIP, GIFAR…): el EOCD está al final.
    if (!res.zip && det.type !== 'zip') {
      const z = zipEntries(b);
      if (z && z.prefix > 0 && z.entries.length) res.zipAppended = { offset: z.prefix, entries: z.entries.slice(0, 500), total: z.entries.length, encrypted: z.entries.some(e => e.encrypted) };
    }
    res.trailer = trailer(b, end);
    if (res.pe && res.pe.overlay) res.trailer = { offset: res.pe.overlay.offset, size: res.pe.overlay.size, overlay: true, type: detect(b.subarray(res.pe.overlay.offset)).type, entropy: +entropy(b, res.pe.overlay.offset).toFixed(2), preview: latin1(b, res.pe.overlay.offset, res.pe.overlay.offset + 64).replace(/[^\x20-\x7e]/g, '.') };
    res.embedded = embedded(b, 200);
    // En un JPEG, una imagen dentro de APP1 es la miniatura EXIF, no un archivo escondido.
    if (res.jpeg) for (const h of res.embedded) {
      const seg = res.jpeg.segments.find(s => s.app && h.offset > s.offset && h.offset < s.offset + s.length);
      if (seg) h.inside = seg.app === 'EXIF' ? 'thumbnail' : seg.app;
    }
    if (res.zip || res.zipAppended) for (const h of res.embedded) h.inZip = h.type !== 'zip';
    return res;
  }

  return { detect, entropy, entropyBlocks, strings, search, searchBytes, iocs, jpegStructure, pngStructure, patchIhdr, gifStructure, zipEntries, zipRead, officeMeta, pdfMeta, peHeader, elfHeader, embedded, trailer, stripJpeg, stripPng, hexdump, analyze, inflate, latin1 };
});
