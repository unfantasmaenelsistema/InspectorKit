/* InspectorKit · motor de hashes. Sin DOM: funciona igual en el navegador y en Node.
   MD5, MD4 (NTLM) y CRC32 propios; SHA-1/256/384/512 con Web Crypto (crypto.subtle). */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.IKHash = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const enc = new TextEncoder();
  const toHex = (u8) => Array.from(u8, b => b.toString(16).padStart(2, '0')).join('');

  // Relleno común a MD4/MD5 (little-endian, longitud en bits en los 8 últimos bytes).
  function padLE(bytes) {
    const len = bytes.length;
    const total = (((len + 8) >>> 6) + 1) << 6;
    const out = new Uint8Array(total);
    out.set(bytes);
    out[len] = 0x80;
    const bits = len * 8;
    const dv = new DataView(out.buffer);
    dv.setUint32(total - 8, bits >>> 0, true);
    dv.setUint32(total - 4, Math.floor(len / 0x20000000), true);
    return dv;
  }
  const rotl = (x, n) => (x << n) | (x >>> (32 - n));

  // ───────────── MD5 (RFC 1321) ─────────────
  const MD5_S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
  const MD5_K = new Int32Array(64);
  for (let i = 0; i < 64; i++) MD5_K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000) | 0;

  function md5(bytes) {
    const dv = padLE(bytes);
    let a0 = 0x67452301, b0 = 0xefcdab89 | 0, c0 = 0x98badcfe | 0, d0 = 0x10325476;
    const M = new Int32Array(16);
    for (let off = 0; off < dv.byteLength; off += 64) {
      for (let i = 0; i < 16; i++) M[i] = dv.getInt32(off + i * 4, true);
      let A = a0, B = b0, C = c0, D = d0;
      for (let i = 0; i < 64; i++) {
        let F, g;
        if (i < 16) { F = (B & C) | (~B & D); g = i; }
        else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) & 15; }
        else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) & 15; }
        else { F = C ^ (B | ~D); g = (7 * i) & 15; }
        const tmp = D; D = C; C = B;
        B = (B + rotl((A + F + MD5_K[i] + M[g]) | 0, MD5_S[i])) | 0;
        A = tmp;
      }
      a0 = (a0 + A) | 0; b0 = (b0 + B) | 0; c0 = (c0 + C) | 0; d0 = (d0 + D) | 0;
    }
    const out = new DataView(new ArrayBuffer(16));
    [a0, b0, c0, d0].forEach((v, i) => out.setInt32(i * 4, v, true));
    return toHex(new Uint8Array(out.buffer));
  }

  // ───────────── MD4 (RFC 1320) · base de NTLM ─────────────
  function md4(bytes) {
    const dv = padLE(bytes);
    let a0 = 0x67452301, b0 = 0xefcdab89 | 0, c0 = 0x98badcfe | 0, d0 = 0x10325476;
    const X = new Int32Array(16);
    const F = (x, y, z) => (x & y) | (~x & z);
    const G = (x, y, z) => (x & y) | (x & z) | (y & z);
    const H = (x, y, z) => x ^ y ^ z;
    for (let off = 0; off < dv.byteLength; off += 64) {
      for (let i = 0; i < 16; i++) X[i] = dv.getInt32(off + i * 4, true);
      let a = a0, b = b0, c = c0, d = d0;
      const r1 = [3, 7, 11, 19], r2 = [3, 5, 9, 13], r3 = [3, 9, 11, 15];
      for (let i = 0; i < 16; i++) {
        const t = (a + F(b, c, d) + X[i]) | 0;
        a = d; d = c; c = b; b = rotl(t, r1[i & 3]);
      }
      const o2 = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15];
      for (let i = 0; i < 16; i++) {
        const t = (a + G(b, c, d) + X[o2[i]] + 0x5a827999) | 0;
        a = d; d = c; c = b; b = rotl(t, r2[i & 3]);
      }
      const o3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15];
      for (let i = 0; i < 16; i++) {
        const t = (a + H(b, c, d) + X[o3[i]] + 0x6ed9eba1) | 0;
        a = d; d = c; c = b; b = rotl(t, r3[i & 3]);
      }
      a0 = (a0 + a) | 0; b0 = (b0 + b) | 0; c0 = (c0 + c) | 0; d0 = (d0 + d) | 0;
    }
    const out = new DataView(new ArrayBuffer(16));
    [a0, b0, c0, d0].forEach((v, i) => out.setInt32(i * 4, v, true));
    return toHex(new Uint8Array(out.buffer));
  }

  // NTLM = MD4 de la contraseña en UTF-16LE.
  function ntlm(text) {
    const u = new Uint8Array(text.length * 2);
    for (let i = 0; i < text.length; i++) { const c = text.charCodeAt(i); u[i * 2] = c & 255; u[i * 2 + 1] = c >>> 8; }
    return md4(u);
  }

  // ───────────── CRC32 (IEEE, el de ZIP/PNG) ─────────────
  const CRC_T = new Uint32Array(256);
  for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; CRC_T[n] = c >>> 0; }
  function crc32Raw(bytes, start, end) {
    let c = 0xffffffff;
    for (let i = start || 0, e = end == null ? bytes.length : end; i < e; i++) c = CRC_T[(c ^ bytes[i]) & 255] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
  }
  const crc32 = (bytes) => crc32Raw(bytes).toString(16).padStart(8, '0');

  // ───────────── SHA con Web Crypto ─────────────
  function subtle() {
    const c = (typeof crypto !== 'undefined' && crypto.subtle) ? crypto : null;
    if (!c) throw new Error('webcrypto');
    return c.subtle;
  }
  async function sha(alg, bytes) { return toHex(new Uint8Array(await subtle().digest(alg, bytes))); }

  const ALGS = ['MD5', 'SHA-1', 'SHA-256', 'SHA-384', 'SHA-512', 'CRC32'];

  // Calcula todos los hashes de unos bytes (o de un texto en UTF-8).
  async function all(input) {
    const bytes = typeof input === 'string' ? enc.encode(input) : input;
    const out = {
      'MD5': md5(bytes),
      'SHA-1': await sha('SHA-1', bytes),
      'SHA-256': await sha('SHA-256', bytes),
      'SHA-384': await sha('SHA-384', bytes),
      'SHA-512': await sha('SHA-512', bytes),
      'CRC32': crc32(bytes),
    };
    if (typeof input === 'string') out.NTLM = ntlm(input);
    return out;
  }

  // Compara un hash esperado con los calculados (sin distinguir mayúsculas ni espacios).
  function verify(expected, hashes) {
    const e = String(expected || '').trim().toLowerCase().replace(/\s+/g, '');
    if (!e) return null;
    for (const [alg, h] of Object.entries(hashes)) if (h === e) return alg;
    return false;
  }

  // ───────────── Identificador ─────────────
  // Cada regla: prueba, nombre, modo de hashcat, formato de John the Ripper y nota opcional (clave i18n).
  const RULES = [
    [/^\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}$/, 'bcrypt', 3200, 'bcrypt', 'slow'],
    [/^\$argon2(id|i|d)\$/, 'Argon2', 34000, 'argon2', 'slow'],
    [/^\$y\$[./A-Za-z0-9]+\$/, 'yescrypt (Linux /etc/shadow)', null, 'crypt', 'shadow'],
    [/^\$gy\$/, 'gost-yescrypt (Linux)', null, 'crypt', 'shadow'],
    [/^\$6\$(rounds=\d+\$)?[^$]{1,16}\$[./A-Za-z0-9]{86}$/, 'sha512crypt (Linux /etc/shadow)', 1800, 'sha512crypt', 'shadow'],
    [/^\$5\$(rounds=\d+\$)?[^$]{1,16}\$[./A-Za-z0-9]{43}$/, 'sha256crypt', 7400, 'sha256crypt', 'shadow'],
    [/^\$1\$[^$]{1,8}\$[./A-Za-z0-9]{22}$/, 'md5crypt (Linux/Cisco)', 500, 'md5crypt', null],
    [/^\$apr1\$[^$]{1,8}\$[./A-Za-z0-9]{22}$/, 'Apache apr1 (htpasswd)', 1600, 'md5crypt', null],
    [/^\$[PH]\$[./A-Za-z0-9]{31}$/, 'phpass (WordPress, phpBB)', 400, 'phpass', null],
    [/^\$wp\$2y\$/, 'WordPress 6.8+ (bcrypt sobre HMAC-SHA384)', null, null, 'slow'],
    [/^pbkdf2_sha256\$\d+\$[^$]+\$[A-Za-z0-9+/=]{44}$/, 'Django PBKDF2-SHA256', 10000, 'django', 'slow'],
    [/^sha1\$[^$]+\$[a-f0-9]{40}$/i, 'Django SHA-1 (antiguo)', 124, null, null],
    [/^\{SSHA\}[A-Za-z0-9+/=]{28,}$/, 'LDAP SSHA (SHA-1 con sal)', 111, 'salted-sha1', null],
    [/^\{SHA\}[A-Za-z0-9+/=]{28}$/, 'LDAP SHA (SHA-1, Base64)', 101, 'nsldap', null],
    [/^\{SSHA512\}[A-Za-z0-9+/=]{88,}$/, 'LDAP SSHA-512', 1711, 'ssha512', null],
    [/^\*[A-F0-9]{40}$/i, 'MySQL 4.1+ (SHA1(SHA1(x)))', 300, 'mysql-sha1', null],
    [/^\$krb5tgs\$23\$/, 'Kerberos 5 TGS-REP RC4 (Kerberoasting)', 13100, 'krb5tgs', 'ad'],
    [/^\$krb5tgs\$(17|18)\$/, 'Kerberos 5 TGS-REP AES (Kerberoasting)', null, 'krb5tgs', 'ad'],
    [/^\$krb5asrep\$23\$/, 'Kerberos 5 AS-REP RC4 (AS-REP roasting)', 18200, 'krb5asrep', 'ad'],
    [/^[^:\s]+::[^:]*:[a-f0-9]{16}:[a-f0-9]{32}:[a-f0-9]+$/i, 'NetNTLMv2 (Responder)', 5600, 'netntlmv2', 'ad'],
    [/^[^:\s]+::[^:]*:[a-f0-9]{48}:[a-f0-9]{48}:[a-f0-9]{16}$/i, 'NetNTLMv1', 5500, 'netntlm', 'ad'],
    [/^[^:\s]+:\d+:[a-f0-9]{32}:[a-f0-9]{32}:::$/i, 'Volcado SAM/pwdump (usuario:RID:LM:NT)', 1000, 'nt', 'pwdump'],
    [/^\$DCC2\$\d+#[^#]+#[a-f0-9]{32}$/i, 'Domain Cached Credentials 2 (mscash2)', 2100, 'mscash2', 'ad'],
    [/^0x0100[a-f0-9]{48}$/i, 'MSSQL 2005', 132, 'mssql05', null],
    [/^0x0200[a-f0-9]{136}$/i, 'MSSQL 2012+', 1731, 'mssql12', null],
    [/^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/, 'JWT (no es un hash: es un token firmado)', 16500, null, 'jwt'],
  ];
  // Hexadecimal puro por longitud.
  const HEX_LEN = {
    8: [['CRC32', 11500, 'crc32'], ['Adler-32', null, null]],
    16: [['MySQL 3.x (OLD_PASSWORD)', 200, 'mysql'], ['Mitad de un hash LM', 3000, 'lm']],
    32: [['MD5', 0, 'raw-md5'], ['NTLM', 1000, 'nt'], ['MD4', 900, 'raw-md4'], ['LM (dos mitades)', 3000, 'lm']],
    40: [['SHA-1', 100, 'raw-sha1'], ['RIPEMD-160', 6000, 'ripemd-160'], ['MySQL 4.1+ sin asterisco', 300, 'mysql-sha1']],
    56: [['SHA-224', 1300, 'raw-sha224'], ['SHA3-224', 17300, null]],
    64: [['SHA-256', 1400, 'raw-sha256'], ['SHA3-256', 17400, 'raw-sha3'], ['Keccak-256', 17800, null], ['BLAKE2s-256', null, null]],
    96: [['SHA-384', 10800, 'raw-sha384'], ['SHA3-384', 17500, null]],
    128: [['SHA-512', 1700, 'raw-sha512'], ['SHA3-512', 17600, null], ['Whirlpool', 6100, 'whirlpool'], ['BLAKE2b-512', 600, 'raw-blake2']],
  };
  // Longitud de un digest en Base64 → algoritmo probable.
  const B64_LEN = { 24: 'MD5', 28: 'SHA-1', 44: 'SHA-256', 64: 'SHA-384', 88: 'SHA-512' };

  function identify(line) {
    const s = String(line || '').trim();
    if (!s) return null;
    const res = { input: s, matches: [], notes: [] };
    for (const [re, name, mode, john, note] of RULES) {
      if (re.test(s)) { res.matches.push({ name, mode, john }); if (note) res.notes.push(note); }
    }
    if (!res.matches.length) {
      const hex = s.replace(/^0x/i, '');
      if (/^[a-f0-9]+$/i.test(hex) && HEX_LEN[hex.length]) {
        for (const [name, mode, john] of HEX_LEN[hex.length]) res.matches.push({ name, mode, john });
        if (hex.length === 32 && hex.toLowerCase() === 'aad3b435b51404eeaad3b435b51404ee') res.notes.push('lmEmpty');
        if (hex.length === 32 && hex.toLowerCase() === '31d6cfe0d16ae931b73c59d7e0c089c0') res.notes.push('ntEmpty');
        if (hex.length === 32 && hex.toLowerCase() === 'd41d8cd98f00b204e9800998ecf8427e') res.notes.push('md5Empty');
        if (hex.length === 40 && hex.toLowerCase() === 'da39a3ee5e6b4b0d3255bfef95601890afd80709') res.notes.push('sha1Empty');
        if (hex.length === 64 && hex.toLowerCase() === 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855') res.notes.push('sha256Empty');
      } else if (/^[A-Za-z0-9+/]+={0,2}$/.test(s) && B64_LEN[s.length]) {
        res.matches.push({ name: B64_LEN[s.length] + ' (Base64)', mode: null, john: null });
        res.notes.push('b64digest');
      } else if (/^[a-f0-9]+$/i.test(hex)) {
        res.notes.push('hexUnknown');
      }
    }
    if (!res.matches.length && !res.notes.length) res.notes.push('unknown');
    return res;
  }

  return { md5, md4, ntlm, crc32, crc32Raw, sha, all, verify, identify, toHex, ALGS };
});
