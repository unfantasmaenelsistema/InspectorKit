/* InspectorKit · decodificador PNG propio, exacto bit a bit.
   El <canvas> del navegador puede aplicar gamma, perfil ICC o alfa premultiplicado y cambiar los bits bajos,
   que es justo donde va la esteganografía LSB. Aquí se leen los valores tal como están en el archivo.
   Admite todos los tipos de color, profundidades 1/2/4/8/16 y entrelazado Adam7. Sin DOM. */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.IKPng = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const u32 = (b, o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;

  async function inflate(bytes) {
    const ds = new DecompressionStream('deflate');
    const stream = new Blob([bytes]).stream().pipeThrough(ds);
    return new Uint8Array(await new Response(stream).arrayBuffer());
  }

  function paeth(a, b, c) { const p = a + b - c, pa = Math.abs(p - a), pb = Math.abs(p - b), pc = Math.abs(p - c); return pa <= pb && pa <= pc ? a : pb <= pc ? b : c; }

  // Deshace los filtros de una imagen (o de una pasada de Adam7) de w×h píxeles.
  function unfilter(data, off, w, h, bpp, bitsPerPixel) {
    const stride = Math.ceil((w * bitsPerPixel) / 8);
    const out = new Uint8Array(stride * h);
    let prev = new Uint8Array(stride);
    let p = off;
    for (let y = 0; y < h; y++) {
      const ft = data[p++];
      const line = out.subarray(y * stride, (y + 1) * stride);
      for (let x = 0; x < stride; x++) {
        const raw = data[p++];
        const a = x >= bpp ? line[x - bpp] : 0, b = prev[x], c = x >= bpp ? prev[x - bpp] : 0;
        let v;
        switch (ft) {
          case 0: v = raw; break;
          case 1: v = raw + a; break;
          case 2: v = raw + b; break;
          case 3: v = raw + ((a + b) >> 1); break;
          case 4: v = raw + paeth(a, b, c); break;
          default: throw new Error('filtro PNG desconocido: ' + ft);
        }
        line[x] = v & 255;
      }
      prev = line;
    }
    return { out, stride, next: p };
  }

  // Muestras (valores de canal) de una fila ya sin filtro.
  function readSamples(line, w, channels, depth) {
    const n = w * channels;
    const s = new Uint16Array(n);
    if (depth === 8) for (let i = 0; i < n; i++) s[i] = line[i];
    else if (depth === 16) for (let i = 0; i < n; i++) s[i] = (line[i * 2] << 8) | line[i * 2 + 1];
    else { const per = 8 / depth, mask = (1 << depth) - 1; for (let i = 0; i < n; i++) s[i] = (line[Math.floor(i / per)] >> (8 - depth * (1 + (i % per)))) & mask; }
    return s;
  }

  async function decode(b) {
    if (!(b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4E && b[3] === 0x47)) throw new Error('no es PNG');
    let i = 8, ihdr = null, plte = null, trns = null;
    const idat = [];
    while (i + 8 <= b.length) {
      const len = u32(b, i), type = String.fromCharCode(b[i + 4], b[i + 5], b[i + 6], b[i + 7]);
      const d = b.subarray(i + 8, i + 8 + len);
      if (type === 'IHDR') ihdr = { w: u32(d, 0), h: u32(d, 4), depth: d[8], color: d[9], interlace: d[12] };
      else if (type === 'PLTE') plte = d;
      else if (type === 'tRNS') trns = d;
      else if (type === 'IDAT') idat.push(d);
      else if (type === 'IEND') break;
      i += 12 + len;
    }
    if (!ihdr || !idat.length) throw new Error('PNG incompleto');
    const { w, h, depth, color, interlace } = ihdr;
    if (w * h > 50e6) throw new Error('imagen demasiado grande');
    const channels = { 0: 1, 2: 3, 3: 1, 4: 2, 6: 4 }[color];
    if (!channels) throw new Error('tipo de color PNG no válido');
    const total = idat.reduce((a, x) => a + x.length, 0);
    const z = new Uint8Array(total);
    let o = 0;
    for (const x of idat) { z.set(x, o); o += x.length; }
    const data = await inflate(z);
    const bitsPerPixel = channels * depth;
    const bpp = Math.max(1, bitsPerPixel >> 3);
    const rgba = new Uint8ClampedArray(w * h * 4);
    const raw = depth === 16 ? new Uint16Array(w * h * channels) : null; // valores de 16 bits sin reducir
    const max = (1 << depth) - 1;
    const to8 = (v) => (depth === 16 ? v >> 8 : depth === 8 ? v : Math.round((v * 255) / max));
    const trnsGray = trns && color === 0 ? (trns[0] << 8) | trns[1] : null;
    const trnsRGB = trns && color === 2 ? [(trns[0] << 8) | trns[1], (trns[2] << 8) | trns[3], (trns[4] << 8) | trns[5]] : null;
    const put = (x, y, s, k) => {
      const p = (y * w + x) * 4;
      if (raw) for (let c = 0; c < channels; c++) raw[(y * w + x) * channels + c] = s[k + c];
      if (color === 0) { const v = to8(s[k]); rgba[p] = rgba[p + 1] = rgba[p + 2] = v; rgba[p + 3] = trnsGray != null && s[k] === trnsGray ? 0 : 255; }
      else if (color === 2) { rgba[p] = to8(s[k]); rgba[p + 1] = to8(s[k + 1]); rgba[p + 2] = to8(s[k + 2]); rgba[p + 3] = trnsRGB && s[k] === trnsRGB[0] && s[k + 1] === trnsRGB[1] && s[k + 2] === trnsRGB[2] ? 0 : 255; }
      else if (color === 3) { const idx = s[k]; rgba[p] = plte ? plte[idx * 3] : 0; rgba[p + 1] = plte ? plte[idx * 3 + 1] : 0; rgba[p + 2] = plte ? plte[idx * 3 + 2] : 0; rgba[p + 3] = trns && idx < trns.length ? trns[idx] : 255; }
      else if (color === 4) { const v = to8(s[k]); rgba[p] = rgba[p + 1] = rgba[p + 2] = v; rgba[p + 3] = to8(s[k + 1]); }
      else { rgba[p] = to8(s[k]); rgba[p + 1] = to8(s[k + 1]); rgba[p + 2] = to8(s[k + 2]); rgba[p + 3] = to8(s[k + 3]); }
    };
    // Índices de paleta (para el análisis LSB de imágenes con paleta).
    const indices = color === 3 ? new Uint8Array(w * h) : null;
    const handle = (x, y, s, k) => { put(x, y, s, k); if (indices) indices[y * w + x] = s[k]; };
    if (!interlace) {
      const { out, stride } = unfilter(data, 0, w, h, bpp, bitsPerPixel);
      for (let y = 0; y < h; y++) { const s = readSamples(out.subarray(y * stride, (y + 1) * stride), w, channels, depth); for (let x = 0; x < w; x++) handle(x, y, s, x * channels); }
    } else {
      const P = [[0, 0, 8, 8], [4, 0, 8, 8], [0, 4, 4, 8], [2, 0, 4, 4], [0, 2, 2, 4], [1, 0, 2, 2], [0, 1, 1, 2]];
      let off = 0;
      for (const [x0, y0, dx, dy] of P) {
        const pw = Math.ceil((w - x0) / dx), ph = Math.ceil((h - y0) / dy);
        if (pw <= 0 || ph <= 0) continue;
        const { out, stride, next } = unfilter(data, off, pw, ph, bpp, bitsPerPixel);
        off = next;
        for (let y = 0; y < ph; y++) { const s = readSamples(out.subarray(y * stride, (y + 1) * stride), pw, channels, depth); for (let x = 0; x < pw; x++) handle(x0 + x * dx, y0 + y * dy, s, x * channels); }
      }
    }
    return { width: w, height: h, data: rgba, depth, color, interlace: !!interlace, channels, indices, raw16: raw };
  }

  return { decode };
});
