/* InspectorKit · esteganografía en imágenes sin pérdida (PNG, BMP, GIF, WebP sin pérdida).
   Trabaja sobre los píxeles RGBA (Uint8ClampedArray de un canvas, o cualquier array en Node).
   Planos de bits, extracción LSB al estilo de zsteg y ataque chi-cuadrado de Westfeld y Pfitzmann. */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.IKStego = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const CH = { r: 0, g: 1, b: 2, a: 3 };

  // Imagen en blanco y negro con el bit «bit» del canal «ch» (blanco = 1).
  function bitPlane(px, w, h, ch, bit) {
    const out = new Uint8ClampedArray(w * h * 4);
    const c = CH[ch], m = 1 << bit;
    let ones = 0;
    for (let i = 0, j = 0; i < w * h; i++, j += 4) {
      const v = px[j + c] & m ? 255 : 0;
      if (v) ones++;
      out[j] = out[j + 1] = out[j + 2] = v; out[j + 3] = 255;
    }
    return { data: out, ones: ones / (w * h) };
  }

  // Extrae bits. channels: 'rgb', 'bgr', 'r', 'rgba'…; bits: [0] o [1, 0]…; order 'row' (filas) o 'col' (columnas);
  // msbFirst: el primer bit leído es el más significativo del byte (lo habitual).
  function extract(px, w, h, opts) {
    const chans = Array.from(opts.channels || 'rgb').map(c => CH[c]);
    const bits = opts.bits || [0];
    const msbFirst = opts.msbFirst !== false;
    const maxBytes = opts.maxBytes || Math.ceil((w * h * chans.length * bits.length) / 8);
    const out = new Uint8Array(Math.min(maxBytes, Math.ceil((w * h * chans.length * bits.length) / 8)));
    let byte = 0, n = 0, k = 0;
    const total = w * h;
    for (let idx = 0; idx < total && k < out.length; idx++) {
      const p = opts.order === 'col' ? ((idx % h) * w + Math.floor(idx / h)) : idx;
      const base = p * 4;
      for (const c of chans) {
        const v = px[base + c];
        for (const bit of bits) {
          const b = (v >> bit) & 1;
          byte = msbFirst ? (byte << 1) | b : byte | (b << n);
          if (++n === 8) { out[k++] = byte & 255; byte = 0; n = 0; if (k >= out.length) break; }
        }
        if (k >= out.length) break;
      }
    }
    return out;
  }

  // Inserta datos (solo para pruebas y demostraciones en clase).
  function embed(px, w, h, data, opts) {
    const out = Uint8ClampedArray.from(px);
    const chans = Array.from(opts.channels || 'rgb').map(c => CH[c]);
    const bits = opts.bits || [0];
    const msbFirst = opts.msbFirst !== false;
    let k = 0, n = 0;
    const total = w * h;
    for (let idx = 0; idx < total && k < data.length; idx++) {
      const p = opts.order === 'col' ? ((idx % h) * w + Math.floor(idx / h)) : idx;
      for (const c of chans) {
        for (const bit of bits) {
          if (k >= data.length) break;
          const b = msbFirst ? (data[k] >> (7 - n)) & 1 : (data[k] >> n) & 1;
          out[p * 4 + c] = (out[p * 4 + c] & ~(1 << bit)) | (b << bit);
          if (++n === 8) { n = 0; k++; }
        }
      }
    }
    return out;
  }

  const MAGIC = [[[0x50, 0x4B, 0x03, 0x04], 'zip'], [[0x89, 0x50, 0x4E, 0x47], 'png'], [[0xFF, 0xD8, 0xFF], 'jpeg'], [[0x25, 0x50, 0x44, 0x46], 'pdf'],
    [[0x47, 0x49, 0x46, 0x38], 'gif'], [[0x1F, 0x8B, 0x08], 'gzip'], [[0x52, 0x61, 0x72, 0x21], 'rar'], [[0x37, 0x7A, 0xBC, 0xAF], '7z'], [[0x7F, 0x45, 0x4C, 0x46], 'elf'], [[0x42, 0x5A, 0x68], 'bzip2']];

  // Describe el comienzo de unos bytes: texto legible, firma conocida o nada.
  function describe(b) {
    for (const [sig, id] of MAGIC) if (sig.every((x, i) => b[i] === x)) return { kind: 'file', type: id, score: 90 };
    let run = 0, best = 0, text = '';
    for (let i = 0; i < Math.min(b.length, 512); i++) {
      const x = b[i];
      if ((x >= 32 && x < 127) || x === 10 || x === 13 || x === 9) { run++; if (run > best) { best = run; } }
      else { if (i < 8 && run < 4) { /* sigue */ } run = 0; }
    }
    let start = 0;
    while (start < b.length && !((b[start] >= 32 && b[start] < 127) || b[start] === 10)) start++;
    // Prefijo de longitud (4 bytes big-endian) seguido de texto, como hacen algunas herramientas.
    const len32 = b.length >= 8 ? ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0 : 0;
    let lead = 0;
    for (let i = 0; i < Math.min(b.length, 64); i++) { const x = b[i]; if ((x >= 32 && x < 127) || x === 10 || x === 13 || x === 9) lead++; else break; }
    // Un mismo carácter repetido (UUUU…, ????) sale de patrones de bits regulares, no de un mensaje.
    const varied = (s) => new Set(s.slice(0, 64)).size >= 5;
    if (lead >= 6) {
      for (let i = 0; i < Math.min(b.length, 200); i++) { const x = b[i]; if ((x >= 32 && x < 127) || x === 10 || x === 13 || x === 9) text += String.fromCharCode(x); else break; }
      if (varied(text)) return { kind: 'text', text, score: Math.min(100, 40 + lead), flag: /[A-Za-z][A-Za-z0-9]{1,15}\{[^}\s]{2,120}\}/.test(text) };
      text = '';
    }
    if (len32 > 0 && len32 < b.length * 8 && len32 < 1e6) {
      let t = 0;
      for (let i = 4; i < Math.min(b.length, 4 + Math.min(len32, 60)); i++) { const x = b[i]; if ((x >= 32 && x < 127) || x === 10) t++; else break; }
      if (t >= Math.min(len32, 6) && t >= 4) {
        for (let i = 4; i < Math.min(b.length, 4 + Math.min(len32, 200)); i++) { const x = b[i]; if ((x >= 32 && x < 127) || x === 10 || x === 13 || x === 9) text += String.fromCharCode(x); else break; }
        if (!varied(text)) return { kind: 'none', score: 0 };
        return { kind: 'text', prefixed: len32, text, score: 70 + Math.min(20, t), flag: /[A-Za-z][A-Za-z0-9]{1,15}\{[^}\s]{2,120}\}/.test(text) };
      }
    }
    return { kind: 'none', score: 0 };
  }

  // Prueba las combinaciones habituales (como hace zsteg) y devuelve las que dan algo con sentido.
  const COMBOS = (() => {
    const out = [];
    for (const channels of ['rgb', 'bgr', 'r', 'g', 'b', 'a', 'rgba', 'abgr']) for (const bits of [[0], [1], [0, 1], [1, 0]]) for (const order of ['row', 'col']) for (const msbFirst of [true, false]) out.push({ channels, bits, order, msbFirst });
    return out;
  })();
  function scan(px, w, h, opts) {
    opts = opts || {};
    const hasAlpha = (() => { for (let i = 3; i < px.length; i += 4) if (px[i] !== 255) return true; return false; })();
    const results = [];
    for (const c of COMBOS) {
      if (!hasAlpha && c.channels.includes('a')) continue;
      const d = extract(px, w, h, Object.assign({ maxBytes: 256 }, c));
      const desc = describe(d);
      if (desc.score >= 45) results.push(Object.assign({}, c, desc));
    }
    return results.sort((a, b) => (b.flag ? 1 : 0) - (a.flag ? 1 : 0) || b.score - a.score).slice(0, opts.limit || 20);
  }

  // ───────── Ataque chi-cuadrado (Westfeld y Pfitzmann, 1999) ─────────
  // Si el LSB lleva datos aleatorios, cada pareja de valores (2k, 2k+1) tiende a igualarse.
  // Devuelve la probabilidad de que haya inserción LSB en cada tramo acumulado de la imagen.
  function lnGamma(x) {
    const c = [76.18009172947146, -86.50532032941677, 24.01409824083091, -1.231739572450155, 0.1208650973866179e-2, -0.5395239384953e-5];
    let y = x, tmp = x + 5.5; tmp -= (x + 0.5) * Math.log(tmp);
    let ser = 1.000000000190015;
    for (let j = 0; j < 6; j++) ser += c[j] / ++y;
    return -tmp + Math.log(2.5066282746310005 * ser / x);
  }
  // Función gamma incompleta regularizada P(a, x).
  function gammaP(a, x) {
    if (x <= 0) return 0;
    if (x < a + 1) {
      let sum = 1 / a, del = sum, ap = a;
      for (let n = 0; n < 500; n++) { ap++; del *= x / ap; sum += del; if (Math.abs(del) < Math.abs(sum) * 1e-12) break; }
      return sum * Math.exp(-x + a * Math.log(x) - lnGamma(a));
    }
    let b = x + 1 - a, c = 1 / 1e-300, d = 1 / b, hh = d;
    for (let i = 1; i < 500; i++) {
      const an = -i * (i - a); b += 2;
      d = an * d + b; if (Math.abs(d) < 1e-300) d = 1e-300;
      c = b + an / c; if (Math.abs(c) < 1e-300) c = 1e-300;
      d = 1 / d; const del = d * c; hh *= del;
      if (Math.abs(del - 1) < 1e-12) break;
    }
    return 1 - Math.exp(-x + a * Math.log(x) - lnGamma(a)) * hh;
  }
  function chiSquare(px, w, h, opts) {
    opts = opts || {};
    const chans = Array.from(opts.channels || 'rgb').map(c => CH[c]);
    const steps = opts.steps || 20;
    const total = w * h;
    const hist = new Float64Array(256);
    const curve = [];
    let next = Math.ceil(total / steps), stepIdx = 1;
    for (let p = 0; p < total; p++) {
      for (const c of chans) hist[px[p * 4 + c]]++;
      if (p + 1 >= next || p === total - 1) {
        let chi = 0, df = -1;
        for (let k = 0; k < 128; k++) {
          const e = (hist[2 * k] + hist[2 * k + 1]) / 2;
          if (e <= 4) continue;
          chi += (hist[2 * k] - e) ** 2 / e;
          df++;
        }
        const prob = df > 0 ? 1 - gammaP(df / 2, chi / 2) : 0;
        curve.push({ upTo: (p + 1) / total, prob });
        stepIdx++;
        next = Math.ceil((total * stepIdx) / steps);
      }
    }
    // Estimación de hasta dónde llegan los datos: último tramo con probabilidad alta.
    let extent = 0;
    for (const pt of curve) if (pt.prob > 0.95) extent = pt.upTo;
    // Indicador: el máximo del primer 20 % (el primer tramo solo tiene pocos píxeles y fluctúa).
    const early = curve.filter(pt => pt.upTo <= 0.2 + 1e-9);
    return { curve, extent, first: early.length ? Math.max(...early.map(pt => pt.prob)) : 0 };
  }

  return { bitPlane, extract, embed, describe, scan, chiSquare, COMBOS };
});
