/* InspectorKit · pestaña Cifrados: codificar/decodificar en cadena, romper sin clave y «Magia» */
(function () {
  'use strict';
  const { t, esc } = IK;
  const C = IKCipher;
  const $ = (id) => document.getElementById(id);

  IK.addI18n({
    es: {
      'ci.inT': 'Entrada', 'ci.inPh': 'Pega aquí el texto codificado o cifrado…', 'ci.op': 'Operación', 'ci.mode': 'Sentido', 'ci.dec': 'Decodificar', 'ci.enc': 'Codificar',
      'ci.magic': '✨ Magia', 'ci.crack': 'Romper sin clave', 'ci.sample': 'Ejemplo',
      'ci.help': 'La operación se aplica al escribir. «Magia» prueba decodificaciones en cadena (hasta 3 capas) y ordena lo que parece texto; «Romper sin clave» ataca César, Vigenère, afín, rail fence, escítala y XOR.',
      'ci.outT': 'Salida', 'ci.viewText': 'TEXTO', 'ci.chain': 'Usar como entrada ↺', 'ci.toFile': '→ Archivo',
      'ci.binary': 'La salida no es texto UTF-8 válido: se muestra byte a byte. Mira la vista HEX o pásala a la pestaña Archivo.',
      'ci.binIn': 'Entrada binaria · {n} bytes (se muestra en hexadecimal)', 'ci.binClear': 'Escribir texto', 'ci.textIn': '{c} caracteres · {n} bytes',
      'ci.recipe': 'Receta:', 'ci.reset': 'volver al original', 'ci.magicT': 'Magia: lo que más parece texto', 'ci.crackT': 'Candidatos sin clave ({op})',
      'ci.key': 'Clave', 'ci.score': 'Parece texto', 'ci.preview': 'Vista previa', 'ci.use': 'Usar', 'ci.steps': 'Pasos', 'ci.noMagic': 'No se ha encontrado ninguna capa que dé texto legible.',
      'ci.g.enc': 'Codificaciones', 'ci.g.classic': 'Cifrados clásicos', 'ci.g.modern': 'Bytes',
      'op.base64': 'Base64', 'op.base32': 'Base32', 'op.base58': 'Base58 (Bitcoin)', 'op.ascii85': 'Ascii85 (Adobe)', 'op.hex': 'Hexadecimal', 'op.binary': 'Binario', 'op.decimal': 'Decimal (bytes)',
      'op.url': 'URL (porcentaje)', 'op.html': 'Entidades HTML', 'op.morse': 'Morse', 'op.bacon': 'Bacon', 'op.reverse': 'Invertir', 'op.rot13': 'ROT13', 'op.rot47': 'ROT47', 'op.caesar': 'César',
      'op.atbash': 'Atbash', 'op.vigenere': 'Vigenère', 'op.affine': 'Afín', 'op.rail': 'Rail fence (zigzag)', 'op.scytale': 'Escítala', 'op.polybius': 'Cuadrado de Polibio', 'op.playfair': 'Playfair', 'op.xor': 'XOR',
      'p.shift': 'Desplazamiento', 'p.key': 'Clave', 'p.a': 'a (coprimo con 26)', 'p.b': 'b', 'p.rails': 'Raíles', 'p.cols': 'Letras por vuelta (columnas)', 'p.v24': 'Alfabeto de 24 (I=J, U=V)',
      'p.clean': 'Quitar las X de relleno', 'p.fmt': 'Formato de la clave', 'p.fmt.text': 'texto', 'p.fmt.hex': 'hex', 'p.polyKey': 'Palabra clave (opcional)',
      'err.badB64': 'No es Base64 válido.', 'err.badB32': 'No es Base32 válido.', 'err.badB58': 'No es Base58 válido.', 'err.badA85': 'No es Ascii85 válido.', 'err.badHex': 'No es hexadecimal válido (número par de dígitos 0-9 a-f).',
      'err.badBin': 'No es binario válido (grupos de 8 bits).', 'err.badDec': 'No son bytes en decimal (0-255 separados por espacios o comas).', 'err.badUrl': 'No hay secuencias %XX que decodificar.',
      'err.badHtml': 'No hay entidades HTML que decodificar.', 'err.badMorse': 'Morse: usa solo . - espacio y / entre palabras.', 'err.badMorseCode': 'Código Morse desconocido: {code}', 'err.badBacon': 'Bacon: hacen falta grupos de 5 A/B (o 0/1).',
      'err.needKey': 'Falta la clave (solo cuentan las letras A-Z).', 'err.badAffine': '«a» tiene que ser coprimo con 26: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23 o 25.', 'err.badRails': 'Hacen falta al menos 2 raíles.',
      'err.badScytale': 'Hacen falta al menos 2 columnas.', 'err.badPoly': 'Polibio: pares de dígitos del 1 al 5 (palabras separadas por / o dos espacios).', 'err.badPolyLen': 'Polibio: número impar de dígitos en una palabra.',
      'err.badPolyPair': 'Polibio: par no válido {pair}.', 'err.badPlayfairLen': 'Playfair: el texto cifrado tiene que tener un número par de letras.', 'err.badXorKey': 'La clave XOR en hex no es válida.',
      'err.tooShort': 'Texto demasiado corto para atacarlo (mínimo {min}).', 'err.empty': 'No hay letras que procesar.',
    },
    en: {
      'ci.inT': 'Input', 'ci.inPh': 'Paste the encoded or encrypted text here…', 'ci.op': 'Operation', 'ci.mode': 'Direction', 'ci.dec': 'Decode', 'ci.enc': 'Encode',
      'ci.magic': '✨ Magic', 'ci.crack': 'Break without key', 'ci.sample': 'Example',
      'ci.help': 'The operation is applied as you type. “Magic” tries chained decodings (up to 3 layers) and ranks what looks like text; “Break without key” attacks Caesar, Vigenère, affine, rail fence, scytale and XOR.',
      'ci.outT': 'Output', 'ci.viewText': 'TEXT', 'ci.chain': 'Use as input ↺', 'ci.toFile': '→ File',
      'ci.binary': 'The output is not valid UTF-8 text: it is shown byte by byte. Use the HEX view or send it to the File tab.',
      'ci.binIn': 'Binary input · {n} bytes (shown in hexadecimal)', 'ci.binClear': 'Type text', 'ci.textIn': '{c} characters · {n} bytes',
      'ci.recipe': 'Recipe:', 'ci.reset': 'back to the original', 'ci.magicT': 'Magic: what looks most like text', 'ci.crackT': 'Keyless candidates ({op})',
      'ci.key': 'Key', 'ci.score': 'Looks like text', 'ci.preview': 'Preview', 'ci.use': 'Use', 'ci.steps': 'Steps', 'ci.noMagic': 'No layer producing readable text was found.',
      'ci.g.enc': 'Encodings', 'ci.g.classic': 'Classical ciphers', 'ci.g.modern': 'Bytes',
      'op.base64': 'Base64', 'op.base32': 'Base32', 'op.base58': 'Base58 (Bitcoin)', 'op.ascii85': 'Ascii85 (Adobe)', 'op.hex': 'Hexadecimal', 'op.binary': 'Binary', 'op.decimal': 'Decimal (bytes)',
      'op.url': 'URL (percent)', 'op.html': 'HTML entities', 'op.morse': 'Morse', 'op.bacon': 'Bacon', 'op.reverse': 'Reverse', 'op.rot13': 'ROT13', 'op.rot47': 'ROT47', 'op.caesar': 'Caesar',
      'op.atbash': 'Atbash', 'op.vigenere': 'Vigenère', 'op.affine': 'Affine', 'op.rail': 'Rail fence (zigzag)', 'op.scytale': 'Scytale', 'op.polybius': 'Polybius square', 'op.playfair': 'Playfair', 'op.xor': 'XOR',
      'p.shift': 'Shift', 'p.key': 'Key', 'p.a': 'a (coprime with 26)', 'p.b': 'b', 'p.rails': 'Rails', 'p.cols': 'Letters per turn (columns)', 'p.v24': '24-letter alphabet (I=J, U=V)',
      'p.clean': 'Remove filler X', 'p.fmt': 'Key format', 'p.fmt.text': 'text', 'p.fmt.hex': 'hex', 'p.polyKey': 'Keyword (optional)',
      'err.badB64': 'Not valid Base64.', 'err.badB32': 'Not valid Base32.', 'err.badB58': 'Not valid Base58.', 'err.badA85': 'Not valid Ascii85.', 'err.badHex': 'Not valid hexadecimal (an even number of 0-9 a-f digits).',
      'err.badBin': 'Not valid binary (groups of 8 bits).', 'err.badDec': 'Not bytes in decimal (0-255 separated by spaces or commas).', 'err.badUrl': 'There are no %XX sequences to decode.',
      'err.badHtml': 'There are no HTML entities to decode.', 'err.badMorse': 'Morse: use only . - space and / between words.', 'err.badMorseCode': 'Unknown Morse code: {code}', 'err.badBacon': 'Bacon: groups of 5 A/B (or 0/1) are needed.',
      'err.needKey': 'The key is missing (only letters A-Z count).', 'err.badAffine': '“a” must be coprime with 26: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23 or 25.', 'err.badRails': 'At least 2 rails are needed.',
      'err.badScytale': 'At least 2 columns are needed.', 'err.badPoly': 'Polybius: pairs of digits 1 to 5 (words separated by / or two spaces).', 'err.badPolyLen': 'Polybius: odd number of digits in a word.',
      'err.badPolyPair': 'Polybius: invalid pair {pair}.', 'err.badPlayfairLen': 'Playfair: the ciphertext must have an even number of letters.', 'err.badXorKey': 'The hex XOR key is not valid.',
      'err.tooShort': 'Text too short to attack (minimum {min}).', 'err.empty': 'There are no letters to process.',
    },
  });

  const state = { op: 'base64', mode: 'dec', params: {}, view: 'text', inBytes: null, original: null, recipe: [], out: null, override: null };
  let timer = null;

  const opName = (id) => t('op.' + id);
  const paramLabel = (op, p) => (op.id === 'polybius' && p.id === 'key') ? t('p.polyKey') : t('p.' + p.id);

  function fillOps() {
    const sel = $('ciOp');
    const groups = { enc: [], classic: [], modern: [] };
    for (const op of C.OPS) groups[op.group].push(op);
    sel.innerHTML = Object.entries(groups).map(([g, ops]) => `<optgroup label="${esc(t('ci.g.' + g))}">${ops.map(o => `<option value="${o.id}">${esc(opName(o.id))}</option>`).join('')}</optgroup>`).join('');
    sel.value = state.op;
  }

  function renderParams() {
    const op = C.OP[state.op];
    const box = $('ciParams');
    const defs = op.params || [];
    for (const d of defs) if (state.params[d.id] == null) state.params[d.id] = d.def;
    box.innerHTML = defs.map(d => {
      const id = 'ciP_' + d.id, v = state.params[d.id];
      if (d.type === 'check') return `<label class="check"><input type="checkbox" id="${id}" ${v ? 'checked' : ''}> <span>${esc(paramLabel(op, d))}</span></label>`;
      if (d.type === 'select') return `<div class="field"><label class="label" for="${id}">${esc(paramLabel(op, d))}</label><select class="select" id="${id}">${d.options.map(o => `<option value="${o}"${o === v ? ' selected' : ''}>${esc(t('p.fmt.' + o))}</option>`).join('')}</select></div>`;
      if (d.type === 'number') return `<div class="field"><label class="label" for="${id}">${esc(paramLabel(op, d))}</label><input class="input" type="number" id="${id}" value="${esc(v)}" min="${d.min}" max="${d.max}"></div>`;
      return `<div class="field"><label class="label" for="${id}">${esc(paramLabel(op, d))}</label><input class="input" id="${id}" value="${esc(v)}" spellcheck="false" autocomplete="off"></div>`;
    }).join('');
    box.hidden = !defs.length;
    defs.forEach(d => {
      const el = $('ciP_' + d.id);
      el.addEventListener(d.type === 'check' || d.type === 'select' ? 'change' : 'input', () => {
        state.params[d.id] = d.type === 'check' ? el.checked : el.value;
        state.override = null; schedule();
      });
    });
    $('ciCrack').disabled = !op.crack || state.mode !== 'dec';
    document.querySelectorAll('#ciMode button').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.mode === state.mode)));
  }

  function inputBytes() { return state.inBytes || C.utf8($('ciIn').value); }

  function updateInInfo() {
    const ta = $('ciIn');
    if (state.inBytes) {
      $('ciInInfo').innerHTML = `${esc(t('ci.binIn', { n: IK.num(state.inBytes.length) }))} · <button class="btn ghost small" type="button" id="ciBinClear">${esc(t('ci.binClear'))}</button>`;
      $('ciBinClear').onclick = () => { state.inBytes = null; ta.readOnly = false; ta.value = ''; state.recipe = []; state.original = null; updateInInfo(); schedule(); };
    } else {
      const v = ta.value;
      $('ciInInfo').textContent = v ? t('ci.textIn', { c: IK.num(Array.from(v).length), n: IK.num(C.utf8(v).length) }) : '';
    }
  }

  function setBinaryInput(bytes) {
    const { binary, text } = C.bytesToText(bytes);
    const ta = $('ciIn');
    if (!binary) { state.inBytes = null; ta.readOnly = false; ta.value = text; }
    else { state.inBytes = bytes; ta.readOnly = true; ta.value = C.hexOf(bytes.length > 65536 ? bytes.subarray(0, 65536) : bytes) + (bytes.length > 65536 ? ' …' : ''); }
    updateInInfo();
  }

  function schedule() { clearTimeout(timer); timer = setTimeout(run, 120); }

  function run() {
    updateInInfo();
    const err = $('ciErr');
    err.innerHTML = '';
    if (state.override) { state.out = state.override.bytes; renderOut(); return; }
    const inp = inputBytes();
    if (!inp.length) { state.out = null; $('ciOut').textContent = ''; return; }
    try {
      state.out = C.run(state.op, state.mode, inp, state.params);
    } catch (e) {
      state.out = null;
      err.innerHTML = `<div class="notice warn" style="margin-bottom:8px">${esc(IK.errText(e))}</div>`;
      $('ciOut').textContent = '';
      return;
    }
    renderOut();
  }

  function renderOut() {
    const out = $('ciOut');
    if (!state.out) { out.textContent = ''; return; }
    const { text, binary } = C.bytesToText(state.out);
    if (binary && state.view === 'text') $('ciErr').innerHTML = `<div class="notice warn" style="margin-bottom:8px">${esc(t('ci.binary'))}</div>`;
    out.classList.toggle('hex', state.view === 'hex');
    out.textContent = state.view === 'hex' ? IKBytes.hexdump(state.out, 0, Math.min(state.out.length, 65536)) : (text.length > 200000 ? text.slice(0, 200000) + '…' : text);
    renderRecipe();
  }

  function stepLabel(s) { return `${opName(s.id)} (${t(s.mode === 'dec' ? 'ci.dec' : 'ci.enc').toLowerCase()})`; }
  function renderRecipe() {
    const box = $('ciRecipe');
    const steps = state.recipe.slice();
    if (state.override) steps.push(...state.override.recipe);
    if (!steps.length) { box.innerHTML = ''; return; }
    box.innerHTML = `<span class="muted">${esc(t('ci.recipe'))}</span> ${steps.map(s => `<span>${esc(stepLabel(s))}</span>`).join(' <span class="muted">→</span> ')}
      ${state.original ? ` · <button type="button" id="ciReset">${esc(t('ci.reset'))}</button>` : ''}`;
    const r = $('ciReset');
    if (r) r.onclick = () => { const o = state.original; state.recipe = []; state.original = null; state.override = null; if (o.bytes) setBinaryInput(o.bytes); else { state.inBytes = null; $('ciIn').readOnly = false; $('ciIn').value = o.text; } schedule(); };
  }

  function chain() {
    if (!state.out) return;
    if (!state.original) state.original = state.inBytes ? { bytes: state.inBytes } : { text: $('ciIn').value };
    if (state.override) state.recipe.push(...state.override.recipe); else state.recipe.push({ id: state.op, mode: state.mode, params: Object.assign({}, state.params) });
    const out = state.out;
    state.override = null;
    setBinaryInput(out);
    $('ciCands').hidden = true;
    schedule();
  }

  function scoreBar(s) { const cls = s >= 60 ? 'ok' : s >= 35 ? 'warn' : 'bad'; return `<div class="bar ${cls}" title="${s}"><i style="width:${Math.max(3, s)}%"></i></div>`; }
  const preview = (s) => esc(s.replace(/\s+/g, ' ').slice(0, 160));

  let cands = [];
  function showCands(title, rows, kind) {
    cands = rows;
    $('ciCands').hidden = false;
    $('ciCandsT').textContent = title;
    if (!rows.length) { $('ciCandsOut').innerHTML = `<p class="muted">${esc(t('ci.noMagic'))}</p>`; return; }
    $('ciCandsOut').innerHTML = `<div class="tbl-wrap"><table class="tbl"><thead><tr><th>${esc(t(kind === 'magic' ? 'ci.steps' : 'ci.key'))}</th><th style="width:120px">${esc(t('ci.score'))}</th><th>${esc(t('ci.preview'))}</th><th></th></tr></thead><tbody>
      ${rows.map((r, i) => `<tr><td class="mono">${kind === 'magic' ? esc(r.recipe.map(stepLabel).join(' → ')) : esc(r.key)}</td><td>${scoreBar(r.score)}</td><td class="mono">${preview(r.text)}</td>
        <td><button class="btn ghost small" type="button" data-cand="${i}" data-kind="${kind}">${esc(t('ci.use'))}</button></td></tr>`).join('')}
      </tbody></table></div>`;
  }

  function doMagic() {
    const inp = inputBytes();
    if (!inp.length) return;
    const res = C.magic(inp);
    showCands(t('ci.magicT'), res, 'magic');
    if (res[0] && res[0].score >= 50) useCand(0, 'magic', true);
    $('ciCands').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
  function doCrack() {
    const op = C.OP[state.op];
    if (!op.crack) return;
    const err = $('ciErr');
    err.innerHTML = '';
    try {
      const res = C.crack(op.crack, inputBytes()).slice(0, 15);
      showCands(t('ci.crackT', { op: opName(op.id) }), res, op.crack);
      if (res[0]) useCand(0, op.crack, true);
    } catch (e) { err.innerHTML = `<div class="notice warn" style="margin-bottom:8px">${esc(IK.errText(e))}</div>`; }
  }

  function useCand(i, kind, quiet) {
    const r = cands[i];
    if (!r) return;
    if (kind === 'magic') {
      state.override = { bytes: r.bytes, recipe: r.recipe };
      run();
    } else {
      const p = state.params;
      if (kind === 'caesar') p.shift = r.key;
      else if (kind === 'vigenere') p.key = r.key;
      else if (kind === 'affine') { p.a = r.a; p.b = r.b; }
      else if (kind === 'rail') p.rails = r.key;
      else if (kind === 'scytale') p.cols = r.key;
      else if (kind === 'xor') { p.key = r.mode === 'xor1' ? r.key.slice(2) : r.keyHex; p.fmt = 'hex'; }
      state.override = null;
      if (kind === 'xor') {
        // El ataque XOR acepta hex o Base64 en la entrada: se muestra el resultado ya calculado.
        state.override = { bytes: r.bytes, recipe: [{ id: 'xor', mode: 'dec', params: { key: p.key, fmt: 'hex' } }] };
      }
      state.mode = 'dec';
      renderParams(); run();
    }
    if (!quiet) $('ciOut').scrollIntoView({ behavior: 'smooth', block: 'center' });
  }

  const SAMPLES = [
    { op: 'base64', text: 'Wm14aFozdGpZWEJoYzE5a1pWOWpiMlJwWm1sallXTnBiMjU5' },
    { op: 'vigenere', text: 'Jn hg lmsaw dr ea Emnhhn, we ugyt nbfbjq nt qhbeja ahoewajye, so ut mmoht tvxmha qze ibvam us hvwadso ie yhs vq lfnmt ef msyiyeeja, aiaeza sztnght, rgois fytcg k gflth cgdrjdbk.' },
    { op: 'morse', text: '..-. .-.. .- --. / ... --- ... / .--. .- .-. .- / - --- -.. --- ...' },
    { op: 'caesar', text: 'Qrv yhprv hq od hvwdflrq d odv vlhwh' },
    { op: 'hex', text: '66 6c 61 67 7b 68 65 78 5f 61 5f 74 65 78 74 6f 7d' },
  ];
  let sampleIdx = 0;

  document.addEventListener('DOMContentLoaded', () => {
    fillOps(); renderParams();
    $('ciOp').addEventListener('change', () => { state.op = $('ciOp').value; state.params = {}; state.override = null; $('ciCands').hidden = true; renderParams(); schedule(); });
    document.querySelectorAll('#ciMode button').forEach(b => b.addEventListener('click', () => { state.mode = b.dataset.mode; state.override = null; renderParams(); schedule(); }));
    document.querySelectorAll('#ciView button').forEach(b => b.addEventListener('click', () => { state.view = b.dataset.view; document.querySelectorAll('#ciView button').forEach(x => x.setAttribute('aria-pressed', String(x === b))); $('ciErr').innerHTML = ''; renderOut(); }));
    $('ciIn').addEventListener('input', () => { state.override = null; state.recipe = []; state.original = null; $('ciCands').hidden = true; schedule(); });
    $('ciMagic').addEventListener('click', doMagic);
    $('ciCrack').addEventListener('click', doCrack);
    $('ciSample').addEventListener('click', () => {
      const s = SAMPLES[sampleIdx++ % SAMPLES.length];
      state.inBytes = null; $('ciIn').readOnly = false; $('ciIn').value = s.text;
      state.op = s.op; state.mode = 'dec'; state.params = {}; state.override = null; state.recipe = []; state.original = null;
      $('ciOp').value = s.op; $('ciCands').hidden = true; renderParams(); run();
      if (s.op === 'base64') doMagic(); else if (C.OP[s.op].crack) doCrack();
    });
    $('ciCandsOut').addEventListener('click', (e) => { const b = e.target.closest('[data-cand]'); if (b) useCand(+b.dataset.cand, b.dataset.kind); });
    $('ciCopy').addEventListener('click', () => { if (state.out) IK.copyText(state.view === 'hex' ? C.hexOf(state.out) : C.asText(state.out)); });
    $('ciChain').addEventListener('click', chain);
    $('ciToHash').addEventListener('click', () => { if (state.out) IK.send('hash', C.bytesToText(state.out).binary ? { bytes: state.out, name: 'salida.bin' } : { text: C.asText(state.out) }); });
    $('ciToFile').addEventListener('click', () => { if (state.out) IK.send('archivo', { bytes: state.out, name: 'salida-cifrados.bin' }); });
    $('ciDl').addEventListener('click', () => { if (state.out) IK.download(C.bytesToText(state.out).binary ? 'salida.bin' : 'salida.txt', state.out); });
    document.addEventListener('ik:lang', () => { fillOps(); renderParams(); updateInInfo(); renderRecipe(); if (!$('ciCands').hidden && cands.length) $('ciCands').hidden = true; });
    // De otras pestañas: { text } o { bytes }; con magic: true lanza la Magia.
    IK.onReceive('cifrados', (p) => {
      state.override = null; state.recipe = []; state.original = null; $('ciCands').hidden = true;
      if (p.bytes) setBinaryInput(p.bytes); else { state.inBytes = null; $('ciIn').readOnly = false; $('ciIn').value = p.text || ''; }
      if (p.op) { state.op = p.op; state.params = {}; $('ciOp').value = p.op; state.mode = 'dec'; renderParams(); }
      run();
      if (p.magic !== false) doMagic();
    });
  });
})();
