/* InspectorKit · pestaña Hash: calcular, verificar e identificar */
(function () {
  'use strict';
  const { t, esc } = IK;
  const $ = (id) => document.getElementById(id);
  const enc = new TextEncoder();

  IK.addI18n({
    es: {
      'hash.calcT': 'Calcular y verificar', 'hash.text': 'Texto', 'hash.file': 'Archivo',
      'hash.textPh': 'Escribe o pega el texto…', 'hash.textNote': 'El texto se codifica en UTF-8 tal cual, sin quitar espacios ni saltos de línea finales (igual que printf, no como echo, que añade un salto).',
      'hash.drop': 'Suelta aquí el archivo o haz clic para elegirlo', 'hash.expected': 'Hash esperado (opcional)', 'hash.expectedPh': 'Pega el hash publicado para comprobar que coincide',
      'hash.upper': 'Mayúsculas', 'hash.alg': 'Algoritmo', 'hash.value': 'Valor',
      'hash.match': '✔ Coincide con {alg}.', 'hash.noMatch': '✘ No coincide con ninguno de los hashes calculados. Comprueba que el archivo o el texto son exactamente los mismos.',
      'hash.ntlmNote': 'NTLM = MD4 del texto en UTF-16LE: es el hash de las contraseñas de Windows.',
      'hash.fileInfo': '{name} · {size}', 'hash.computing': 'Calculando…',
      'hash.idT': 'Identificar hashes', 'hash.idPh': 'Pega uno o varios hashes, uno por línea (también líneas de /etc/shadow, volcados SAM o NetNTLMv2)', 'hash.idBtn': 'Identificar', 'hash.sample': 'Ejemplos',
      'hash.cand': 'Posibles tipos', 'hash.mode': 'hashcat -m', 'hash.john': 'john --format', 'hash.input': 'Entrada', 'hash.notes': 'Notas',
      'hash.n.slow': 'Algoritmo lento a propósito: un ataque de diccionario va a ser costoso.',
      'hash.n.shadow': 'Formato de /etc/shadow: el texto entre los dos primeros $ es el tipo y lo siguiente, la sal.',
      'hash.n.ad': 'Hash de Active Directory: se ataca sin conexión con hashcat.',
      'hash.n.pwdump': 'Línea usuario:RID:LM:NT. La parte útil es el hash NT (cuarto campo).',
      'hash.n.jwt': 'Un JWT no se descifra: va firmado. El modo 16500 de hashcat ataca el secreto HS256 si es débil. Su contenido se puede leer con Base64 en Cifrados.',
      'hash.n.lmEmpty': 'Es el hash LM de la contraseña vacía: LM está desactivado en esa cuenta.',
      'hash.n.ntEmpty': 'Es el hash NT de la contraseña vacía.',
      'hash.n.md5Empty': 'Es el MD5 de un texto vacío.', 'hash.n.sha1Empty': 'Es el SHA-1 de un texto vacío.', 'hash.n.sha256Empty': 'Es el SHA-256 de un texto vacío.',
      'hash.n.b64digest': 'Parece un hash binario codificado en Base64. Decodifícalo en Cifrados (Base64 → Hex) para tenerlo en hexadecimal.',
      'hash.n.hexUnknown': 'Hexadecimal de una longitud que no corresponde a ningún hash habitual ({len} caracteres).',
      'hash.n.unknown': 'No se reconoce el formato.',
      'hash.cmd': 'Orden', 'hash.rockyou': '¿Contraseña común? Búscala en <a href="https://unfantasmaenelsistema.github.io/RockYouFinder/" target="_blank" rel="noopener">RockYouFinder</a>.',
    },
    en: {
      'hash.calcT': 'Compute and verify', 'hash.text': 'Text', 'hash.file': 'File',
      'hash.textPh': 'Type or paste the text…', 'hash.textNote': 'The text is encoded as UTF-8 exactly as typed, without trimming spaces or final line breaks (like printf, unlike echo, which adds a newline).',
      'hash.drop': 'Drop the file here or click to choose it', 'hash.expected': 'Expected hash (optional)', 'hash.expectedPh': 'Paste the published hash to check that it matches',
      'hash.upper': 'Uppercase', 'hash.alg': 'Algorithm', 'hash.value': 'Value',
      'hash.match': '✔ Matches {alg}.', 'hash.noMatch': '✘ Does not match any of the computed hashes. Check that the file or the text are exactly the same.',
      'hash.ntlmNote': 'NTLM = MD4 of the text in UTF-16LE: it is the Windows password hash.',
      'hash.fileInfo': '{name} · {size}', 'hash.computing': 'Computing…',
      'hash.idT': 'Identify hashes', 'hash.idPh': 'Paste one or more hashes, one per line (also /etc/shadow lines, SAM dumps or NetNTLMv2)', 'hash.idBtn': 'Identify', 'hash.sample': 'Examples',
      'hash.cand': 'Possible types', 'hash.mode': 'hashcat -m', 'hash.john': 'john --format', 'hash.input': 'Input', 'hash.notes': 'Notes',
      'hash.n.slow': 'Deliberately slow algorithm: a dictionary attack will be expensive.',
      'hash.n.shadow': '/etc/shadow format: the text between the first two $ is the type and what follows is the salt.',
      'hash.n.ad': 'Active Directory hash: it is attacked offline with hashcat.',
      'hash.n.pwdump': 'user:RID:LM:NT line. The useful part is the NT hash (fourth field).',
      'hash.n.jwt': 'A JWT is not decrypted: it is signed. hashcat mode 16500 attacks a weak HS256 secret. Its content can be read with Base64 in Ciphers.',
      'hash.n.lmEmpty': 'It is the LM hash of the empty password: LM is disabled on that account.',
      'hash.n.ntEmpty': 'It is the NT hash of the empty password.',
      'hash.n.md5Empty': 'It is the MD5 of an empty text.', 'hash.n.sha1Empty': 'It is the SHA-1 of an empty text.', 'hash.n.sha256Empty': 'It is the SHA-256 of an empty text.',
      'hash.n.b64digest': 'It looks like a binary hash encoded in Base64. Decode it in Ciphers (Base64 → Hex) to get it in hexadecimal.',
      'hash.n.hexUnknown': 'Hexadecimal of a length that matches no common hash ({len} characters).',
      'hash.n.unknown': 'The format is not recognised.',
      'hash.cmd': 'Command', 'hash.rockyou': 'A common password? Look it up in <a href="https://unfantasmaenelsistema.github.io/RockYouFinder/" target="_blank" rel="noopener">RockYouFinder</a>.',
    },
  });

  let mode = 'text';
  let fileBytes = null, fileName = '';
  let last = null;
  let timer = null;

  function setMode(m) {
    mode = m;
    document.querySelectorAll('#hashMode button').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.mode === m)));
    $('hashTextBox').hidden = m !== 'text';
    $('hashFileBox').hidden = m !== 'file';
    compute();
  }

  async function compute() {
    const out = $('hashOut');
    let input;
    if (mode === 'text') input = $('hashText').value;
    else input = fileBytes;
    if (input == null || (mode === 'file' && !fileBytes)) { out.innerHTML = ''; $('hashVerdict').innerHTML = ''; last = null; return; }
    out.innerHTML = `<p class="muted"><span class="spin"></span> ${esc(t('hash.computing'))}</p>`;
    try { last = await IKHash.all(input); } catch (e) { out.innerHTML = `<div class="notice bad">${esc(IK.errText(e))}</div>`; return; }
    render();
  }

  function render() {
    if (!last) return;
    const up = $('hashUpper').checked;
    const match = IKHash.verify($('hashExpected').value, last);
    const rows = Object.entries(last).map(([alg, h]) => {
      const v = up ? h.toUpperCase() : h;
      return `<tr${match === alg ? ' class="hl"' : ''}><td class="k mono">${esc(alg)}</td><td class="mono">${esc(v)}</td>
        <td><div class="btns"><button class="btn ghost small" data-copy="${esc(v)}">${esc(t('c.copy'))}</button><button class="btn ghost small" data-id="${esc(h)}">${esc(t('hash.idBtn'))}</button></div></td></tr>`;
    }).join('');
    $('hashOut').innerHTML = `<div class="tbl-wrap"><table class="tbl"><thead><tr><th>${esc(t('hash.alg'))}</th><th>${esc(t('hash.value'))}</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>
      ${last.NTLM ? `<p class="muted small" style="margin-top:8px">${esc(t('hash.ntlmNote'))}</p>` : ''}`;
    const v = $('hashVerdict');
    if (match === null) v.innerHTML = '';
    else v.innerHTML = `<div class="notice ${match ? 'ok' : 'bad'}" style="margin-bottom:10px">${esc(match ? t('hash.match', { alg: match }) : t('hash.noMatch'))}</div>`;
  }

  function identify() {
    const lines = $('hashId').value.split(/\r?\n/).map(s => s.trim()).filter(Boolean).slice(0, 500);
    if (!lines.length) { $('hashIdOut').innerHTML = ''; return; }
    const rows = lines.map(l => {
      const r = IKHash.identify(l);
      const cands = r.matches.map(m => `<div>${esc(m.name)}</div>`).join('') || '<span class="muted">—</span>';
      const modes = r.matches.map(m => `<div class="mono">${m.mode != null ? esc(m.mode) : '—'}</div>`).join('');
      const johns = r.matches.map(m => `<div class="mono">${m.john ? esc(m.john) : '—'}</div>`).join('');
      const hex = l.replace(/^0x/i, '');
      const notes = r.notes.map(n => `<div class="small">${esc(t('hash.n.' + n, { len: hex.length }))}</div>`).join('');
      const first = r.matches.find(m => m.mode != null);
      const cmd = first ? `hashcat -m ${first.mode} hash.txt rockyou.txt` : '';
      return `<tr><td class="mono" style="max-width:280px">${esc(l.length > 90 ? l.slice(0, 90) + '…' : l)}</td><td>${cands}</td><td>${modes}</td><td>${johns}</td>
        <td>${notes}${cmd ? `<div class="btns" style="margin-top:4px"><code>${esc(cmd)}</code><button class="btn ghost small" data-copy="${esc(cmd)}">${esc(t('c.copy'))}</button></div>` : ''}</td></tr>`;
    }).join('');
    $('hashIdOut').innerHTML = `<div class="tbl-wrap"><table class="tbl"><thead><tr><th>${esc(t('hash.input'))}</th><th>${esc(t('hash.cand'))}</th><th>${esc(t('hash.mode'))}</th><th>${esc(t('hash.john'))}</th><th>${esc(t('hash.notes'))}</th></tr></thead><tbody>${rows}</tbody></table></div>
      <p class="muted small" style="margin-top:8px">${t('hash.rockyou')}</p>`;
  }

  const SAMPLES = [
    '5f4dcc3b5aa765d61d8327deb882cf99',
    '$6$fantasma$h7PkwwgU6BpATlWNNJE1foekdyINSzwcs0Np//6SVU0yBouUUdKeKQZLb2XzJ1zVu9YzBC9KCUNvNDkzdSPM40',
    '$1$fantasma$sWQSBXZD7abpHkJv2fpEo/',
    '$2y$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy',
    'Administrador:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::',
    '*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19',
    'X03MO1qnZdYdgyfeuILPmQ==',
  ];

  document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('#hashMode button').forEach(b => b.addEventListener('click', () => setMode(b.dataset.mode)));
    $('hashText').addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(compute, 200); });
    $('hashExpected').addEventListener('input', render);
    $('hashUpper').addEventListener('change', render);
    IK.dropzone($('hashDrop'), async (f) => {
      fileName = f.name;
      $('hashFileName').textContent = t('hash.fileInfo', { name: f.name, size: IK.size(f.size) });
      $('hashFileName').removeAttribute('data-t');
      fileBytes = await IK.readFile(f);
      compute();
    });
    $('hashIdBtn').addEventListener('click', identify);
    $('hashIdSample').addEventListener('click', () => { $('hashId').value = SAMPLES.join('\n'); identify(); });
    document.querySelector('[data-tab="hash"]').addEventListener('click', (e) => {
      const c = e.target.closest('[data-copy]'); if (c) { IK.copyText(c.dataset.copy); return; }
      const i = e.target.closest('[data-id]'); if (i) { $('hashId').value = i.dataset.id; identify(); $('hashId').scrollIntoView({ behavior: 'smooth', block: 'center' }); }
    });
    document.addEventListener('ik:lang', () => { render(); identify(); if (fileName) $('hashFileName').textContent = t('hash.fileInfo', { name: fileName, size: IK.size(fileBytes.length) }); });
    // Lo que llega de otras pestañas: { text } , { bytes, name } o { identify }
    IK.onReceive('hash', (p) => {
      if (p.identify) { $('hashId').value = p.identify; identify(); return; }
      if (p.bytes) { fileBytes = p.bytes; fileName = p.name || 'datos.bin'; $('hashFileName').textContent = t('hash.fileInfo', { name: fileName, size: IK.size(fileBytes.length) }); $('hashFileName').removeAttribute('data-t'); setMode('file'); return; }
      if (p.text != null) { $('hashText').value = p.text; setMode('text'); }
    });
  });
})();
