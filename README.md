# InspectorKit

**Caja de inspección forense y para CTF, gratis y en el navegador** · *Free forensic and CTF inspection toolbox, right in your browser*

👉 **https://unfantasmaenelsistema.github.io/InspectorKit/**

| Pestaña | Qué hace | Antes |
|---|---|---|
| 🗂️ [Archivo](https://unfantasmaenelsistema.github.io/InspectorKit/#archivo) | Triaje de cualquier archivo: tipo real por su firma (y aviso si la extensión engaña), entropía, MD5/SHA-1/SHA-256. Metadatos EXIF/XMP/IPTC con GPS y miniatura, textos PNG, comentarios JPEG/GIF, PDF (`/Info`, XMP y elementos activos como hace pdfid, también dentro de flujos comprimidos), Office (autor, empresa, macros, plantillas remotas), ZIP (contenido, cifrado ZipCrypto/AES), PE y ELF. Datos añadidos tras el final, archivos incrustados, ZIP pegados (políglotas) y PNG con la altura manipulada, con reparación automática. Esteganografía LSB: planos de bits, búsqueda automática como zsteg, extracción manual y ataque chi-cuadrado. Cadenas ASCII/UTF-8 y UTF-16LE, búsqueda que cuenta cada aparición, búsqueda de bytes con comodines, indicadores (URL, IP, correos, rutas, registro, hashes, Base64) y secretos (claves de AWS, Google, GitHub, Slack, Stripe, JWT, claves privadas). Borrado de metadatos de JPEG y PNG sin recomprimir. Visor hexadecimal. | StegaScan, StringerThings |
| #️⃣ [Hash](https://unfantasmaenelsistema.github.io/InspectorKit/#hash) | MD5, SHA-1, SHA-256, SHA-384, SHA-512, CRC32 y NTLM de un texto o un archivo; comprobación contra el hash publicado. Identificador de hashes (hex por longitud, `/etc/shadow`, bcrypt, phpass, Django, LDAP, MySQL, MSSQL, volcados SAM, NetNTLMv1/v2, Kerberoasting, AS-REP, DCC2…) con su modo de hashcat y su formato de John the Ripper. | HashInspector |
| 🔐 [Cifrados](https://unfantasmaenelsistema.github.io/InspectorKit/#cifrados) | Base64, Base32, Base58, Ascii85, hex, binario, decimal, URL, entidades HTML, Morse, Bacon, ROT13, ROT47, César, Atbash, Vigenère, afín, rail fence, escítala, Polibio, Playfair y XOR, en los dos sentidos y en cadena (receta). Ataques sin clave: César, afín, rail fence y escítala por fuerza bruta; Vigenère por índice de coincidencia y chi-cuadrado (español e inglés); XOR de un byte y de clave repetida. «Magia»: detecta hasta tres capas de codificación y ordena lo que parece texto. | C1PH3R |
| 🌐 [Cabeceras](https://unfantasmaenelsistema.github.io/InspectorKit/#cabeceras) | Auditoría de las cabeceras HTTP de seguridad: HSTS, CSP directiva a directiva, clickjacking, nosniff, Referrer-Policy, Permissions-Policy, COOP/CORP, CORS, fugas de versión y cookies (Secure, HttpOnly, SameSite, prefijos `__Host-`/`__Secure-`). Nota tipo securityheaders.com, recomendaciones e informe en Markdown. Genera las órdenes `curl`/PowerShell para obtenerlas. | HttpInspector |

Las pestañas se pasan el trabajo: una cadena Base64 encontrada en un ejecutable va a Cifrados con un clic, un hash extraído va al identificador y el ZIP escondido al final de una foto, o la salida binaria de un decodificador, se vuelve a analizar como archivo. La interfaz está en **español e inglés** y tiene tema **claro u oscuro**.

## Qué se ha corregido respecto a las herramientas originales

Cada una de las cinco webs anteriores tenía fallos que daban resultados falsos:

- **HttpInspector** hacía `fetch()` a la URL desde el navegador. El navegador bloquea casi siempre esa petición por CORS y, cuando la deja pasar, oculta todas las cabeceras salvo siete «inofensivas»; la herramienta daba entonces por **ausentes** cabeceras que sí estaban (con `api.github.com` marcaba como faltantes HSTS, CSP, X-Frame-Options, nosniff y Referrer-Policy, que sí envía). Ahora las cabeceras se pegan desde `curl` o las DevTools, y el botón «Probar desde el navegador» explica qué deja ver el navegador y por qué no sirve para auditar.
- **StegaScan** no hacía esteganografía: solo leía EXIF con exif-js, que solo entiende JPEG, aunque la página prometía IPTC y otros formatos.
- **HashInspector** decía «genera y verifica» pero no verificaba, y si se elegía un archivo y después se escribía un texto seguía calculando el hash del archivo.
- **StringerThings** contaba líneas con coincidencia, no apariciones («admin admin admin» contaba 1), no veía las cadenas UTF-16 de los ejecutables de Windows y pintaba el término buscado con `innerHTML`.
- **C1PH3R** rompía la escítala cuando la longitud no era múltiplo de la clave, decodificaba mal el Base64 con tildes o eñes («contraseÃ±a») y daba basura con claves Vigenère con espacios. La «detección automática» solo listaba las 25 rotaciones de César.

## Privacidad

Web estática en GitHub Pages: sin servidor, cuentas, base de datos ni analítica. Los archivos se leen con la API de archivos del navegador y **no se suben a ningún sitio**. La única petición de red opcional es «Probar desde el navegador» en Cabeceras, que va directa a la URL que escribas. El idioma y el tema se guardan en `localStorage` (`ik_lang`, `ik_theme`).

## Detalles técnicos

- HTML, CSS y JavaScript sin compilar ni dependencias en tiempo de ejecución, salvo [exifr](https://github.com/MikeKovarik/exifr) 7.1.3 (MIT) empaquetado en `assets/vendor/` para leer EXIF, XMP, IPTC y GPS.
- Los motores de `assets/engine/` no tocan el DOM y funcionan igual en Node, así que se pueden probar fuera del navegador:
  - `hash.js`: MD5, MD4/NTLM y CRC32 propios; SHA con Web Crypto. Probado contra el `crypto` de Node con 300 tamaños aleatorios y con los vectores de los RFC.
  - `cipher.js`: probado con los vectores publicados (Vigenère, rail fence, Playfair y afín de Wikipedia; Base32 y Ascii85 contra Python; Base58 con el vector de Bitcoin), ida y vuelta de escítala y rail fence en cientos de combinaciones, y ataques sin clave sobre textos en español e inglés.
  - `bytes.js`: firmas, estructura y metadatos, probado con archivos fabricados con Pillow, pikepdf y python-docx y con ejecutables reales de Windows comparados con pefile.
  - `png.js`: decodificador PNG propio, exacto bit a bit (todas las profundidades, paleta con transparencia y entrelazado Adam7; idéntico a Pillow en las 19 variantes probadas). El `<canvas>` del navegador puede aplicar gamma, perfil de color o alfa premultiplicado y cambiar justo los bits bajos donde va la esteganografía.
  - `stego.js`: extracción LSB al estilo de zsteg (encuentra lo escondido con la herramienta `stegano` de Python) y ataque chi-cuadrado de Westfeld y Pfitzmann.
  - `headers.js`: probado con las cabeceras reales de varias webs y casos de cookies, CORS y CSP.
- Todo texto que viene de un archivo se escapa antes de pintarse.

```
index.html            página única con las pestañas (#inicio #archivo #hash #cifrados #cabeceras)
assets/core.js        marca, ES/EN, tema, pestañas, «Enviar a…» y utilidades
assets/app-*.js       interfaz de cada pestaña
assets/engine/*.js    motores sin DOM
assets/vendor/        exifr y su licencia
```

Para probarlo en local: `python -m http.server` en la carpeta y abre `http://localhost:8000`.

---

## English

**InspectorKit** merges five earlier tools into one page with four tabs. **File** triages any file: real type by signature, misleading extensions, entropy, hashes, EXIF/XMP/GPS, PDF (including compressed object streams), Office (macros, remote templates), ZIP, PE and ELF metadata; data appended after the end, embedded files, polyglots and PNGs with a tampered height (repaired automatically); LSB steganography (bit planes, zsteg-like search, manual extraction, chi-square attack); ASCII/UTF-16 strings, indicators and secrets; lossless metadata removal for JPEG and PNG; hex viewer. **Hash** computes and verifies MD5/SHA/CRC32/NTLM and identifies unknown hashes with their hashcat mode and John format. **Ciphers** encodes and decodes 23 encodings and classical ciphers in chains, breaks Caesar, affine, rail fence, scytale, Vigenère and XOR without the key, and detects layered encodings automatically. **Headers** audits HTTP security headers pasted from `curl` or the DevTools, because a web page cannot read another site's headers. Everything runs in your browser; nothing is uploaded.

## Licencia · License

Código bajo licencia [MIT](LICENSE). exifr: MIT (`assets/vendor/LICENSE-exifr.txt`).
