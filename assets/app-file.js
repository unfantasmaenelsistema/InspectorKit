/* InspectorKit · pestaña Archivo: triaje forense de cualquier archivo */
(function () {
  'use strict';
  const { t, esc } = IK;
  const B = IKBytes;
  const $ = (id) => document.getElementById(id);
  const MAX = 512 * 1024 * 1024;
  const AUTO_STRINGS = 64 * 1024 * 1024;

  IK.addI18n({
    es: {
      'file.title': 'Analizar un archivo', 'file.drop': 'Suelta aquí un archivo o haz clic para elegirlo', 'file.dropSub': 'Cualquier tipo. No se sube a ningún sitio: se lee en tu navegador.', 'file.dropAria': 'Elegir archivo para analizar',
      'file.tooBig': 'El archivo pasa de 512 MB: es demasiado grande para analizarlo en el navegador.', 'file.reading': 'Leyendo y analizando…', 'file.root': 'Archivo', 'file.back': 'Volver a',
      'file.sumT': 'Resumen', 'file.name': 'Nombre', 'file.size': 'Tamaño', 'file.real': 'Tipo real', 'file.browser': 'Tipo según el navegador', 'file.ext': 'Extensión', 'file.extOk': 'coincide con el contenido', 'file.extNone': 'sin extensión',
      'file.entropy': 'Entropía', 'file.entMap': 'Entropía a lo largo del archivo', 'file.hashes': 'Hashes', 'file.verify': 'Verificar en Hash →',
      'file.e0': 'muy repetitivo (relleno, ceros)', 'file.e1': 'texto o código', 'file.e2': 'binario normal', 'file.e3': 'comprimido o cifrado (no se distinguen solo por la entropía)',
      'file.alertsT': 'Hallazgos', 'file.noAlerts': 'Nada llamativo a primera vista. Revisa las secciones de abajo.',
      'file.metaT': 'Metadatos', 'file.structT': 'Estructura y datos ocultos', 'file.stegoT': 'Esteganografía', 'file.strT': 'Cadenas', 'file.iocT': 'Indicadores y secretos', 'file.hexT': 'Hexadecimal',
      'file.unknownType': 'desconocido', 'file.offset': 'Offset', 'file.type': 'Tipo', 'file.note': 'Nota', 'file.extract': 'Extraer', 'file.analyzeIt': 'Analizar →',
      'a.mismatch': 'La extensión «.{ext}» no corresponde al contenido real ({type}). Esperable: {exp}.',
      'a.unknown': 'No se reconoce el tipo por su firma: puede ser un formato raro, datos cifrados o un archivo dañado.',
      'a.trailer': 'Hay {size} añadidos tras el final real del archivo (offset {off}). Contenido: {kind}.', 'a.trailerZeros': 'Hay {size} de ceros tras el final del archivo (relleno, normalmente inofensivo).',
      'a.overlay': 'El ejecutable lleva {size} de «overlay» tras sus secciones (offset {off}), típico de instaladores… y de malware que esconde carga útil. Contenido: {kind}.',
      'a.zipAppended': 'Lleva un ZIP pegado al final con {n} entradas: es un archivo políglota (se abre como {type} y como ZIP).',
      'a.embedded': 'Se han encontrado {n} firmas de archivo dentro (offsets en «Estructura»).', 'a.thumb': 'Contiene una miniatura EXIF: puede mostrar la foto antes de recortarla o editarla.',
      'a.crc': 'El CRC de la cabecera IHDR no cuadra: alguien ha cambiado el ancho o el alto.', 'a.crcFix': 'Tamaño real recuperado por fuerza bruta: {w}×{h}. Descarga el PNG reparado en «Estructura».',
      'a.crcBad': 'Hay trozos PNG con el CRC incorrecto: {list}.', 'a.pngPrivate': 'Trozos PNG no estándar: {list}. Pueden llevar datos escondidos.', 'a.pngText': 'Trae {n} textos incrustados (tEXt/zTXt/iTXt).',
      'a.gps': 'La foto lleva coordenadas GPS: revela dónde se tomó.', 'a.author': 'Lleva datos personales o del equipo: {list}.',
      'a.comment': 'Tiene comentarios incrustados en la imagen.',
      'a.pdfJs': 'El PDF tiene JavaScript ({list}): revísalo antes de abrirlo en un lector que lo ejecute.', 'a.pdfLaunch': 'El PDF puede lanzar programas o abrir archivos (/Launch).',
      'a.pdfEmbedded': 'El PDF lleva archivos adjuntos (/EmbeddedFile).', 'a.pdfEnc': 'El PDF está cifrado.', 'a.pdfUpdates': 'El PDF se ha modificado {n} veces después de crearse (actualizaciones incrementales): las versiones anteriores siguen dentro.',
      'a.macros': 'El documento contiene macros (vbaProject.bin).', 'a.external': 'El documento carga recursos externos: {list}. Es la técnica de «plantilla remota» para colar macros.',
      'a.zipEnc': 'El ZIP tiene entradas cifradas ({kind}).', 'a.zipEncWeak': 'ZipCrypto, débil: se ataca con john/hashcat o con texto en claro conocido (bkcrack)', 'a.zipEncAes': 'AES',
      'a.packed': 'El ejecutable parece empaquetado ({list}): el código real va comprimido o cifrado.', 'a.highEntropySection': 'Secciones con entropía muy alta: {list}.',
      'a.secrets': 'Hay posibles secretos en claro: {list}.', 'a.flag': 'Posible bandera de CTF: {v}', 'a.stego': 'Datos legibles en los bits menos significativos ({combo}): «{text}».',
      'a.chi': 'El ataque chi-cuadrado indica inserción LSB en ~{p} % de la imagen (canales RGB, probabilidad {prob}).',
      'a.highEntropy': 'Entropía muy alta ({e}) para un {type}: podría ir cifrado o llevar datos comprimidos dentro.',
      'm.none': 'No se han encontrado metadatos reconocibles en este tipo de archivo.', 'm.strip': 'Descargar sin metadatos', 'm.stripDone': 'Quitados {n} bloques de metadatos{tr}. La imagen no se recomprime: los píxeles son idénticos.', 'm.stripTr': ' y {size} añadidos al final',
      'm.orient': 'Ojo: la foto tiene orientación EXIF {o}; sin metadatos algunos visores la mostrarán girada.', 'm.stripNo': 'Solo se borran metadatos de JPEG y PNG.',
      'm.map': 'Ver en OpenStreetMap', 'm.thumb': 'Miniatura EXIF', 'm.exifErr': 'No se pudieron leer los metadatos EXIF/XMP.',
      'm.pngText': 'Textos PNG', 'm.keyword': 'Clave', 'm.value': 'Valor', 'm.comments': 'Comentarios', 'm.pdfInfo': 'Diccionario /Info', 'm.pdfXmp': 'XMP', 'm.pdfid': 'Elementos activos (como pdfid)',
      'm.pdfPages': '{n} páginas · PDF {v} · {u} actualizaciones incrementales', 'm.office': 'Propiedades del documento', 'm.zipT': 'Contenido del ZIP ({n} entradas)', 'm.zipName': 'Nombre', 'm.zipSize': 'Tamaño', 'm.zipComp': 'Comprimido',
      'm.zipMod': 'Modificado', 'm.zipEnc': 'Cifrado', 'm.zipComment': 'Comentario del ZIP', 'm.peT': 'Ejecutable de Windows (PE)', 'm.elfT': 'Ejecutable ELF', 'm.sections': 'Secciones',
      'm.machine': 'Arquitectura', 'm.compiled': 'Compilado', 'm.subsystem': 'Subsistema', 'm.dll': 'Biblioteca (DLL)', 'm.bits': 'Bits', 'm.endian': 'Orden de bytes', 'm.elfType': 'Tipo',
      'm.sName': 'Nombre', 'm.sV': 'Tamaño virtual', 'm.sR': 'En disco', 'm.sE': 'Entropía', 'm.sF': 'Permisos', 'm.dims': 'Dimensiones', 'm.frames': 'Fotogramas', 'm.bpp': 'Bits por píxel',
      'mk.title': 'Título', 'mk.subject': 'Asunto', 'mk.author': 'Autor', 'mk.lastModifiedBy': 'Modificado por', 'mk.created': 'Creado', 'mk.modified': 'Modificado', 'mk.lastPrinted': 'Impreso', 'mk.revision': 'Revisión',
      'mk.keywords': 'Palabras clave', 'mk.description': 'Descripción', 'mk.category': 'Categoría', 'mk.application': 'Aplicación', 'mk.appVersion': 'Versión', 'mk.company': 'Empresa', 'mk.manager': 'Responsable',
      'mk.template': 'Plantilla', 'mk.totalTime': 'Tiempo de edición', 'mk.pages': 'Páginas', 'mk.words': 'Palabras', 'mk.macros': 'Macros', 'mk.external': 'Recursos externos',
      's.trailerT': 'Datos tras el final', 's.embT': 'Firmas de archivo dentro', 's.embNone': 'No hay firmas de archivo incrustadas.', 's.thumb': 'miniatura EXIF', 's.inZip': 'dentro del ZIP', 's.inApp': 'dentro de {app}',
      's.chunks': 'Trozos PNG', 's.crcOk': 'CRC correcto', 's.crcBad': 'CRC MAL', 's.private': 'no estándar', 's.fixT': 'Reparar la cabecera', 's.fix': 'El CRC guardado corresponde a {w}×{h} (ahora dice {cw}×{ch}).', 's.fixDl': 'Descargar PNG reparado', 's.fixNo': 'No se ha encontrado un tamaño que cuadre con el CRC (hasta 16384 px de lado).',
      's.segs': 'Segmentos JPEG', 's.len': 'Longitud', 's.noTrailer': 'No hay datos tras el final del archivo.', 's.trailerEnd': 'El formato no permite saber dónde acaba: no se comprueban datos añadidos.',
      'g.noImage': 'La esteganografía LSB solo se puede analizar en imágenes que el navegador sepa abrir.', 'g.jpeg': 'JPEG comprime con pérdida: los bits menos significativos de sus píxeles no guardan datos. Lo habitual en JPEG es steghide (pruébalo sin conexión con steghide o stegseek). Aun así se muestran los planos de bits, que a veces revelan marcas visuales.',
      'g.canvas': 'Esta imagen se decodifica con el navegador: con transparencias o perfiles de color los bits bajos pueden no ser exactos. Los PNG se leen con un decodificador propio, exacto bit a bit.',
      'g.planes': 'Planos de bits', 'g.channel': 'Canal', 'g.bit': 'Bit', 'g.ones': '{p} % de unos', 'g.scanT': 'Búsqueda automática (como zsteg)', 'g.scanNone': 'Ninguna combinación habitual da texto legible ni una firma de archivo.',
      'g.combo': 'Combinación', 'g.result': 'Resultado', 'g.manualT': 'Extracción manual', 'g.channels': 'Canales (orden)', 'g.bits': 'Bits (p. ej. 0 o 1,0)', 'g.order': 'Recorrido', 'g.row': 'por filas', 'g.col': 'por columnas',
      'g.bitOrder': 'Orden de bits', 'g.msb': 'MSB primero', 'g.lsb': 'LSB primero', 'g.bytes': 'Bytes', 'g.extract': 'Extraer', 'g.chiT': 'Ataque chi-cuadrado (Westfeld)', 'g.chiNote': 'Probabilidad de que haya datos aleatorios en el LSB de los canales RGB, acumulando desde el principio de la imagen. Cerca de 1 = datos insertados; cerca de 0 = imagen limpia.',
      'g.upTo': 'Hasta el {p} %', 'g.text': 'texto', 'g.file': 'archivo {t}', 'g.palette': 'Imagen con paleta: los bits se leen de los colores ya convertidos. Para el LSB del índice de paleta usa el canal «índice».',
      'g.index': 'índice',
      'st.min': 'Longitud mínima', 'st.enc': 'Codificación', 'st.all': 'todas', 'st.filter': 'Filtrar', 'st.filterPh': 'texto a filtrar…', 'st.count': '{n} cadenas', 'st.trunc': ' (se ha cortado en {n})',
      'st.export': 'Exportar .txt', 'st.searchT': 'Buscar (cuenta cada aparición)', 'st.searchPh': 'password, token, admin', 'st.regex': 'Expresión regular', 'st.case': 'Distinguir mayúsculas', 'st.search': 'Buscar',
      'st.term': 'Término', 'st.hits': 'Apariciones', 'st.inStrings': 'En cadenas', 'st.badRegex': 'expresión no válida', 'st.bytesT': 'Buscar bytes (hex, ?? = comodín)', 'st.bytesPh': 'FF D8 FF ?? 00 10', 'st.bytesRes': '{n} coincidencias', 'st.bytesBad': 'Patrón hex no válido.',
      'st.compute': 'Extraer cadenas', 'st.big': 'El archivo es grande: las cadenas se extraen a petición.',
      'io.kind': 'Tipo', 'io.value': 'Valor', 'io.n': 'Veces', 'io.none': 'No se han encontrado indicadores.', 'io.export': 'Exportar JSON', 'io.private': 'privada',
      'ik.flag': 'Banderas CTF', 'ik.privkey': 'Claves privadas', 'ik.aws': 'Claves de AWS', 'ik.gcp': 'Claves de Google', 'ik.github': 'Tokens de GitHub', 'ik.slack': 'Tokens de Slack', 'ik.stripe': 'Claves de Stripe', 'ik.jwt': 'JWT',
      'ik.url': 'URL', 'ik.email': 'Correos', 'ik.ipv4': 'IPv4', 'ik.winpath': 'Rutas de Windows', 'ik.unixpath': 'Rutas de Unix', 'ik.registry': 'Registro de Windows', 'ik.pdb': 'Rutas PDB (equipo del desarrollador)', 'ik.md5': 'Hashes de 32 hex', 'ik.sha1': 'Hashes de 40 hex', 'ik.sha256': 'Hashes de 64 hex', 'ik.base64': 'Base64 que decodifica a texto',
      'hx.go': 'Ir', 'hx.prev': '◀ Anterior', 'hx.next': 'Siguiente ▶', 'hx.start': 'Inicio', 'hx.end': 'Final', 'hx.offsetPh': 'offset (0x1A2B o 6699)',
    },
    en: {
      'file.title': 'Analyse a file', 'file.drop': 'Drop a file here or click to choose it', 'file.dropSub': 'Any type. It is not uploaded anywhere: it is read in your browser.', 'file.dropAria': 'Choose a file to analyse',
      'file.tooBig': 'The file is over 512 MB: too large to analyse in the browser.', 'file.reading': 'Reading and analysing…', 'file.root': 'File', 'file.back': 'Back to',
      'file.sumT': 'Summary', 'file.name': 'Name', 'file.size': 'Size', 'file.real': 'Real type', 'file.browser': 'Type according to the browser', 'file.ext': 'Extension', 'file.extOk': 'matches the content', 'file.extNone': 'no extension',
      'file.entropy': 'Entropy', 'file.entMap': 'Entropy along the file', 'file.hashes': 'Hashes', 'file.verify': 'Verify in Hash →',
      'file.e0': 'very repetitive (padding, zeros)', 'file.e1': 'text or code', 'file.e2': 'ordinary binary', 'file.e3': 'compressed or encrypted (entropy alone cannot tell them apart)',
      'file.alertsT': 'Findings', 'file.noAlerts': 'Nothing stands out at first sight. Check the sections below.',
      'file.metaT': 'Metadata', 'file.structT': 'Structure and hidden data', 'file.stegoT': 'Steganography', 'file.strT': 'Strings', 'file.iocT': 'Indicators and secrets', 'file.hexT': 'Hexadecimal',
      'file.unknownType': 'unknown', 'file.offset': 'Offset', 'file.type': 'Type', 'file.note': 'Note', 'file.extract': 'Extract', 'file.analyzeIt': 'Analyse →',
      'a.mismatch': 'The “.{ext}” extension does not match the real content ({type}). Expected: {exp}.',
      'a.unknown': 'The type is not recognised by its signature: it may be a rare format, encrypted data or a damaged file.',
      'a.trailer': 'There are {size} appended after the real end of the file (offset {off}). Content: {kind}.', 'a.trailerZeros': 'There are {size} of zeros after the end of the file (padding, usually harmless).',
      'a.overlay': 'The executable carries {size} of “overlay” after its sections (offset {off}), typical of installers… and of malware hiding a payload. Content: {kind}.',
      'a.zipAppended': 'It has a ZIP appended at the end with {n} entries: it is a polyglot file (it opens as {type} and as ZIP).',
      'a.embedded': '{n} file signatures were found inside (offsets under “Structure”).', 'a.thumb': 'It contains an EXIF thumbnail: it may show the photo before it was cropped or edited.',
      'a.crc': 'The IHDR header CRC does not match: someone changed the width or the height.', 'a.crcFix': 'Real size recovered by brute force: {w}×{h}. Download the repaired PNG under “Structure”.',
      'a.crcBad': 'There are PNG chunks with a wrong CRC: {list}.', 'a.pngPrivate': 'Non-standard PNG chunks: {list}. They may carry hidden data.', 'a.pngText': 'It carries {n} embedded texts (tEXt/zTXt/iTXt).',
      'a.gps': 'The photo has GPS coordinates: it reveals where it was taken.', 'a.author': 'It carries personal or device data: {list}.',
      'a.comment': 'It has comments embedded in the image.',
      'a.pdfJs': 'The PDF has JavaScript ({list}): review it before opening it in a reader that runs it.', 'a.pdfLaunch': 'The PDF can launch programs or open files (/Launch).',
      'a.pdfEmbedded': 'The PDF carries attached files (/EmbeddedFile).', 'a.pdfEnc': 'The PDF is encrypted.', 'a.pdfUpdates': 'The PDF was modified {n} times after it was created (incremental updates): the earlier versions are still inside.',
      'a.macros': 'The document contains macros (vbaProject.bin).', 'a.external': 'The document loads external resources: {list}. It is the “remote template” technique to sneak in macros.',
      'a.zipEnc': 'The ZIP has encrypted entries ({kind}).', 'a.zipEncWeak': 'ZipCrypto, weak: attack it with john/hashcat or with known plaintext (bkcrack)', 'a.zipEncAes': 'AES',
      'a.packed': 'The executable looks packed ({list}): the real code is compressed or encrypted.', 'a.highEntropySection': 'Sections with very high entropy: {list}.',
      'a.secrets': 'There may be secrets in clear text: {list}.', 'a.flag': 'Possible CTF flag: {v}', 'a.stego': 'Readable data in the least significant bits ({combo}): “{text}”.',
      'a.chi': 'The chi-square attack indicates LSB embedding in ~{p}% of the image (RGB channels, probability {prob}).',
      'a.highEntropy': 'Very high entropy ({e}) for a {type}: it could be encrypted or carry compressed data inside.',
      'm.none': 'No recognisable metadata was found for this file type.', 'm.strip': 'Download without metadata', 'm.stripDone': '{n} metadata blocks removed{tr}. The image is not recompressed: the pixels are identical.', 'm.stripTr': ' and {size} appended at the end',
      'm.orient': 'Note: the photo has EXIF orientation {o}; without metadata some viewers will show it rotated.', 'm.stripNo': 'Metadata can only be removed from JPEG and PNG.',
      'm.map': 'View on OpenStreetMap', 'm.thumb': 'EXIF thumbnail', 'm.exifErr': 'The EXIF/XMP metadata could not be read.',
      'm.pngText': 'PNG texts', 'm.keyword': 'Key', 'm.value': 'Value', 'm.comments': 'Comments', 'm.pdfInfo': '/Info dictionary', 'm.pdfXmp': 'XMP', 'm.pdfid': 'Active elements (like pdfid)',
      'm.pdfPages': '{n} pages · PDF {v} · {u} incremental updates', 'm.office': 'Document properties', 'm.zipT': 'ZIP contents ({n} entries)', 'm.zipName': 'Name', 'm.zipSize': 'Size', 'm.zipComp': 'Compressed',
      'm.zipMod': 'Modified', 'm.zipEnc': 'Encrypted', 'm.zipComment': 'ZIP comment', 'm.peT': 'Windows executable (PE)', 'm.elfT': 'ELF executable', 'm.sections': 'Sections',
      'm.machine': 'Architecture', 'm.compiled': 'Compiled', 'm.subsystem': 'Subsystem', 'm.dll': 'Library (DLL)', 'm.bits': 'Bits', 'm.endian': 'Byte order', 'm.elfType': 'Type',
      'm.sName': 'Name', 'm.sV': 'Virtual size', 'm.sR': 'On disk', 'm.sE': 'Entropy', 'm.sF': 'Permissions', 'm.dims': 'Dimensions', 'm.frames': 'Frames', 'm.bpp': 'Bits per pixel',
      'mk.title': 'Title', 'mk.subject': 'Subject', 'mk.author': 'Author', 'mk.lastModifiedBy': 'Last modified by', 'mk.created': 'Created', 'mk.modified': 'Modified', 'mk.lastPrinted': 'Printed', 'mk.revision': 'Revision',
      'mk.keywords': 'Keywords', 'mk.description': 'Description', 'mk.category': 'Category', 'mk.application': 'Application', 'mk.appVersion': 'Version', 'mk.company': 'Company', 'mk.manager': 'Manager',
      'mk.template': 'Template', 'mk.totalTime': 'Editing time', 'mk.pages': 'Pages', 'mk.words': 'Words', 'mk.macros': 'Macros', 'mk.external': 'External resources',
      's.trailerT': 'Data after the end', 's.embT': 'File signatures inside', 's.embNone': 'There are no embedded file signatures.', 's.thumb': 'EXIF thumbnail', 's.inZip': 'inside the ZIP', 's.inApp': 'inside {app}',
      's.chunks': 'PNG chunks', 's.crcOk': 'CRC OK', 's.crcBad': 'BAD CRC', 's.private': 'non-standard', 's.fixT': 'Repair the header', 's.fix': 'The stored CRC matches {w}×{h} (it now says {cw}×{ch}).', 's.fixDl': 'Download repaired PNG', 's.fixNo': 'No size matching the CRC was found (up to 16384 px per side).',
      's.segs': 'JPEG segments', 's.len': 'Length', 's.noTrailer': 'There is no data after the end of the file.', 's.trailerEnd': 'The format does not tell where it ends: appended data is not checked.',
      'g.noImage': 'LSB steganography can only be analysed in images the browser can open.', 'g.jpeg': 'JPEG is lossy: the least significant bits of its pixels do not keep data. The usual JPEG tool is steghide (try it offline with steghide or stegseek). The bit planes are still shown, as they sometimes reveal visual marks.',
      'g.canvas': 'This image is decoded by the browser: with transparency or colour profiles the low bits may not be exact. PNGs are read with our own decoder, exact bit by bit.',
      'g.planes': 'Bit planes', 'g.channel': 'Channel', 'g.bit': 'Bit', 'g.ones': '{p}% ones', 'g.scanT': 'Automatic search (like zsteg)', 'g.scanNone': 'No usual combination gives readable text or a file signature.',
      'g.combo': 'Combination', 'g.result': 'Result', 'g.manualT': 'Manual extraction', 'g.channels': 'Channels (order)', 'g.bits': 'Bits (e.g. 0 or 1,0)', 'g.order': 'Traversal', 'g.row': 'by rows', 'g.col': 'by columns',
      'g.bitOrder': 'Bit order', 'g.msb': 'MSB first', 'g.lsb': 'LSB first', 'g.bytes': 'Bytes', 'g.extract': 'Extract', 'g.chiT': 'Chi-square attack (Westfeld)', 'g.chiNote': 'Probability that the LSBs of the RGB channels hold random data, accumulating from the start of the image. Close to 1 = embedded data; close to 0 = clean image.',
      'g.upTo': 'Up to {p}%', 'g.text': 'text', 'g.file': '{t} file', 'g.palette': 'Palette image: bits are read from the converted colours. For the LSB of the palette index use the “index” channel.',
      'g.index': 'index',
      'st.min': 'Minimum length', 'st.enc': 'Encoding', 'st.all': 'all', 'st.filter': 'Filter', 'st.filterPh': 'text to filter…', 'st.count': '{n} strings', 'st.trunc': ' (cut at {n})',
      'st.export': 'Export .txt', 'st.searchT': 'Search (counts every occurrence)', 'st.searchPh': 'password, token, admin', 'st.regex': 'Regular expression', 'st.case': 'Case sensitive', 'st.search': 'Search',
      'st.term': 'Term', 'st.hits': 'Occurrences', 'st.inStrings': 'In strings', 'st.badRegex': 'invalid expression', 'st.bytesT': 'Search bytes (hex, ?? = wildcard)', 'st.bytesPh': 'FF D8 FF ?? 00 10', 'st.bytesRes': '{n} matches', 'st.bytesBad': 'Invalid hex pattern.',
      'st.compute': 'Extract strings', 'st.big': 'The file is large: strings are extracted on request.',
      'io.kind': 'Kind', 'io.value': 'Value', 'io.n': 'Times', 'io.none': 'No indicators were found.', 'io.export': 'Export JSON', 'io.private': 'private',
      'ik.flag': 'CTF flags', 'ik.privkey': 'Private keys', 'ik.aws': 'AWS keys', 'ik.gcp': 'Google keys', 'ik.github': 'GitHub tokens', 'ik.slack': 'Slack tokens', 'ik.stripe': 'Stripe keys', 'ik.jwt': 'JWT',
      'ik.url': 'URLs', 'ik.email': 'Emails', 'ik.ipv4': 'IPv4', 'ik.winpath': 'Windows paths', 'ik.unixpath': 'Unix paths', 'ik.registry': 'Windows registry', 'ik.pdb': 'PDB paths (developer machine)', 'ik.md5': '32-hex hashes', 'ik.sha1': '40-hex hashes', 'ik.sha256': '64-hex hashes', 'ik.base64': 'Base64 that decodes to text',
      'hx.go': 'Go', 'hx.prev': '◀ Previous', 'hx.next': 'Next ▶', 'hx.start': 'Start', 'hx.end': 'End', 'hx.offsetPh': 'offset (0x1A2B or 6699)',
    },
  });

  const TYPE_NAMES = { jpeg: 'JPEG', png: 'PNG', gif: 'GIF', webp: 'WebP', bmp: 'BMP', tiff: 'TIFF', heic: 'HEIC/HEIF', avif: 'AVIF', ico: 'ICO', psd: 'Photoshop PSD', jp2: 'JPEG 2000', svg: 'SVG',
    pdf: 'PDF', zip: 'ZIP', docx: 'Word (DOCX)', xlsx: 'Excel (XLSX)', pptx: 'PowerPoint (PPTX)', odf: 'OpenDocument', epub: 'EPUB', apk: 'Android APK', jar: 'Java JAR', rar: 'RAR', '7z': '7-Zip', gzip: 'GZIP',
    bzip2: 'BZIP2', xz: 'XZ', zstd: 'Zstandard', tar: 'TAR', ole: 'Office antiguo (OLE2: DOC/XLS/PPT/MSI)', pe: 'Ejecutable de Windows (PE)', dll: 'DLL de Windows', elf: 'ELF (Linux)', macho: 'Mach-O (macOS)', class: 'Clase Java',
    dex: 'Android DEX', wasm: 'WebAssembly', mp3: 'MP3', ogg: 'OGG', flac: 'FLAC', wav: 'WAV', avi: 'AVI', mkv: 'Matroska/WebM', mp4: 'MP4', mov: 'QuickTime MOV', m4a: 'M4A', '3gp': '3GP', cr3: 'Canon CR3',
    sqlite: 'SQLite', rtf: 'RTF', ps: 'PostScript', pcap: 'PCAP (captura de red)', pcapng: 'PCAPNG (captura de red)', lnk: 'Acceso directo de Windows (LNK)', ar: 'ar / paquete DEB', rpm: 'RPM', cab: 'CAB',
    iso: 'Imagen ISO', regf: 'Colmena del registro de Windows', evtx: 'Registro de eventos de Windows (EVTX)', mdmp: 'Volcado de memoria (minidump)', vmdk: 'Disco VMware (VMDK)', woff: 'WOFF', woff2: 'WOFF2', otf: 'OpenType',
    pem: 'PEM (clave o certificado)', sshkey: 'Clave privada OpenSSH', script: 'Script con shebang', xml: 'XML', html: 'HTML', json: 'JSON', text: 'Texto', unknown: null };
  // Los nombres descriptivos se traducen; las siglas (PNG, ZIP…) valen para los dos idiomas.
  IK.addI18n({ en: { 'ty.ole': 'Legacy Office (OLE2: DOC/XLS/PPT/MSI)', 'ty.pe': 'Windows executable (PE)', 'ty.dll': 'Windows DLL', 'ty.class': 'Java class', 'ty.pcap': 'PCAP (network capture)',
    'ty.pcapng': 'PCAPNG (network capture)', 'ty.lnk': 'Windows shortcut (LNK)', 'ty.ar': 'ar / DEB package', 'ty.iso': 'ISO image', 'ty.regf': 'Windows registry hive', 'ty.evtx': 'Windows event log (EVTX)',
    'ty.mdmp': 'Memory dump (minidump)', 'ty.vmdk': 'VMware disk (VMDK)', 'ty.pem': 'PEM (key or certificate)', 'ty.sshkey': 'OpenSSH private key', 'ty.script': 'Script with shebang', 'ty.text': 'Text' } });
  const typeName = (id) => (!id || id === 'unknown') ? t('file.unknownType') : (IK.lang() === 'en' && IK.has('ty.' + id) ? t('ty.' + id) : (TYPE_NAMES[id] || id));
  const IMG = new Set(['jpeg', 'png', 'gif', 'webp', 'bmp', 'ico', 'avif']);
  const EXIF_TYPES = new Set(['jpeg', 'tiff', 'heic', 'avif', 'png', 'webp']);
  const COMPRESSED = new Set(['zip', 'docx', 'xlsx', 'pptx', 'odf', 'epub', 'apk', 'jar', 'rar', '7z', 'gzip', 'bzip2', 'xz', 'zstd', 'jpeg', 'png', 'gif', 'webp', 'mp3', 'ogg', 'flac', 'mkv', 'mp4', 'mov', 'm4a', 'avif', 'heic', 'woff', 'woff2', 'pdf', 'cab', 'jp2', 'cr3', '3gp', 'avi']);

  // Pila de análisis anidados (archivo → ZIP pegado → entrada…)
  const stack = [];
  const cur = () => stack[stack.length - 1];

  async function openFile(file) {
    if (file.size > MAX) { $('fileOut').innerHTML = `<div class="notice bad">${esc(t('file.tooBig'))}</div>`; return; }
    $('fileOut').innerHTML = `<section class="panel"><span class="spin"></span> ${esc(t('file.reading'))}</section>`;
    const bytes = await IK.readFile(file);
    stack.length = 0;
    await push(bytes, file.name, file.type, null);
  }

  async function push(bytes, name, browserType, label) {
    const item = { bytes, name, browserType: browserType || '', label: label || name, res: null, alerts: [], strings: null, iocs: null, exif: null, img: null, hex: 0, stego: null, stripInfo: null };
    stack.push(item);
    $('fileOut').innerHTML = `<section class="panel"><span class="spin"></span> ${esc(t('file.reading'))}</section>`;
    try { item.res = await B.analyze(bytes, name); } catch (e) { $('fileOut').innerHTML = `<div class="notice bad">${esc(IK.errText(e))}</div>`; return; }
    renderCrumbs();
    render();
    // Etapas que se completan después (y van añadiendo hallazgos)
    hashes(item);
    if (EXIF_TYPES.has(item.res.detect.type)) readExif(item);
    if (bytes.length <= AUTO_STRINGS) setTimeout(() => computeStrings(item), 30);
    if (IMG.has(item.res.detect.type)) loadImage(item);
  }

  function renderCrumbs() {
    const box = $('fileCrumbs');
    if (stack.length < 2) { box.hidden = true; box.innerHTML = ''; return; }
    box.hidden = false;
    box.innerHTML = stack.map((s, i) => i < stack.length - 1 ? `<button type="button" data-crumb="${i}">${esc(s.label)}</button> <span class="muted">›</span>` : `<b>${esc(s.label)}</b>`).join(' ');
  }

  // ───────────── Hallazgos ─────────────
  function computeAlerts(it) {
    const r = it.res, A = [];
    const add = (level, key, vars) => A.push({ level, key, vars });
    const d = r.detect;
    if (d.type === 'unknown') add('info', 'a.unknown');
    if (d.mismatch) add('bad', 'a.mismatch', { ext: d.ext, type: typeName(d.type), exp: d.expectedExt.filter(Boolean).slice(0, 4).map(e => '.' + e).join(', ') || '—' });
    if (r.trailer) {
      if (r.trailer.zeros) add('info', 'a.trailerZeros', { size: IK.size(r.trailer.size) });
      else add(r.trailer.overlay ? 'warn' : 'bad', r.trailer.overlay ? 'a.overlay' : 'a.trailer', { size: IK.size(r.trailer.size), off: IK.hex(r.trailer.offset), kind: trailerKind(r.trailer) });
    }
    if (r.zipAppended) add('bad', 'a.zipAppended', { n: r.zipAppended.total, type: typeName(d.type) });
    const emb = r.embedded.filter(h => !h.inside && !(h.inZip && r.zip) && !(r.trailer && h.offset === r.trailer.offset));
    if (emb.length) add('warn', 'a.embedded', { n: emb.length });
    if (r.embedded.some(h => h.inside === 'thumbnail')) add('info', 'a.thumb');
    if (r.png) {
      const ih = r.png.chunks.find(c => c.type === 'IHDR');
      if (ih && !ih.crcOk) { add('bad', 'a.crc'); if (r.png.ihdrFix && !r.png.ihdrFix.notFound) add('ok', 'a.crcFix', { w: r.png.ihdrFix.width, h: r.png.ihdrFix.height }); }
      const badc = r.png.chunks.filter(c => c.type !== 'IHDR' && c.crcOk === false).map(c => c.type);
      if (badc.length) add('warn', 'a.crcBad', { list: Array.from(new Set(badc)).join(', ') });
      if (r.png.unknown.length) add('warn', 'a.pngPrivate', { list: r.png.unknown.join(', ') });
      if (r.png.texts.length) add('info', 'a.pngText', { n: r.png.texts.length });
    }
    if ((r.jpeg && r.jpeg.comments.length) || (r.gif && r.gif.comments.length)) add('info', 'a.comment');
    if (r.pdf) {
      const c = r.pdf.counts;
      const js = ['/JavaScript', '/JS', '/OpenAction', '/AA'].filter(k => c[k]);
      if (c['/JavaScript'] || c['/JS']) add('bad', 'a.pdfJs', { list: js.join(', ') });
      if (c['/Launch']) add('bad', 'a.pdfLaunch');
      if (c['/EmbeddedFile']) add('warn', 'a.pdfEmbedded');
      if (c['/Encrypt']) add('info', 'a.pdfEnc');
      if (r.pdf.updates > 0) add('info', 'a.pdfUpdates', { n: r.pdf.updates });
    }
    if (r.office) {
      if (r.office.macros) add('bad', 'a.macros');
      if (r.office.external.length) add('bad', 'a.external', { list: r.office.external.slice(0, 3).join(', ') });
      const who = r.office.fields.filter(f => ['author', 'lastModifiedBy', 'company', 'manager'].includes(f.key)).map(f => `${t('mk.' + f.key)}: ${f.value}`);
      if (who.length) add('warn', 'a.author', { list: who.join(' · ') });
    }
    const z = r.zip || r.zipAppended;
    if (z && z.encrypted) add('info', 'a.zipEnc', { kind: z.aes ? t('a.zipEncAes') : t('a.zipEncWeak') });
    if (r.pe) {
      if (r.pe.packed) add('warn', 'a.packed', { list: r.pe.sections.map(s => s.name).join(', ') });
      const hi = r.pe.sections.filter(s => s.entropy > 7.2).map(s => `${s.name} (${s.entropy})`);
      if (hi.length && !r.pe.packed) add('info', 'a.highEntropySection', { list: hi.join(', ') });
    }
    if (it.exif) {
      if (it.exif.gps) add('bad', 'a.gps');
      const who = [];
      const e = it.exif.flat;
      for (const k of ['Artist', 'Copyright', 'OwnerName', 'CameraOwnerName', 'BodySerialNumber', 'SerialNumber', 'LensSerialNumber', 'XPAuthor', 'creator', 'Creator', 'By-line', 'HostComputer']) if (e[k]) who.push(`${k}: ${String(e[k]).slice(0, 60)}`);
      if (e.Make || e.Model) who.push(e.Model && e.Make && String(e.Model).toLowerCase().startsWith(String(e.Make).toLowerCase()) ? String(e.Model) : [e.Make, e.Model].filter(Boolean).join(' '));
      if (who.length) add('warn', 'a.author', { list: who.join(' · ') });
    }
    if (it.iocs) {
      const sec = it.iocs.secrets;
      if (sec.length) add('bad', 'a.secrets', { list: sec.map(k => `${t('ik.' + k)} (${it.iocs.found[k].length})`).join(', ') });
      if (it.iocs.found.flag) for (const f of it.iocs.found.flag.slice(0, 3)) add('ok', 'a.flag', { v: f.value });
    }
    if (it.stego && it.stego.scan) for (const s of it.stego.scan.filter(x => x.kind === 'text' && x.score >= 60).slice(0, 2)) add('bad', 'a.stego', { combo: comboLabel(s), text: s.text.slice(0, 60) });
    if (it.stego && it.stego.chi && it.stego.chi.first > 0.95) add('warn', 'a.chi', { p: Math.round(it.stego.chi.extent * 100), prob: it.stego.chi.first.toFixed(2) });
    if (r.entropy > 7.6 && !COMPRESSED.has(d.type) && d.type !== 'unknown' && !(r.pe)) add('warn', 'a.highEntropy', { e: r.entropy.toFixed(2), type: typeName(d.type) });
    const order = { bad: 0, warn: 1, ok: 2, info: 3 };
    it.alerts = A.sort((a, b) => order[a.level] - order[b.level]);
  }
  function trailerKind(tr) {
    if (tr.type && tr.type !== 'unknown') return typeName(tr.type);
    return `«${tr.preview.slice(0, 40)}» (${t('file.entropy').toLowerCase()} ${tr.entropy})`;
  }
  function renderAlerts() {
    const it = cur(); if (!it) return;
    computeAlerts(it);
    const box = $('ikAlerts'); if (!box) return;
    box.innerHTML = it.alerts.length ? it.alerts.map(a => `<div class="alert"><span class="lvl ${a.level}">${esc(t('lvl.' + a.level))}</span><p>${esc(t(a.key, a.vars))}</p></div>`).join('') : `<p class="muted">${esc(t('file.noAlerts'))}</p>`;
  }

  // ───────────── Render principal ─────────────
  function entropyText(e) { return e < 1 ? t('file.e0') : e < 5.5 ? t('file.e1') : e < 7.5 ? t('file.e2') : t('file.e3'); }
  function render() {
    const it = cur(); if (!it) return;
    const r = it.res, d = r.detect;
    const extLine = !d.ext ? t('file.extNone') : d.mismatch ? `.${d.ext} ✘` : d.type === 'unknown' ? `.${d.ext}` : `.${d.ext} — ${t('file.extOk')}`;
    $('fileOut').innerHTML = `
      <section class="panel">
        <div class="panel-title">${esc(t('file.sumT'))}</div>
        <div class="grid2">
          <dl class="kv">
            <dt>${esc(t('file.name'))}</dt><dd>${esc(it.name)}</dd>
            <dt>${esc(t('file.size'))}</dt><dd>${esc(IK.size(r.size))} <span class="muted">(${esc(IK.num(r.size))} B)</span></dd>
            <dt>${esc(t('file.real'))}</dt><dd><b>${esc(typeName(d.type))}</b> <span class="muted mono small">${esc(d.mime)}</span></dd>
            ${it.browserType ? `<dt>${esc(t('file.browser'))}</dt><dd class="mono">${esc(it.browserType)}</dd>` : ''}
            <dt>${esc(t('file.ext'))}</dt><dd>${d.mismatch ? `<span class="lvl bad">✘</span> ` : ''}${esc(extLine)}</dd>
            <dt>${esc(t('file.entropy'))}</dt><dd>${r.entropy.toFixed(3)} / 8 · <span class="muted">${esc(entropyText(r.entropy))}</span></dd>
          </dl>
          <div>
            <span class="label">${esc(t('file.entMap'))}</span>
            <canvas class="spark" id="ikSpark" width="600" height="60"></canvas>
          </div>
        </div>
        <div style="margin-top:12px"><span class="label">${esc(t('file.hashes'))}</span><div id="ikHashes"><span class="spin"></span></div></div>
      </section>
      <section class="panel"><div class="panel-title">${esc(t('file.alertsT'))}</div><div class="alerts" id="ikAlerts"></div></section>
      <details class="sec" id="secMeta" open><summary>${esc(t('file.metaT'))}</summary><div class="body" id="ikMeta"></div></details>
      <details class="sec" id="secStruct"><summary>${esc(t('file.structT'))} <span class="count" id="ikStructCount"></span></summary><div class="body" id="ikStruct"></div></details>
      ${IMG.has(d.type) ? `<details class="sec" id="secStego"><summary>${esc(t('file.stegoT'))}</summary><div class="body" id="ikStego"><span class="spin"></span></div></details>` : ''}
      <details class="sec" id="secStr"><summary>${esc(t('file.strT'))} <span class="count" id="ikStrCount"></span></summary><div class="body" id="ikStr"></div></details>
      <details class="sec" id="secIoc"><summary>${esc(t('file.iocT'))} <span class="count" id="ikIocCount"></span></summary><div class="body" id="ikIoc"></div></details>
      <details class="sec" id="secHex"><summary>${esc(t('file.hexT'))}</summary><div class="body" id="ikHex"></div></details>`;
    drawSpark(it);
    renderHashes(it);
    renderMeta(it);
    renderStruct(it);
    renderStrings(it);
    renderIocs(it);
    renderHex(it);
    renderStego(it);
    renderAlerts();
    const struct = r.trailer || r.zipAppended || (r.png && r.png.chunks.some(c => c.crcOk === false || (!c.known && !c.broken))) || r.embedded.some(h => !h.inside && !h.inZip);
    if (struct) $('secStruct').open = true;
  }

  function drawSpark(it) {
    const cv = $('ikSpark'); if (!cv) return;
    const ctx = cv.getContext('2d');
    const { blocks } = B.entropyBlocks(it.bytes, 150);
    const css = getComputedStyle(document.documentElement);
    const col = (e) => e > 7.5 ? css.getPropertyValue('--bad') : e > 5.5 ? css.getPropertyValue('--warn') : css.getPropertyValue('--accent');
    ctx.clearRect(0, 0, cv.width, cv.height);
    const w = cv.width / blocks.length;
    blocks.forEach((b, i) => { const h = Math.max(1, (b.e / 8) * (cv.height - 4)); ctx.fillStyle = col(b.e).trim(); ctx.fillRect(i * w, cv.height - h, Math.max(1, w - 0.5), h); });
  }

  async function hashes(it) {
    try { it.hashes = await IKHash.all(it.bytes); } catch (e) { it.hashes = null; }
    if (cur() === it) renderHashes(it);
  }
  function renderHashes(it) {
    const box = $('ikHashes'); if (!box) return;
    if (!it.hashes) { box.innerHTML = '<span class="spin"></span>'; return; }
    box.innerHTML = `<div class="tbl-wrap"><table class="tbl"><tbody>${['MD5', 'SHA-1', 'SHA-256'].map(a => `<tr><td class="k mono">${a}</td><td class="mono">${esc(it.hashes[a])}</td><td><button class="btn ghost small" type="button" data-copy="${esc(it.hashes[a])}">${esc(t('c.copy'))}</button></td></tr>`).join('')}</tbody></table></div>
      <div class="btns" style="margin-top:8px"><button class="btn ghost small" type="button" data-act="toHash">${esc(t('file.verify'))}</button></div>`;
  }

  // ───────────── Metadatos ─────────────
  async function readExif(it) {
    const opts = { tiff: true, ifd0: true, ifd1: true, exif: true, gps: true, interop: false, xmp: true, iptc: true, icc: false, jfif: false, ihdr: false, makerNote: false, userComment: true, translateKeys: true, translateValues: true, reviveValues: true, mergeOutput: false };
    const ex = { blocks: null, gps: null, thumb: null, flat: {}, error: false };
    try {
      ex.blocks = await exifr.parse(it.bytes, opts);
      if (ex.blocks) for (const blk of Object.values(ex.blocks)) if (blk && typeof blk === 'object') Object.assign(ex.flat, blk);
      try { const g = await exifr.gps(it.bytes); if (g && Number.isFinite(g.latitude) && Number.isFinite(g.longitude)) ex.gps = g; } catch (e) { /* sin GPS */ }
      try { const th = await exifr.thumbnail(it.bytes); if (th && th.length) ex.thumb = URL.createObjectURL(new Blob([th], { type: 'image/jpeg' })); } catch (e) { /* sin miniatura */ }
    } catch (e) { ex.error = !/Unknown file format|Unsupported|No .* found/i.test(String(e && e.message)); }
    it.exif = ex;
    if (cur() === it) { renderMeta(it); renderAlerts(); }
  }

  function fmtVal(v) {
    if (v == null) return '';
    if (v instanceof Date) return isNaN(v) ? String(v) : v.toISOString().replace('T', ' ').replace(/\.000Z$/, ' (UTC)').replace('Z', '');
    if (v instanceof Uint8Array || ArrayBuffer.isView(v)) { const a = Array.from(v.slice(0, 32)); return a.map(x => x.toString(16).padStart(2, '0')).join(' ') + (v.length > 32 ? ` … (${v.length} B)` : ''); }
    if (Array.isArray(v)) return v.map(fmtVal).join(', ');
    if (typeof v === 'object') { try { return JSON.stringify(v); } catch (e) { return String(v); } }
    return String(v);
  }
  const kvTable = (rows) => `<div class="tbl-wrap"><table class="tbl"><tbody>${rows.map(([k, v, mono]) => `<tr><td class="k">${esc(k)}</td><td class="${mono ? 'mono' : ''}">${esc(v)}</td></tr>`).join('')}</tbody></table></div>`;

  function renderMeta(it) {
    const box = $('ikMeta'); if (!box) return;
    const r = it.res, parts = [];
    const ex = it.exif;
    if (ex && ex.blocks) {
      if (ex.gps) {
        const lat = ex.gps.latitude.toFixed(6), lon = ex.gps.longitude.toFixed(6);
        parts.push(`<div class="notice bad"><b>GPS</b> ${esc(lat)}, ${esc(lon)} · <a href="https://www.openstreetmap.org/?mlat=${encodeURIComponent(lat)}&mlon=${encodeURIComponent(lon)}#map=16/${encodeURIComponent(lat)}/${encodeURIComponent(lon)}" target="_blank" rel="noopener noreferrer">${esc(t('m.map'))}</a></div>`);
      }
      for (const [name, blk] of Object.entries(ex.blocks)) {
        if (!blk || typeof blk !== 'object') continue;
        const rows = Object.entries(blk).filter(([k]) => k !== 'thumbnail').map(([k, v]) => [k, fmtVal(v), typeof v !== 'string']);
        if (rows.length) parts.push(`<div><span class="label">${esc(name.toUpperCase())}</span>${kvTable(rows)}</div>`);
      }
      if (ex.thumb) parts.push(`<div><span class="label">${esc(t('m.thumb'))}</span><img src="${ex.thumb}" alt="${esc(t('m.thumb'))}" style="max-width:220px;border:1px solid var(--border);border-radius:4px"></div>`);
    } else if (ex && ex.error) parts.push(`<p class="muted">${esc(t('m.exifErr'))}</p>`);
    if (r.png && r.png.texts.length) parts.push(`<div><span class="label">${esc(t('m.pngText'))}</span><div class="tbl-wrap"><table class="tbl"><thead><tr><th>${esc(t('m.keyword'))}</th><th>${esc(t('m.value'))}</th><th></th></tr></thead><tbody>
      ${r.png.texts.map(x => `<tr><td class="k mono">${esc(x.type)} · ${esc(x.keyword)}</td><td class="mono">${esc((x.text || '').slice(0, 2000))}</td><td><button class="btn ghost small" type="button" data-cipher="${esc(x.text || '')}">${esc(t('c.toCipher'))}</button></td></tr>`).join('')}</tbody></table></div></div>`);
    if (r.png && r.png.ihdr) parts.push(kvTable([[t('m.dims'), `${r.png.ihdr.width} × ${r.png.ihdr.height}`], ['IHDR', `bit depth ${r.png.ihdr.bitDepth} · color type ${r.png.ihdr.colorType}${r.png.ihdr.interlace ? ' · Adam7' : ''}`], ...r.png.chunks.filter(c => c.time).map(c => ['tIME', c.time])]));
    const comments = (r.jpeg && r.jpeg.comments) || (r.gif && r.gif.comments) || [];
    if (comments.length) parts.push(`<div><span class="label">${esc(t('m.comments'))}</span>${comments.map(c => `<pre class="out">${esc(c)}</pre>`).join('')}</div>`);
    if (r.gif) parts.push(kvTable([[t('m.dims'), `${r.gif.width} × ${r.gif.height}`], [t('m.frames'), r.gif.frames]]));
    if (r.jpeg && r.jpeg.width) parts.push(kvTable([[t('m.dims'), `${r.jpeg.width} × ${r.jpeg.height}`]]));
    if (r.bmp) parts.push(kvTable([[t('m.dims'), `${r.bmp.width} × ${r.bmp.height}`], [t('m.bpp'), r.bmp.bpp]]));
    if (r.pdf) {
      const p = r.pdf;
      parts.push(`<p class="muted">${esc(t('m.pdfPages', { n: p.pages, v: p.version || '?', u: p.updates }))}</p>`);
      if (p.fields.length) parts.push(`<div><span class="label">${esc(t('m.pdfInfo'))}</span>${kvTable(p.fields.map(f => [f.key, f.value]))}</div>`);
      if (p.xmpFields.length) parts.push(`<div><span class="label">${esc(t('m.pdfXmp'))}</span>${kvTable(p.xmpFields.map(f => [f.key, f.value]))}</div>`);
      const RISK = { '/JavaScript': 'bad', '/JS': 'bad', '/Launch': 'bad', '/OpenAction': 'warn', '/AA': 'warn', '/EmbeddedFile': 'warn', '/RichMedia': 'warn', '/XFA': 'warn', '/SubmitForm': 'warn', '/GoToR': 'warn', '/JBIG2Decode': 'warn', '/URI': 'info', '/AcroForm': 'info', '/Encrypt': 'info', '/ObjStm': 'info' };
      const c = Object.entries(p.counts);
      if (c.length) parts.push(`<div><span class="label">${esc(t('m.pdfid'))}</span><div class="tbl-wrap"><table class="tbl"><tbody>${c.map(([k, n]) => `<tr><td class="k mono">${esc(k)}</td><td>${n}</td><td><span class="lvl ${RISK[k] || 'info'}">${esc(t('lvl.' + (RISK[k] || 'info')))}</span></td></tr>`).join('')}</tbody></table></div></div>`);
    }
    if (r.office) {
      const rows = r.office.fields.map(f => [t('mk.' + f.key), f.value]);
      rows.push([t('mk.macros'), r.office.macros ? t('c.yes') : t('c.no')]);
      if (r.office.external.length) rows.push([t('mk.external'), r.office.external.join('\n'), true]);
      parts.push(`<div><span class="label">${esc(t('m.office'))}</span>${kvTable(rows)}</div>`);
    }
    const z = r.zip || r.zipAppended;
    if (z) parts.push(zipTable(z, !!r.zipAppended));
    if (r.pe) {
      const p = r.pe;
      parts.push(`<div><span class="label">${esc(t('m.peT'))}</span>${kvTable([[t('m.machine'), p.machine + (p.pe32plus ? ' (PE32+)' : ' (PE32)')], [t('m.compiled'), p.compiled || '—'], [t('m.subsystem'), p.subsystem], [t('m.dll'), p.dll ? t('c.yes') : t('c.no')]])}</div>`);
      parts.push(`<div><span class="label">${esc(t('m.sections'))}</span><div class="tbl-wrap"><table class="tbl"><thead><tr><th>${esc(t('m.sName'))}</th><th>${esc(t('m.sV'))}</th><th>${esc(t('m.sR'))}</th><th>${esc(t('m.sE'))}</th><th>${esc(t('m.sF'))}</th></tr></thead><tbody>
        ${p.sections.map(s => `<tr><td class="mono">${esc(s.name)}</td><td>${IK.num(s.vsize)}</td><td>${IK.num(s.rsize)}</td><td>${s.entropy}${s.entropy > 7.2 ? ' <span class="lvl warn">!</span>' : ''}</td><td class="mono">${s.exec ? 'X' : '-'}${s.write ? 'W' : '-'}</td></tr>`).join('')}</tbody></table></div></div>`);
    }
    if (r.elf) parts.push(`<div><span class="label">${esc(t('m.elfT'))}</span>${kvTable([[t('m.bits'), r.elf.bits], [t('m.endian'), r.elf.endian], [t('m.elfType'), r.elf.type], [t('m.machine'), r.elf.machine]])}</div>`);
    if (r.detect.type === 'jpeg' || r.detect.type === 'png') {
      const orient = it.exif && it.exif.flat && it.exif.flat.Orientation;
      parts.push(`<div class="btns"><button class="btn ghost" type="button" data-act="strip">${esc(t('m.strip'))}</button></div>${it.stripInfo ? `<div class="notice ok">${esc(it.stripInfo)}</div>` : ''}
        ${orient && !/horizontal \(normal\)|^1$/i.test(String(orient)) ? `<p class="muted small">${esc(t('m.orient', { o: orient }))}</p>` : ''}`);
    }
    if (!parts.length) parts.push(`<p class="muted">${esc(it.exif === null && EXIF_TYPES.has(r.detect.type) ? '…' : t('m.none'))}</p>`);
    box.innerHTML = parts.join('');
  }

  function zipTable(z, appended) {
    const rows = z.entries.slice(0, 500).map((e, i) => `<tr><td class="mono">${esc(e.name)}</td><td>${e.dir ? '' : IK.num(e.usize)}</td><td>${e.dir ? '' : IK.num(e.csize)}</td><td class="mono">${esc(e.modified)}</td>
      <td>${e.encrypted ? `<span class="lvl warn">${e.aes ? 'AES' : 'ZipCrypto'}</span>` : ''}</td>
      <td>${!e.dir && !e.encrypted && (e.method === 0 || e.method === 8) ? `<div class="btns"><button class="btn ghost small" type="button" data-zip="${i}" data-zop="dl">${esc(t('c.download'))}</button><button class="btn ghost small" type="button" data-zip="${i}" data-zop="an">${esc(t('file.analyzeIt'))}</button></div>` : ''}</td></tr>`).join('');
    return `<div><span class="label">${esc(t('m.zipT', { n: z.total }))}${appended ? ' · ' + esc(IK.hex(z.offset)) : ''}</span><div class="tbl-wrap" style="max-height:420px"><table class="tbl"><thead><tr><th>${esc(t('m.zipName'))}</th><th>${esc(t('m.zipSize'))}</th><th>${esc(t('m.zipComp'))}</th><th>${esc(t('m.zipMod'))}</th><th>${esc(t('m.zipEnc'))}</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>
      ${z.comment ? `<p class="small" style="margin-top:6px"><b>${esc(t('m.zipComment'))}:</b> <span class="mono">${esc(z.comment)}</span></p>` : ''}</div>`;
  }

  // ───────────── Estructura ─────────────
  function renderStruct(it) {
    const box = $('ikStruct'); if (!box) return;
    const r = it.res, parts = [];
    const ends = r.jpeg || r.png || r.gif || r.pdf || r.zip || r.bmp || r.pe;
    if (r.trailer) {
      const tr = r.trailer;
      parts.push(`<div><span class="label">${esc(t('s.trailerT'))}</span>${kvTable([[t('file.offset'), `${IK.hex(tr.offset)} (${IK.num(tr.offset)})`, true], [t('file.size'), IK.size(tr.size)], [t('file.type'), tr.zeros ? '00…' : trailerKind(tr)]])}
        ${tr.zeros ? '' : `<pre class="out" style="margin-top:6px">${esc(B.hexdump(it.bytes, tr.offset, 128))}</pre>
        <div class="btns" style="margin-top:6px"><button class="btn ghost small" type="button" data-cut="${tr.offset}" data-cutend="${it.bytes.length}" data-op="dl">${esc(t('c.download'))}</button><button class="btn ghost small" type="button" data-cut="${tr.offset}" data-cutend="${it.bytes.length}" data-op="an">${esc(t('file.analyzeIt'))}</button><button class="btn ghost small" type="button" data-cut="${tr.offset}" data-cutend="${it.bytes.length}" data-op="ci">${esc(t('c.toCipher'))}</button></div>`}</div>`);
    } else parts.push(`<p class="muted">${esc(ends ? t('s.noTrailer') : t('s.trailerEnd'))}</p>`);
    if (r.png) {
      const ih = r.png.chunks.find(c => c.type === 'IHDR');
      if (ih && !ih.crcOk) {
        const f = r.png.ihdrFix;
        parts.push(`<div class="notice bad"><b>${esc(t('s.fixT'))}.</b> ${esc(f && !f.notFound ? t('s.fix', { w: f.width, h: f.height, cw: r.png.ihdr.width, ch: r.png.ihdr.height }) : t('s.fixNo'))}
          ${f && !f.notFound ? `<div class="btns" style="margin-top:8px"><button class="btn small" type="button" data-act="fixDl">${esc(t('s.fixDl'))}</button><button class="btn ghost small" type="button" data-act="fixAn">${esc(t('file.analyzeIt'))}</button></div>` : ''}</div>`);
      }
      parts.push(`<div><span class="label">${esc(t('s.chunks'))}</span><div class="tbl-wrap" style="max-height:380px"><table class="tbl"><thead><tr><th>${esc(t('file.type'))}</th><th>${esc(t('file.offset'))}</th><th>${esc(t('s.len'))}</th><th>CRC</th></tr></thead><tbody>
        ${compactChunks(r.png.chunks).map(c => `<tr><td class="mono">${esc(c.type)}${c.n > 1 ? ` ×${c.n}` : ''}${!c.known && !c.broken ? ` <span class="lvl warn">${esc(t('s.private'))}</span>` : ''}</td><td class="mono">${IK.hex(c.offset)}</td><td>${IK.num(c.length)}</td><td>${c.broken ? '<span class="lvl bad">?</span>' : c.crcOk ? `<span class="lvl ok">${esc(t('s.crcOk'))}</span>` : `<span class="lvl bad">${esc(t('s.crcBad'))}</span>`}</td></tr>`).join('')}</tbody></table></div></div>`);
    }
    if (r.jpeg) parts.push(`<div><span class="label">${esc(t('s.segs'))}</span><div class="tbl-wrap" style="max-height:320px"><table class="tbl"><thead><tr><th></th><th>${esc(t('file.offset'))}</th><th>${esc(t('s.len'))}</th><th>${esc(t('file.note'))}</th></tr></thead><tbody>
      ${r.jpeg.segments.map(s => `<tr><td class="mono">${esc(s.marker)}</td><td class="mono">${IK.hex(s.offset)}</td><td>${IK.num(s.length)}</td><td>${esc(s.app || (s.text != null ? s.text.slice(0, 80) : '') || (s.progressive ? 'progressive' : ''))}</td></tr>`).join('')}</tbody></table></div></div>`);
    const emb = r.embedded;
    const list = emb.map((h, i) => {
      const end = emb[i + 1] ? emb[i + 1].offset : it.bytes.length;
      const note = h.inside === 'thumbnail' ? t('s.thumb') : h.inside ? t('s.inApp', { app: h.inside }) : (h.inZip && (r.zip || (r.zipAppended && h.offset >= r.zipAppended.offset))) ? t('s.inZip') : '';
      return `<tr><td class="mono">${IK.hex(h.offset)}</td><td>${esc(typeName(h.type))}</td><td class="muted">${esc(note)}</td>
        <td><div class="btns"><button class="btn ghost small" type="button" data-cut="${h.offset}" data-cutend="${end}" data-op="dl">${esc(t('file.extract'))}</button><button class="btn ghost small" type="button" data-cut="${h.offset}" data-cutend="${end}" data-op="an">${esc(t('file.analyzeIt'))}</button></div></td></tr>`;
    }).join('');
    parts.push(`<div><span class="label">${esc(t('s.embT'))}</span>${emb.length ? `<div class="tbl-wrap" style="max-height:320px"><table class="tbl"><thead><tr><th>${esc(t('file.offset'))}</th><th>${esc(t('file.type'))}</th><th>${esc(t('file.note'))}</th><th></th></tr></thead><tbody>${list}</tbody></table></div>` : `<p class="muted">${esc(t('s.embNone'))}</p>`}</div>`);
    box.innerHTML = parts.join('');
    const n = (r.trailer && !r.trailer.zeros ? 1 : 0) + emb.filter(h => !h.inside && !h.inZip).length;
    $('ikStructCount').textContent = n ? `(${n})` : '';
  }
  function compactChunks(chunks) {
    const out = [];
    for (const c of chunks) {
      const last = out[out.length - 1];
      if (last && last.type === c.type && c.type === 'IDAT' && last.crcOk && c.crcOk) { last.n++; last.length += c.length; }
      else out.push(Object.assign({ n: 1 }, c));
    }
    return out;
  }

  // ───────────── Cadenas ─────────────
  function computeStrings(it) {
    const min = +((document.getElementById('stMin') || {}).value || 4);
    it.strings = B.strings(it.bytes, { min, max: 300000 });
    it.iocs = B.iocs(it.strings.list);
    it.strShown = 400;
    if (cur() === it) { renderStrings(it); renderIocs(it); renderAlerts(); }
  }
  function renderStrings(it) {
    const box = $('ikStr'); if (!box) return;
    if (!it.strings) {
      box.innerHTML = it.bytes.length > AUTO_STRINGS ? `<p class="muted">${esc(t('st.big'))}</p><div class="btns"><button class="btn" type="button" data-act="strings">${esc(t('st.compute'))}</button></div>` : '<span class="spin"></span>';
      return;
    }
    const prev = box.querySelector('#stFilter');
    const state = { min: (box.querySelector('#stMin') || {}).value || 4, enc: (box.querySelector('#stEnc') || {}).value || 'all', filter: prev ? prev.value : '' };
    box.innerHTML = `
      <div class="row">
        <div class="field" style="flex:0 1 130px"><label class="label" for="stMin">${esc(t('st.min'))}</label><input class="input" type="number" id="stMin" min="2" max="200" value="${esc(state.min)}"></div>
        <div class="field" style="flex:0 1 160px"><label class="label" for="stEnc">${esc(t('st.enc'))}</label><select class="select" id="stEnc"><option value="all">${esc(t('st.all'))}</option><option value="utf8">ASCII / UTF-8</option><option value="utf16le">UTF-16LE</option></select></div>
        <div class="field" style="flex:2 1 200px"><label class="label" for="stFilter">${esc(t('st.filter'))}</label><input class="input" id="stFilter" placeholder="${esc(t('st.filterPh'))}" value="${esc(state.filter)}" spellcheck="false"></div>
        <button class="btn ghost" type="button" data-act="strExport">${esc(t('st.export'))}</button>
      </div>
      <p class="muted small" id="stInfo"></p>
      <pre class="out" id="stList" style="max-height:420px"></pre>
      <div class="btns" id="stMoreBox"></div>
      <div class="panel-title" style="margin-top:6px">${esc(t('st.searchT'))}</div>
      <div class="row">
        <div class="field" style="flex:3 1 220px"><input class="input" id="stTerms" placeholder="${esc(t('st.searchPh'))}" spellcheck="false" value="${esc(it.lastTerms || '')}"></div>
        <label class="check"><input type="checkbox" id="stRegex"> ${esc(t('st.regex'))}</label>
        <label class="check"><input type="checkbox" id="stCase"> ${esc(t('st.case'))}</label>
        <button class="btn" type="button" data-act="strSearch">${esc(t('st.search'))}</button>
      </div>
      <div id="stSearchOut"></div>
      <div class="panel-title" style="margin-top:6px">${esc(t('st.bytesT'))}</div>
      <div class="row"><div class="field" style="flex:3 1 220px"><input class="input" id="stBytes" placeholder="${esc(t('st.bytesPh'))}" spellcheck="false"></div><button class="btn ghost" type="button" data-act="byteSearch">${esc(t('st.search'))}</button></div>
      <div id="stBytesOut"></div>`;
    $('stEnc').value = state.enc;
    $('stMin').addEventListener('change', () => { computeStrings(it); });
    $('stEnc').addEventListener('change', () => { it.strShown = 400; listStrings(it); });
    $('stFilter').addEventListener('input', () => { it.strShown = 400; listStrings(it); });
    listStrings(it);
  }
  function filteredStrings(it) {
    const enc = $('stEnc').value, f = $('stFilter').value.toLowerCase();
    return it.strings.list.filter(s => (enc === 'all' || s.enc === enc) && (!f || s.text.toLowerCase().includes(f)));
  }
  function listStrings(it) {
    const list = filteredStrings(it);
    const shown = list.slice(0, it.strShown);
    $('stList').innerHTML = shown.map(s => `<span class="muted" data-hexoff="${s.offset}" style="cursor:pointer">${s.offset.toString(16).padStart(8, '0')}</span> ${s.enc === 'utf16le' ? '<span class="lvl info">16</span> ' : ''}${esc(s.text.length > 400 ? s.text.slice(0, 400) + '…' : s.text)}`).join('\n');
    $('stInfo').textContent = t('st.count', { n: IK.num(list.length) }) + (it.strings.truncated ? t('st.trunc', { n: IK.num(it.strings.list.length) }) : '');
    $('ikStrCount').textContent = `(${IK.num(it.strings.list.length)})`;
    $('stMoreBox').innerHTML = list.length > it.strShown ? `<button class="btn ghost small" type="button" data-act="strMore">${esc(t('c.more'))} (${IK.num(list.length - it.strShown)})</button>` : '';
  }
  function searchStrings(it) {
    const terms = $('stTerms').value.split(',').map(s => s.trim()).filter(Boolean);
    it.lastTerms = $('stTerms').value;
    if (!terms.length) { $('stSearchOut').innerHTML = ''; return; }
    const res = B.search(it.strings.list, terms, { regex: $('stRegex').checked, caseSensitive: $('stCase').checked });
    $('stSearchOut').innerHTML = `<div class="tbl-wrap"><table class="tbl"><thead><tr><th>${esc(t('st.term'))}</th><th>${esc(t('st.hits'))}</th><th>${esc(t('st.inStrings'))}</th></tr></thead><tbody>
      ${res.map(r => `<tr><td class="mono">${esc(r.term)}</td><td>${r.error ? `<span class="lvl bad">${esc(t('st.badRegex'))}</span>` : `<b>${IK.num(r.count)}</b>`}</td><td>${r.error ? '' : `${IK.num(r.strings)}${r.hits.length ? `<pre class="out" style="max-height:160px;margin-top:4px">${r.hits.slice(0, 50).map(h => `<span class="muted" data-hexoff="${h.offset}" style="cursor:pointer">${h.offset.toString(16).padStart(8, '0')}</span> ${esc(h.text.slice(0, 200))}`).join('\n')}</pre>` : ''}`}</td></tr>`).join('')}</tbody></table></div>`;
  }
  function searchBytes(it) {
    const hits = B.searchBytes(it.bytes, $('stBytes').value, 500);
    $('stBytesOut').innerHTML = hits == null ? `<div class="notice warn">${esc(t('st.bytesBad'))}</div>` : `<p class="small">${esc(t('st.bytesRes', { n: hits.length }))}</p>${hits.length ? `<pre class="out" style="max-height:160px">${hits.map(o => `<span data-hexoff="${o}" style="cursor:pointer">${IK.hex(o, 8)}</span>`).join('  ')}</pre>` : ''}`;
  }

  // ───────────── Indicadores ─────────────
  const IOC_ORDER = ['flag', 'privkey', 'aws', 'gcp', 'github', 'slack', 'stripe', 'jwt', 'url', 'email', 'ipv4', 'winpath', 'unixpath', 'registry', 'pdb', 'base64', 'md5', 'sha1', 'sha256'];
  function renderIocs(it) {
    const box = $('ikIoc'); if (!box) return;
    if (!it.iocs) { box.innerHTML = it.strings === null && it.bytes.length > AUTO_STRINGS ? `<p class="muted">${esc(t('st.big'))}</p>` : '<span class="spin"></span>'; return; }
    const f = it.iocs.found;
    const kinds = IOC_ORDER.filter(k => f[k]);
    const total = kinds.reduce((a, k) => a + f[k].length, 0);
    $('ikIocCount').textContent = total ? `(${IK.num(total)})` : '';
    if (!kinds.length) { box.innerHTML = `<p class="muted">${esc(t('io.none'))}</p>`; return; }
    if (it.iocs.secrets.length || f.flag) $('secIoc').open = true;
    box.innerHTML = kinds.map(k => {
      const rows = f[k].slice(0, 200).map(v => {
        const toC = ['base64', 'jwt', 'flag'].includes(k), toH = ['md5', 'sha1', 'sha256'].includes(k);
        return `<tr><td class="mono">${esc(v.value.length > 300 ? v.value.slice(0, 300) + '…' : v.value)}${v.private ? ` <span class="lvl info">${esc(t('io.private'))}</span>` : ''}</td><td>${v.count}</td>
          <td><div class="btns"><button class="btn ghost small" type="button" data-copy="${esc(v.value)}">${esc(t('c.copy'))}</button>${toC ? `<button class="btn ghost small" type="button" data-cipher="${esc(v.value)}">${esc(t('c.toCipher'))}</button>` : ''}${toH ? `<button class="btn ghost small" type="button" data-hashid="${esc(v.value)}">${esc(t('c.toHash'))}</button>` : ''}</div></td></tr>`;
      }).join('');
      const lv = it.iocs.secrets.includes(k) ? 'bad' : k === 'flag' ? 'ok' : null;
      return `<div><span class="label">${lv ? `<span class="lvl ${lv}">!</span> ` : ''}${esc(t('ik.' + k))} (${f[k].length})</span><div class="tbl-wrap" style="max-height:260px"><table class="tbl"><tbody>${rows}</tbody></table></div></div>`;
    }).join('') + `<div class="btns"><button class="btn ghost small" type="button" data-act="iocExport">${esc(t('io.export'))}</button></div>`;
  }

  // ───────────── Hex ─────────────
  function renderHex(it) {
    const box = $('ikHex'); if (!box) return;
    box.innerHTML = `<div class="row"><div class="field" style="flex:1 1 200px"><input class="input" id="hxOff" placeholder="${esc(t('hx.offsetPh'))}" spellcheck="false"></div>
      <div class="btns"><button class="btn ghost small" type="button" data-hx="go">${esc(t('hx.go'))}</button><button class="btn ghost small" type="button" data-hx="start">${esc(t('hx.start'))}</button><button class="btn ghost small" type="button" data-hx="prev">${esc(t('hx.prev'))}</button><button class="btn ghost small" type="button" data-hx="next">${esc(t('hx.next'))}</button><button class="btn ghost small" type="button" data-hx="end">${esc(t('hx.end'))}</button></div></div>
      <pre class="out hex" id="hxOut"></pre>`;
    hexAt(it, it.hex);
  }
  function hexAt(it, off) {
    const page = 512;
    off = Math.max(0, Math.min(off, Math.max(0, it.bytes.length - 1))) & ~15;
    it.hex = off;
    const o = $('hxOut'); if (o) o.textContent = B.hexdump(it.bytes, off, page);
  }
  function jumpHex(off) {
    const it = cur();
    $('secHex').open = true;
    hexAt(it, off);
    $('secHex').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  // ───────────── Esteganografía ─────────────
  async function loadImage(it) {
    const type = it.res.detect.type;
    try {
      if (type === 'png') {
        const d = await IKPng.decode(it.bytes);
        it.img = { width: d.width, height: d.height, data: d.data, exact: true, indices: d.indices };
      } else {
        const blob = new Blob([it.bytes], { type: it.res.detect.mime });
        const bmp = await createImageBitmap(blob, { colorSpaceConversion: 'none', premultiplyAlpha: 'none' });
        const cv = document.createElement('canvas');
        cv.width = bmp.width; cv.height = bmp.height;
        const ctx = cv.getContext('2d', { willReadFrequently: true });
        ctx.drawImage(bmp, 0, 0);
        it.img = { width: bmp.width, height: bmp.height, data: ctx.getImageData(0, 0, bmp.width, bmp.height).data, exact: false };
      }
    } catch (e) { it.img = { error: true }; }
    if (it.img && !it.img.error && type !== 'jpeg' && it.img.width * it.img.height <= 25e6) {
      const px = imgPixels(it, 'rgba');
      it.stego = { scan: IKStego.scan(px, it.img.width, it.img.height), chi: IKStego.chiSquare(px, it.img.width, it.img.height) };
    } else it.stego = { scan: [], chi: null };
    if (cur() === it) { renderStego(it); renderAlerts(); if (it.stego.scan.some(s => s.score >= 60) || (it.stego.chi && it.stego.chi.first > 0.95)) $('secStego').open = true; }
  }
  // Para imágenes con paleta, el canal «índice» se expone como un canal R ficticio.
  function imgPixels(it, mode) {
    if (mode !== 'index' || !it.img.indices) return it.img.data;
    const px = new Uint8ClampedArray(it.img.width * it.img.height * 4);
    for (let i = 0; i < it.img.indices.length; i++) { px[i * 4] = px[i * 4 + 1] = px[i * 4 + 2] = it.img.indices[i]; px[i * 4 + 3] = 255; }
    return px;
  }
  const comboLabel = (s) => `${s.channels.toUpperCase()} · b${s.bits.join(',')} · ${s.order === 'col' ? t('g.col') : t('g.row')} · ${s.msbFirst ? 'MSB' : 'LSB'}`;
  function renderStego(it) {
    const box = $('ikStego'); if (!box) return;
    if (!it.img) { box.innerHTML = '<span class="spin"></span>'; return; }
    if (it.img.error) { box.innerHTML = `<p class="muted">${esc(t('g.noImage'))}</p>`; return; }
    const type = it.res.detect.type;
    const st = it.stego || { scan: [] };
    const scanRows = st.scan.map((s, i) => `<tr><td class="mono">${esc(comboLabel(s))}</td><td>${s.kind === 'file' ? esc(t('g.file', { t: typeName(s.type) })) : `<span class="mono">${esc(s.text.slice(0, 160))}</span>`}${s.flag ? ' <span class="lvl ok">flag</span>' : ''}</td>
      <td><div class="btns"><button class="btn ghost small" type="button" data-scan="${i}" data-sop="use">${esc(t('ci.use'))}</button></div></td></tr>`).join('');
    const chi = st.chi;
    box.innerHTML = `
      ${type === 'jpeg' ? `<div class="notice warn">${esc(t('g.jpeg'))}</div>` : ''}
      ${!it.img.exact && type !== 'jpeg' ? `<p class="muted small">${esc(t('g.canvas'))}</p>` : ''}
      ${it.img.indices ? `<p class="muted small">${esc(t('g.palette'))}</p>` : ''}
      <div class="grid2">
        <div>
          <span class="label">${esc(t('g.planes'))}</span>
          <div class="row" style="margin-bottom:8px">
            <div class="field" style="flex:0 1 140px"><label class="label" for="gCh">${esc(t('g.channel'))}</label><select class="select" id="gCh"><option value="r">R</option><option value="g">G</option><option value="b">B</option><option value="a">A</option>${it.img.indices ? `<option value="idx">${esc(t('g.index'))}</option>` : ''}</select></div>
            <div class="field" style="flex:1 1 160px"><label class="label" for="gBit">${esc(t('g.bit'))} <span id="gBitV">0</span></label><input type="range" id="gBit" min="0" max="7" value="0" style="width:100%;accent-color:var(--accent)"></div>
          </div>
          <canvas class="pix" id="gCanvas"></canvas>
          <p class="muted small" id="gOnes"></p>
        </div>
        <div>
          ${type !== 'jpeg' ? `<span class="label">${esc(t('g.scanT'))}</span>
          ${st.scan.length ? `<div class="tbl-wrap" style="max-height:260px"><table class="tbl"><thead><tr><th>${esc(t('g.combo'))}</th><th>${esc(t('g.result'))}</th><th></th></tr></thead><tbody>${scanRows}</tbody></table></div>` : `<p class="muted">${esc(t('g.scanNone'))}</p>`}
          ${chi ? `<span class="label" style="margin-top:12px">${esc(t('g.chiT'))}</span><p class="muted small">${esc(t('g.chiNote'))}</p>
            <div style="display:grid;grid-template-columns:auto 1fr auto;gap:3px 8px;align-items:center;font-size:.85rem">${chi.curve.filter((_, i) => i % 2 === 1).map(p => `<span class="mono muted">${esc(t('g.upTo', { p: Math.round(p.upTo * 100) }))}</span><div class="bar ${p.prob > 0.95 ? 'bad' : p.prob > 0.5 ? 'warn' : 'ok'}"><i style="width:${Math.max(2, p.prob * 100)}%"></i></div><span class="mono">${p.prob.toFixed(3)}</span>`).join('')}</div>` : ''}` : ''}
        </div>
      </div>
      ${type !== 'jpeg' ? `<span class="label">${esc(t('g.manualT'))}</span>
      <div class="row">
        <div class="field" style="flex:1 1 120px"><label class="label" for="gmCh">${esc(t('g.channels'))}</label><input class="input" id="gmCh" value="rgb" spellcheck="false"></div>
        <div class="field" style="flex:1 1 120px"><label class="label" for="gmBits">${esc(t('g.bits'))}</label><input class="input" id="gmBits" value="0" spellcheck="false"></div>
        <div class="field" style="flex:1 1 130px"><label class="label" for="gmOrd">${esc(t('g.order'))}</label><select class="select" id="gmOrd"><option value="row">${esc(t('g.row'))}</option><option value="col">${esc(t('g.col'))}</option></select></div>
        <div class="field" style="flex:1 1 130px"><label class="label" for="gmBo">${esc(t('g.bitOrder'))}</label><select class="select" id="gmBo"><option value="msb">${esc(t('g.msb'))}</option><option value="lsb">${esc(t('g.lsb'))}</option></select></div>
        <div class="field" style="flex:0 1 110px"><label class="label" for="gmN">${esc(t('g.bytes'))}</label><input class="input" type="number" id="gmN" value="512" min="1"></div>
        <label class="check"><input type="checkbox" id="gmIdx" ${it.img.indices ? '' : 'disabled'}> ${esc(t('g.index'))}</label>
        <button class="btn" type="button" data-act="lsb">${esc(t('g.extract'))}</button>
      </div>
      <div id="gmOut"></div>` : ''}`;
    drawPlane(it);
    $('gCh').addEventListener('change', () => drawPlane(it));
    $('gBit').addEventListener('input', () => { $('gBitV').textContent = $('gBit').value; drawPlane(it); });
  }
  function drawPlane(it) {
    const cv = $('gCanvas'); if (!cv || !it.img || it.img.error) return;
    const ch = $('gCh').value, bit = +$('gBit').value;
    const w = it.img.width, h = it.img.height;
    const px = ch === 'idx' ? imgPixels(it, 'index') : it.img.data;
    const plane = IKStego.bitPlane(px, w, h, ch === 'idx' ? 'r' : ch, bit);
    cv.width = w; cv.height = h;
    cv.getContext('2d').putImageData(new ImageData(plane.data, w, h), 0, 0);
    $('gOnes').textContent = t('g.ones', { p: (plane.ones * 100).toFixed(1) });
  }
  function manualLsb(it, preset) {
    if (preset) { $('gmCh').value = preset.channels; $('gmBits').value = preset.bits.join(','); $('gmOrd').value = preset.order; $('gmBo').value = preset.msbFirst ? 'msb' : 'lsb'; }
    const channels = $('gmCh').value.toLowerCase().replace(/[^rgba]/g, '') || 'rgb';
    const bits = $('gmBits').value.split(/[\s,]+/).map(Number).filter(n => n >= 0 && n <= 7);
    const useIdx = $('gmIdx').checked && it.img.indices;
    const px = useIdx ? imgPixels(it, 'index') : it.img.data;
    const data = IKStego.extract(px, it.img.width, it.img.height, { channels: useIdx ? 'r' : channels, bits: bits.length ? bits : [0], order: $('gmOrd').value, msbFirst: $('gmBo').value === 'msb', maxBytes: Math.max(1, +$('gmN').value || 512) });
    it.lsbOut = data;
    const kind = B.detect(data).type;
    // Texto con los bytes no imprimibles como «·» (lo escondido suele ir al principio y luego viene ruido).
    let shown = '';
    for (let i = 0; i < Math.min(data.length, 4000); i++) { const c = data[i]; shown += (c >= 32 && c < 127) || c === 10 ? String.fromCharCode(c) : '·'; }
    $('gmOut').innerHTML = `<p class="small">${kind !== 'unknown' && kind !== 'text' ? `<span class="lvl ok">${esc(typeName(kind))}</span> ` : ''}${IK.num(data.length)} B</p>
      <pre class="out" style="max-height:160px">${esc(shown)}</pre>
      <pre class="out hex" style="max-height:160px;margin-top:6px">${esc(B.hexdump(data, 0, 256))}</pre>
      <div class="btns" style="margin-top:6px"><button class="btn ghost small" type="button" data-act="lsbDl">${esc(t('c.download'))}</button><button class="btn ghost small" type="button" data-act="lsbCi">${esc(t('c.toCipher'))}</button><button class="btn ghost small" type="button" data-act="lsbAn">${esc(t('file.analyzeIt'))}</button></div>`;
  }

  // ───────────── Acciones ─────────────
  const baseName = (n) => String(n || 'archivo').replace(/\.[^.]+$/, '');
  async function onClick(e) {
    const it = cur(); if (!it) return;
    const el = e.target.closest('button, [data-hexoff]');
    if (!el) return;
    const ds = el.dataset;
    if (ds.copy != null) { IK.copyText(ds.copy); return; }
    if (ds.crumb != null) { stack.length = +ds.crumb + 1; renderCrumbs(); render(); return; }
    if (ds.hexoff != null) { jumpHex(+ds.hexoff); return; }
    if (ds.cipher != null) { IK.send('cifrados', { text: ds.cipher }); return; }
    if (ds.hashid != null) { IK.send('hash', { identify: ds.hashid }); return; }
    if (ds.hx) { const page = 512; if (ds.hx === 'go') { const v = $('hxOff').value.trim(); const n = /^0x/i.test(v) ? parseInt(v, 16) : /[a-f]/i.test(v) ? parseInt(v, 16) : parseInt(v, 10); if (Number.isFinite(n)) hexAt(it, n); } else if (ds.hx === 'start') hexAt(it, 0); else if (ds.hx === 'end') hexAt(it, it.bytes.length - page); else hexAt(it, it.hex + (ds.hx === 'next' ? page : -page)); return; }
    if (ds.cut != null) {
      const sub = it.bytes.slice(+ds.cut, +ds.cutend);
      const label = `${IK.hex(+ds.cut)}`;
      if (ds.op === 'dl') IK.download(`${baseName(it.name)}_${label}.bin`, sub);
      else if (ds.op === 'ci') IK.send('cifrados', { bytes: sub });
      else await push(sub, `${baseName(it.name)}_${label}.bin`, '', `${typeName(B.detect(sub).type)} @ ${label}`);
      return;
    }
    if (ds.zip != null) {
      const z = it.res.zip || it.res.zipAppended;
      const entry = z.entries[+ds.zip];
      const data = await B.zipRead(it.bytes, entry);
      if (!data) return;
      const nm = entry.name.split('/').pop() || 'entrada';
      if (ds.zop === 'dl') IK.download(nm, data); else await push(data, nm, '', nm);
      return;
    }
    if (ds.scan != null) { $('secStego').open = true; manualLsb(it, it.stego.scan[+ds.scan]); $('gmOut').scrollIntoView({ behavior: 'smooth', block: 'center' }); return; }
    switch (ds.act) {
      case 'toHash': IK.send('hash', { bytes: it.bytes, name: it.name }); break;
      case 'strip': {
        const r = it.res.detect.type === 'jpeg' ? B.stripJpeg(it.bytes) : await B.stripPng(it.bytes);
        if (!r) { IK.toast(t('m.stripNo')); break; }
        it.stripInfo = t('m.stripDone', { n: r.removed, tr: r.trailing > 0 ? t('m.stripTr', { size: IK.size(r.trailing) }) : '' });
        IK.download(`${baseName(it.name)}_limpio.${it.res.detect.type === 'jpeg' ? 'jpg' : 'png'}`, r.bytes);
        renderMeta(it);
        break;
      }
      case 'fixDl': case 'fixAn': {
        const f = it.res.png.ihdrFix;
        const fixed = B.patchIhdr(it.bytes, it.res.png, f.width, f.height);
        if (ds.act === 'fixDl') IK.download(`${baseName(it.name)}_reparado.png`, fixed); else await push(fixed, `${baseName(it.name)}_reparado.png`, 'image/png', `${f.width}×${f.height}`);
        break;
      }
      case 'strings': computeStrings(it); break;
      case 'strMore': it.strShown += 1000; listStrings(it); break;
      case 'strSearch': searchStrings(it); break;
      case 'byteSearch': searchBytes(it); break;
      case 'strExport': IK.download(`${baseName(it.name)}_cadenas.txt`, filteredStrings(it).map(s => `${s.offset.toString(16).padStart(8, '0')}\t${s.enc}\t${s.text}`).join('\n'), 'text/plain;charset=utf-8'); break;
      case 'iocExport': IK.download(`${baseName(it.name)}_indicadores.json`, JSON.stringify({ file: it.name, sha256: it.hashes && it.hashes['SHA-256'], indicators: it.iocs.found }, null, 2), 'application/json'); break;
      case 'lsb': manualLsb(it); break;
      case 'lsbDl': IK.download(`${baseName(it.name)}_lsb.bin`, it.lsbOut); break;
      case 'lsbCi': IK.send('cifrados', { bytes: it.lsbOut }); break;
      case 'lsbAn': await push(it.lsbOut, `${baseName(it.name)}_lsb.bin`, '', 'LSB'); break;
      default: break;
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    IK.dropzone($('fileDrop'), openFile);
    $('fileOut').addEventListener('click', onClick);
    $('fileCrumbs').addEventListener('click', onClick);
    document.addEventListener('keydown', (e) => { if (e.key === 'Enter' && e.target && e.target.id === 'stTerms') searchStrings(cur()); if (e.key === 'Enter' && e.target && e.target.id === 'hxOff') { const b = document.querySelector('[data-hx="go"]'); if (b) b.click(); } });
    // Pegar un archivo con Ctrl+V en la pestaña Archivo
    document.addEventListener('paste', (e) => { if (IK.tab() !== 'archivo') return; const f = e.clipboardData && e.clipboardData.files && e.clipboardData.files[0]; if (f) { e.preventDefault(); openFile(f); } });
    document.addEventListener('ik:lang', () => { if (cur()) { renderCrumbs(); render(); } });
    document.addEventListener('ik:theme', () => { if (cur()) drawSpark(cur()); });
    IK.onReceive('archivo', async (p) => { stack.length = 0; await push(p.bytes, p.name || 'datos.bin', '', p.name || 'datos.bin'); });
  });
})();
