"""PlatformIO pre-build hook: embed Web UI gzip bytes instead of a large UTF-8 literal."""
import gzip
import pathlib
import re

Import("env")  # noqa: F821 - injected by PlatformIO
# LTO objects require the GCC linker driver to enable its LTO plugin.
env.AppendUnique(LINKFLAGS=["-flto", "-fuse-linker-plugin"])
root = pathlib.Path(env["PROJECT_DIR"])
source = (root / "src/web_ui.h").read_text(encoding="utf-8")
match = re.search(r'R"HTML\((.*?)\)HTML";', source, re.DOTALL)
if match is None:
    raise RuntimeError("HTML raw literal missing; blocking firmware build")
html = match.group(1).encode("utf-8")
blob = gzip.compress(html, compresslevel=9, mtime=0)
if len(blob) >= len(html):
    raise RuntimeError("Compression failed to save program space")
out = root / "src/web_ui_gzip.h"
parts = [blob[i:i+16] for i in range(0, len(blob), 16)]
text = '#pragma once\n#include <Arduino.h>\n'
text += 'static const unsigned char INDEX_HTML_GZ[] PROGMEM = {\n'
text += ''.join('  '+', '.join('0x%02x' % item for item in block)+',\n' for block in parts)
text += '};\n'
text += 'static constexpr size_t INDEX_HTML_GZ_LEN = sizeof(INDEX_HTML_GZ);\n'
if not out.exists() or out.read_text(encoding="utf-8") != text:
    out.write_text(text, encoding="utf-8")
print(f"EMBEDDED_WEB_UI_COMPRESSED original={len(html)} gzip={len(blob)} saved={len(html)-len(blob)}")
