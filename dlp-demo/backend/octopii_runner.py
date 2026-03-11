"""
Thin wrapper: inject a textract mock, then call Octopii's search_pii()
on the file passed as argv[1] and print a single JSON object to stdout.

Running as a subprocess keeps Octopii's heavy import chain isolated from
the Flask process and avoids circular-import issues between Octopii modules.
"""
import sys, os, json, types

# ── Minimal textract mock ────────────────────────────────────────────────────
# octopii.py and file_utils.py import textract at the top level.
# For .txt files Octopii just reads the file; our mock replicates that without
# requiring the full textract package and its shell dependencies.
_mod = types.ModuleType("textract")

class _Exceptions:
    class MissingFileError(Exception): pass
    class ShellError(Exception): pass

_mod.exceptions = _Exceptions

def _process(file_path, **kwargs):
    with open(file_path, "rb") as fh:
        return fh.read()

_mod.process = _process
sys.modules["textract"] = _mod
# ─────────────────────────────────────────────────────────────────────────────

OCTOPII_DIR = "/opt/octopii"
sys.path.insert(0, OCTOPII_DIR)
os.chdir(OCTOPII_DIR)          # Octopii uses relative paths: definitions.json, face_cascade.xml

import text_utils as _tu
import octopii    as _oc

# octopii.search_pii() references a module-level `rules` global that is
# normally set in the __main__ block; we set it explicitly here.
_oc.rules = _tu.get_regexes()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "No file path provided"}))
        sys.exit(1)
    result = _oc.search_pii(sys.argv[1])
    print(json.dumps(result))
