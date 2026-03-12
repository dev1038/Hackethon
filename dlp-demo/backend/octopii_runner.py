import sys, os, json, types

# textract mock (not installed in Docker image)
_mod = types.ModuleType("textract")
class _Exceptions:
    class MissingFileError(Exception): pass
    class ShellError(Exception): pass
_mod.exceptions = _Exceptions
_mod.process = lambda path, **kw: open(path, "rb").read()
sys.modules["textract"] = _mod

OCTOPII_DIR = "/opt/octopii"
sys.path.insert(0, OCTOPII_DIR)
os.chdir(OCTOPII_DIR)

import text_utils as _tu
import octopii    as _oc

_oc.rules = _tu.get_regexes()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "No file path provided"}))
        sys.exit(1)
    result = _oc.search_pii(sys.argv[1])
    print(json.dumps(result))
