import os

try:
    import yara
    _YARA_AVAILABLE = True
except ImportError:
    _YARA_AVAILABLE = False

def run_yara(rules_path: str, file_path: str):
    """
    Compiles a YARA rule and scans a file for matches.
    yara-python works natively on both Windows and Linux.
    """
    if not _YARA_AVAILABLE:
        return {"error": "yara-python is not installed. On Windows, install Microsoft C++ Build Tools first, then: uv pip install yara-python"}
    if not os.path.exists(rules_path):
        return {"error": f"Rules file not found: {rules_path}"}
    if not os.path.exists(file_path):
        return {"error": f"Target file not found: {file_path}"}

    try:
        rules = yara.compile(filepath=rules_path)
        matches = rules.match(file_path)

        formatted_matches = []
        for match in matches:
            formatted_matches.append({
                "rule"     : match.rule,
                "namespace": match.namespace,
                "tags"     : match.tags,
                "meta"     : match.meta
            })

        return {"matches": formatted_matches}
    except yara.SyntaxError as e:
        return {"error": f"YARA Syntax Error: {e}"}
    except Exception as e:
        return {"error": str(e)}
