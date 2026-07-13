import json
import os
from wrappers.platform_utils import run, EXIFTOOL_BIN

def run_exiftool(file_path: str):
    """
    Runs exiftool on a specified file path and returns extracted metadata.
    Works on both Windows and Linux/macOS.
    """
    if not os.path.exists(file_path):
        return {"error": f"File not found: {file_path}"}

    try:
        cmd = [EXIFTOOL_BIN, '-j']

        if os.path.isdir(file_path):
            cmd.append('-r')

        cmd.append(file_path)

        result = run(cmd, timeout=60)

        if result.returncode == 0:
            output = json.loads(result.stdout)
            if os.path.isdir(file_path):
                return {"total_files_scanned": len(output), "all_metadata": output}
            else:
                return output[0] if len(output) > 0 else {}
        else:
            return {"error": result.stderr.strip() or "exiftool returned a non-zero exit code."}

    except FileNotFoundError:
        return {
            "error": "exiftool is not installed or not found in PATH.",
            "fix": "Linux: sudo apt install exiftool | Windows: Download from https://exiftool.org and add to PATH"
        }
    except Exception as e:
        return {"error": str(e)}
