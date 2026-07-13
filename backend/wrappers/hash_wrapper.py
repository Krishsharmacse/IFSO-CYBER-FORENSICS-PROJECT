import os
from wrappers.platform_utils import run, JOHN_BIN, IS_WINDOWS

def crack_hash(file_path: str):
    """
    Runs John the Ripper on a hash file.
    Cross-platform: works on Windows and Linux/macOS.
    """
    if not os.path.exists(file_path):
        return {"error": f"Hash file not found: {file_path}"}

    if not JOHN_BIN:
        install_hint = (
            "Windows: Download from https://www.openwall.com/john/ and add run/ to PATH"
            if IS_WINDOWS else
            "Linux: sudo apt install john"
        )
        return {"error": f"John the Ripper is not installed. {install_hint}"}

    try:
        proc      = run([JOHN_BIN, file_path], timeout=120)
        show_proc = run([JOHN_BIN, "--show", file_path], timeout=30)
        return {
            "status"   : "Success",
            "crack_log": proc.stdout.strip().split("\n"),
            "results"  : show_proc.stdout.strip().split("\n")
        }
    except FileNotFoundError:
        install_hint = (
            "Windows: Download from https://www.openwall.com/john/ and add run/ to PATH"
            if IS_WINDOWS else
            "Linux: sudo apt install john"
        )
        return {"error": f"John the Ripper executable not found. {install_hint}"}
    except Exception as e:
        return {"error": str(e)}
