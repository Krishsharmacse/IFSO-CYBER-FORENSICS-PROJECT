import os
from wrappers.platform_utils import run, STEGHIDE_BIN, IS_WINDOWS

def check_stego(file_path: str):
    """
    Checks for hidden data inside images/audio using steghide.
    Cross-platform: works on Windows and Linux.
    Note: steghide supports BMP, JPEG, AU, WAV formats.
    """
    if not os.path.exists(file_path):
        return {"error": f"Image/Audio file not found: {file_path}"}

    try:
        proc = run([STEGHIDE_BIN, "info", file_path, "-p", ""], timeout=30)
        output = (proc.stdout + proc.stderr).strip()
        return {"status": "Success", "output": output.split('\n')}

    except FileNotFoundError:
        install_hint = (
            "Windows: Download from https://steghide.sourceforge.net and add to PATH"
            if IS_WINDOWS else
            "Linux: sudo apt install steghide"
        )
        return {
            "error": f"steghide is not installed. {install_hint}",
            "note" : "steghide supports BMP, JPEG, AU and WAV file formats."
        }
    except Exception as e:
        return {"error": str(e)}

# Alias used by main.py
analyze_stego = check_stego
