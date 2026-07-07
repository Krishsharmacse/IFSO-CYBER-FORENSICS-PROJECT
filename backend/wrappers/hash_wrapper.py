import subprocess
import os

JOHN_BIN = '/usr/sbin/john'

def crack_hash(file_path: str):
    if not os.path.exists(file_path):
        return {"error": f"Hash file not found: {file_path}"}
    try:
        proc      = subprocess.run([JOHN_BIN, file_path], capture_output=True, text=True)
        show_proc = subprocess.run([JOHN_BIN, "--show", file_path], capture_output=True, text=True)
        return {
            "status"   : "Success",
            "crack_log": proc.stdout.strip().split("\n"),
            "results"  : show_proc.stdout.strip().split("\n")
        }
    except FileNotFoundError:
        return {"error": "John the Ripper is not installed. Run 'sudo apt install john'"}
    except Exception as e:
        return {"error": str(e)}
