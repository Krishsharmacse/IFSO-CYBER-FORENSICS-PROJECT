import subprocess
import os

def analyze_stego(file_path: str):
    if not os.path.exists(file_path):
        return {"error": f"Image/Audio file not found: {file_path}"}
        
    try:
        proc = subprocess.run(["steghide", "info", file_path, "-p", ""], capture_output=True, text=True)
        # returncode 0 means data found without password or no data. returncode 1 means it asked for password or failed.
        output = proc.stdout + proc.stderr
        return {"status": "Success", "output": output.split('\n')}
    except FileNotFoundError:
        return {"error": "steghide is not installed. Run 'sudo apt install steghide'"}
    except Exception as e:
        return {"error": str(e)}
