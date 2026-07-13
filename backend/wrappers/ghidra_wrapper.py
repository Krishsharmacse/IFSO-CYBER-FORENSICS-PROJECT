import os
import shutil
import uuid
import tempfile
from wrappers.platform_utils import run, GHIDRA_HEADLESS, IS_WINDOWS

def run_headless_analysis(file_path: str):
    """
    Uses Ghidra's analyzeHeadless script to import and analyse a binary.
    Works on Windows (analyzeHeadless.bat) and Linux/macOS (analyzeHeadless).
    """
    if not os.path.exists(file_path):
        return {"error": f"Binary file not found: {file_path}"}

    temp_dir    = tempfile.mkdtemp(prefix="ghidra_")
    project_name = f"Project_{uuid.uuid4().hex[:8]}"

    results = {
        "status"      : "Analysis attempted",
        "project_dir" : temp_dir,
        "project_name": project_name,
        "target_file" : file_path
    }

    try:
        cmd = [GHIDRA_HEADLESS, temp_dir, project_name, "-import", file_path]

        process = run(cmd, timeout=300)

        if process.returncode == 0:
            log_lines = [line for line in process.stdout.split('\n') if line.strip()]
            results["ghidra_log"] = log_lines[-10:] if len(log_lines) > 10 else log_lines
            results["message"]    = "Ghidra headless analysis completed successfully."
        else:
            results["error"] = (
                "Ghidra execution failed. "
                "Please ensure analyzeHeadless (or analyzeHeadless.bat on Windows) "
                "is accessible via the plugins/ghidra_* directory or your system PATH."
            )
            results["details"] = process.stderr[-500:]

    except FileNotFoundError:
        install_hint = (
            "Windows: Download Ghidra from https://ghidra-sre.org and extract to plugins/ghidra_*"
            if IS_WINDOWS else
            "Linux/macOS: Download from https://ghidra-sre.org and extract to plugins/ghidra_*"
        )
        results["error"] = f"Ghidra 'analyzeHeadless' not found. {install_hint}"

    except Exception as e:
        results["error"] = str(e)

    finally:
        try:
            shutil.rmtree(temp_dir)
        except Exception:
            pass

    return results

# Alias used by main.py
analyze_binary = run_headless_analysis
