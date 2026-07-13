import os
from wrappers.platform_utils import run, VOLATILITY_BIN

# Map plugin short-name → volatility plugin name
_PLUGIN_MAP = {
    "info"    : "windows.info.Info",
    "pslist"  : "windows.pslist.PsList",
    "malfind" : "windows.malfind.Malfind",
    "netscan" : "windows.netscan.NetScan",
    "cmdline" : "windows.cmdline.CmdLine",
    "filescan": "windows.filescan.FileScan",
}

# Linux / Mac fallback equivalents for the "info" plugin
_FALLBACK_PLUGINS = ["linux.info.Info", "mac.info.Info"]


def run_volatility(file_path: str, scan_type: str = "info"):
    """
    Runs Volatility 3 on a memory dump.
    Supported scan_types: info, pslist, malfind, netscan, cmdline, filescan.
    Cross-platform: works on Windows and Linux/macOS.
    """
    if not os.path.exists(file_path):
        return {"error": f"Memory dump file not found: {file_path}"}

    plugin = _PLUGIN_MAP.get(scan_type, "windows.info.Info")
    cmd    = [VOLATILITY_BIN, "-f", file_path, "-r", "json", plugin]

    import json

    try:
        process = run(cmd, timeout=300)

        # If Windows plugin fails on a Linux/Mac dump, try fallbacks
        if (process.returncode != 0
                and scan_type == "info"
                and "Unable to validate the plugin requirements" in process.stderr):
            for fallback in _FALLBACK_PLUGINS:
                fallback_cmd = [VOLATILITY_BIN, "-f", file_path, "-r", "json", fallback]
                process = run(fallback_cmd, timeout=300)
                if process.returncode == 0:
                    break

        if process.returncode == 0:
            try:
                output = json.loads(process.stdout)
                return {"status": "Success", "volatility_results": output}
            except json.JSONDecodeError:
                return {
                    "status"  : "Success (Raw Text)",
                    "output"  : process.stdout,
                    "warnings": process.stderr
                }
        else:
            error_msg = process.stderr.strip()
            if "Unable to validate the plugin requirements" in error_msg:
                return {
                    "error" : "Volatility could not detect a valid OS kernel in this file.",
                    "fix"   : (
                        "Ensure this is a valid memory dump (.raw, .vmem, .mem). "
                        "If it is a Windows dump, Volatility might be missing the "
                        "specific Symbol Table (ISF) for this exact OS build."
                    ),
                    "raw_error": error_msg[-500:]
                }
            return {"error": "Volatility failed.", "details": error_msg}

    except FileNotFoundError:
        return {
            "error": f"Volatility 3 binary '{VOLATILITY_BIN}' not found.",
            "fix"  : (
                "Linux:   pip install volatility3  OR  sudo apt install volatility3\n"
                "Windows: pip install volatility3  (adds 'vol' to your venv Scripts/)"
            )
        }
    except Exception as e:
        return {"error": str(e)}
