import subprocess
import json
import os

def analyze_memory(file_path: str, scan_type: str = "info"):
    """
    Runs Volatility 3 to extract forensic data from a memory dump.
    Supported scan_types: info, pslist, malfind, netscan, cmdline, filescan
    """
    if not os.path.exists(file_path):
        return {"error": f"Memory dump file not found: {file_path}"}
        
    try:
        # Determine the Volatility plugin to use based on the user's choice
        plugin_map = {
            "info": "windows.info.Info",
            "pslist": "windows.pslist.PsList",
            "malfind": "windows.malfind.Malfind",
            "netscan": "windows.netscan.NetScan",
            "cmdline": "windows.cmdline.CmdLine",
            "filescan": "windows.filescan.FileScan"
        }
        
        plugin = plugin_map.get(scan_type, "windows.info.Info")
        cmd = ["vol", "-f", file_path, "-r", "json", plugin]
        
        process = subprocess.run(cmd, capture_output=True, text=True)
        
        # If Windows fails for 'info', try Linux/Mac fallback. 
        # (pslist/malfind have linux/mac equivalents like linux.pslist.Pslist, but we keep it simple for now)
        if process.returncode != 0 and scan_type == "info" and "Unable to validate the plugin requirements" in process.stderr:
            cmd_linux = ["vol", "-f", file_path, "-r", "json", "linux.info.Info"]
            process = subprocess.run(cmd_linux, capture_output=True, text=True)
            if process.returncode != 0 and "Unable to validate the plugin requirements" in process.stderr:
                cmd_mac = ["vol", "-f", file_path, "-r", "json", "mac.info.Info"]
                process = subprocess.run(cmd_mac, capture_output=True, text=True)
        
        if process.returncode == 0:
            try:
                output = json.loads(process.stdout)
                return {"status": "Success", "volatility_results": output}
            except json.JSONDecodeError:
                return {"status": "Success (Raw Text)", "output": process.stdout, "warnings": process.stderr}
        else:
            error_msg = process.stderr.strip()
            if "Unable to validate the plugin requirements" in error_msg:
                return {
                    "error": "Volatility could not detect a valid OS kernel in this file.",
                    "fix": "Ensure this is a valid memory dump (.raw, .vmem, .mem). If it is a Windows dump, Volatility might be missing the specific Symbol Table (ISF) for this exact OS build.",
                    "raw_error": error_msg[-500:] # Just return the tail of the error
                }
            return {"error": "Volatility failed.", "details": error_msg}
            
    except FileNotFoundError:
         return {"error": "Volatility 3 (vol command) not found. Please ensure it is installed correctly."}
    except Exception as e:
         return {"error": str(e)}
