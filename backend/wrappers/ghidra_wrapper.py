import subprocess
import os
import tempfile
import uuid
import shutil

# Path to the analyzeHeadless script from a compiled Ghidra release
GHIDRA_HEADLESS_PATH = "/home/krish-sharma/Desktop/Cyber Security Project for cyber safe/plugins/ghidra_12.1.2_PUBLIC/support/analyzeHeadless"

def analyze_binary(file_path: str):
    """
    Uses Ghidra's analyzeHeadless script to import and analyze a binary.
    """
    if not os.path.exists(file_path):
        return {"error": f"Binary file not found: {file_path}"}
        
    # Create a temporary directory for the Ghidra project
    temp_dir = tempfile.mkdtemp(prefix="ghidra_")
    project_name = f"Project_{uuid.uuid4().hex[:8]}"
    
    results = {
        "status": "Analysis attempted",
        "project_dir": temp_dir,
        "project_name": project_name,
        "target_file": file_path
    }
    
    try:
        # Basic headless command to just import and auto-analyze
        cmd = [GHIDRA_HEADLESS_PATH, temp_dir, project_name, "-import", file_path]
        
        process = subprocess.run(cmd, capture_output=True, text=True)
        
        if process.returncode == 0:
            # Capture the last few lines of Ghidra's log to show success
            log_lines = [line for line in process.stdout.split('\n') if line.strip()]
            results["ghidra_log"] = log_lines[-10:] if len(log_lines) > 10 else log_lines
            results["message"] = "Ghidra headless analysis completed successfully."
        else:
            results["error"] = "Ghidra execution failed. Please ensure 'analyzeHeadless' is in your system PATH or update the script path."
                
    except FileNotFoundError:
         results["error"] = "Ghidra 'analyzeHeadless' executable not found. You may need to compile the Ghidra source or download a release zip."
    except Exception as e:
         results["error"] = str(e)
    
    # Cleanup the temp project (optional, but good for saving space)
    try:
        shutil.rmtree(temp_dir)
    except:
        pass
         
    return results
