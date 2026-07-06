import subprocess
import json
import os

def run_exiftool(file_path: str):
    """
    Runs exiftool on a specified file path and returns the extracted metadata as a Python dictionary.
    """
    if not os.path.exists(file_path):
        return {"error": f"File not found: {file_path}"}
        
    try:
        # Assuming exiftool is installed on the system and available in PATH
        # We use -j to get JSON formatted output
        cmd = ['exiftool', '-j']
        
        # If the path is a directory, add the -r (recursive) flag to scan all files inside
        if os.path.isdir(file_path):
            cmd.append('-r')
            
        cmd.append(file_path)

        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            # exiftool returns a list of JSON objects (one per file)
            output = json.loads(result.stdout)
            
            if os.path.isdir(file_path):
                # Return the full list of all images if it was a folder scan
                return {"total_files_scanned": len(output), "all_metadata": output}
            else:
                # Keep original behavior for single file
                return output[0] if len(output) > 0 else {}
        else:
            return {"error": result.stderr.strip()}
            
    except Exception as e:
        return {"error": str(e)}
