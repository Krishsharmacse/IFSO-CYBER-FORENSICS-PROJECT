import subprocess
import os

def analyze_image(image_path: str, scan_type: str = "mmls"):
    """
    Uses Sleuth Kit (the core engine behind Autopsy) to analyze a disk image.
    Supports mmls (partitions), fsstat (file system info), fls (list files), and timeline (mactime).
    """
    if not os.path.exists(image_path):
        return {"error": f"Disk image file not found: {image_path}"}
        
    results = {}
    
    try:
        if scan_type == "mmls":
            # 1. Get Partition/Volume details using 'mmls'
            proc = subprocess.run(['mmls', image_path], capture_output=True, text=True)
            if proc.returncode == 0:
                results['partitions'] = proc.stdout.strip().split('\n')
                results['status'] = 'Success'
            else:
                results['error'] = "Could not parse partitions (It might not have a volume system or mmls is not installed)."
                results['details'] = proc.stderr
                
        elif scan_type == "fsstat":
            # 2. Get File System info using 'fsstat'
            proc = subprocess.run(['fsstat', image_path], capture_output=True, text=True)
            if proc.returncode == 0:
                results['file_system_info'] = proc.stdout.strip().split('\n')
                results['status'] = 'Success'
            else:
                results['error'] = "Could not parse file system details (fsstat failed)."
                results['details'] = proc.stderr
                
        elif scan_type == "fls":
            # 3. List all files and deleted files recursively using 'fls -r'
            # Note: For raw images, you usually have to provide a partition offset (e.g. -o 2048) 
            # if the image has a volume system. If it's a raw file system, no offset is needed.
            # We'll just run 'fls -r' which works on single partitions.
            proc = subprocess.run(['fls', '-r', image_path], capture_output=True, text=True)
            if proc.returncode == 0:
                output_lines = proc.stdout.strip().split('\n')
                # If output is massive, limit to first 1000 lines for JSON safety
                results['files'] = output_lines[:1000] 
                if len(output_lines) > 1000:
                    results['notice'] = f"Truncated output. Found {len(output_lines)} total files. Showing first 1000."
                results['status'] = 'Success'
            else:
                results['error'] = "Could not list files (fls failed). Note: If the image has multiple partitions, you must provide an offset."
                results['details'] = proc.stderr
                
        elif scan_type == "timeline":
            # Generate an evidence timeline (mactime)
            body_proc = subprocess.run(['fls', '-r', '-m', '/', image_path], capture_output=True, text=True)
            if body_proc.returncode == 0:
                body_file_path = f"/tmp/{os.path.basename(image_path)}.body"
                with open(body_file_path, "w") as f:
                    f.write(body_proc.stdout)
                
                mac_proc = subprocess.run(['mactime', '-b', body_file_path], capture_output=True, text=True)
                output_lines = mac_proc.stdout.strip().split('\n')
                results['timeline'] = output_lines[:2000] # Limit to 2000 lines
                if len(output_lines) > 2000:
                    results['notice'] = f"Truncated timeline. Found {len(output_lines)} events. Showing first 2000."
                results['status'] = 'Success'
                os.remove(body_file_path) # Cleanup
            else:
                results['error'] = "Could not generate timeline (fls failed to build body file)."
                results['details'] = body_proc.stderr
                
        else:
            results['error'] = f"Unknown scan type: {scan_type}"
            
    except Exception as e:
        results['error'] = f"Sleuth Kit Execution Failed: {str(e)}"
        
    return results
