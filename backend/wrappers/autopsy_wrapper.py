import subprocess
import os

def analyze_image(image_path: str):
    """
    Uses Sleuth Kit (the core engine behind Autopsy) to analyze a disk image.
    It runs 'mmls' to get partition tables and 'fsstat' to get file system details.
    """
    if not os.path.exists(image_path):
        return {"error": f"Disk image file not found: {image_path}"}
        
    results = {}
    
    # 1. Get Partition/Volume   details using 'mmls'
    try:
        mmls_result = subprocess.run(['mmls', image_path], capture_output=True, text=True)
        if mmls_result.returncode == 0:
            results['partitions'] = mmls_result.stdout.strip().split('\n')
        else:
            results['partitions_error'] = "Could not parse partitions (It might not have a volume system or mmls is not installed)."
    except Exception as e:
        results['partitions_error'] = str(e)
        
    # 2. Get File System info using 'fsstat'
    try:
        # Assuming the first partition is at an offset, but fsstat might work directly if it's a raw partition image.
        fsstat_result = subprocess.run(['fsstat', image_path], capture_output=True, text=True)
        if fsstat_result.returncode == 0:
            results['file_system_info'] = fsstat_result.stdout.strip().split('\n')
        else:
            results['fsstat_error'] = "Could not parse file system details."
    except Exception as e:
         results['fsstat_error'] = str(e)
         
    return results
