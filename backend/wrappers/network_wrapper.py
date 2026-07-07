import subprocess
import os

def analyze_pcap(file_path: str, scan_type: str = "dns"):
    if not os.path.exists(file_path):
        return {"error": f"PCAP file not found: {file_path}"}
    
    try:
        if scan_type == "dns":
            cmd = ["tshark", "-r", file_path, "-T", "fields", "-e", "dns.qry.name", "-Y", "dns.flags.response eq 0"]
        elif scan_type == "hierarchy":
            cmd = ["tshark", "-r", file_path, "-q", "-z", "io,phs"]
        elif scan_type == "endpoints":
            cmd = ["tshark", "-r", file_path, "-q", "-z", "endpoints,ip"]
        else:
            return {"error": "Unknown network scan type"}
            
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            return {"error": "tshark failed or is not installed. Run 'sudo apt install tshark'", "details": proc.stderr}
            
        lines = proc.stdout.strip().split('\n')
        if scan_type == "dns":
            lines = list(set([l for l in lines if l])) # deduplicate
            
        return {"status": "Success", "results": lines[:1000]}
    except FileNotFoundError:
        return {"error": "tshark is not installed. Run 'sudo apt install tshark'"}
    except Exception as e:
        return {"error": str(e)}
