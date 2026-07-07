"""
Registry Password Cracking Wrapper
Uses: impacket-secretsdump (to extract NTLM hashes from SAM and SYSTEM hives)
Uses: john (John the Ripper, to crack the extracted hashes)
"""

import subprocess
import os
import tempfile

def crack_registry(sam_path: str, system_path: str):
    if not os.path.exists(sam_path):
        return {"error": f"SAM hive not found: {sam_path}"}
    if not os.path.exists(system_path):
        return {"error": f"SYSTEM hive not found: {system_path}"}
        
    try:
        # 1. Use Impacket's secretsdump to extract hashes from SAM/SYSTEM
        secretsdump_bin = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".venv", "bin", "secretsdump.py"))
        if not os.path.exists(secretsdump_bin):
            return {"error": "impacket-secretsdump is not installed in the virtual environment."}

        dump_proc = subprocess.run(
            [secretsdump_bin, "-sam", sam_path, "-system", system_path, "LOCAL"],
            capture_output=True, text=True
        )
        
        dump_output = dump_proc.stdout
        if "Traceback" in dump_output or dump_proc.returncode != 0:
            return {"error": "Failed to extract hashes from registry hives.", "details": dump_output + "\n" + dump_proc.stderr}

        # 2. Parse the NTLM hashes for John the Ripper
        hashes = []
        for line in dump_output.split("\n"):
            # Secretsdump format: Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
            if ":" in line and len(line.split(":")) >= 4:
                parts = line.split(":")
                username = parts[0]
                ntlm_hash = parts[3]
                if ntlm_hash and ntlm_hash != "empty" and ntlm_hash != "31d6cfe0d16ae931b73c59d7e0c089c0":
                    hashes.append(line)

        if not hashes:
            return {
                "status": "Success",
                "message": "No crackable hashes found in the provided registry hives.",
                "raw_dump": dump_output.split("\n")
            }

        # 3. Save hashes to a temporary file for John
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as temp_hash_file:
            temp_hash_file.write("\n".join(hashes))
            temp_hash_path = temp_hash_file.name

        # 4. Run John the Ripper with NT format specification
        john_proc = subprocess.run(["john", "--format=NT", temp_hash_path], capture_output=True, text=True)
        show_proc = subprocess.run(["john", "--show", "--format=NT", temp_hash_path], capture_output=True, text=True)
        
        os.remove(temp_hash_path)

        return {
            "status": "Success", 
            "extracted_hashes": hashes,
            "john_crack_log": john_proc.stdout.strip().split("\n"),
            "john_results": show_proc.stdout.strip().split("\n"),
            "raw_dump": dump_output.split("\n")
        }
    except Exception as e:
        return {"error": str(e)}
