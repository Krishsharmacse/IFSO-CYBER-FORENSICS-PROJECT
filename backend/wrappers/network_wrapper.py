import os
from wrappers.platform_utils import run, TSHARK_BIN, IS_WINDOWS

def analyze_pcap(file_path: str, scan_type: str = "dns"):
    """
    Analyse a PCAP/PCAPNG file using tshark.
    Cross-platform: works on Windows (Wireshark) and Linux.
    """
    if not os.path.exists(file_path):
        return {"error": f"PCAP file not found: {file_path}"}

    try:
        if scan_type == "dns":
            cmd = [
                TSHARK_BIN, "-r", file_path,
                "-T", "fields", "-e", "dns.qry.name",
                "-Y", "dns.flags.response eq 0"
            ]
        elif scan_type == "hierarchy":
            cmd = [TSHARK_BIN, "-r", file_path, "-q", "-z", "io,phs"]
        elif scan_type == "endpoints":
            cmd = [TSHARK_BIN, "-r", file_path, "-q", "-z", "endpoints,ip"]
        else:
            return {"error": "Unknown network scan type. Valid: dns, hierarchy, endpoints"}

        proc = run(cmd, timeout=120)

        if proc.returncode != 0:
            install_hint = (
                "Windows: Install Wireshark from https://www.wireshark.org (includes tshark)"
                if IS_WINDOWS else
                "Linux: sudo apt install tshark"
            )
            return {
                "error"  : f"tshark failed or is not installed. {install_hint}",
                "details": proc.stderr
            }

        lines = proc.stdout.strip().split('\n')
        if scan_type == "dns":
            lines = list(set([l for l in lines if l]))   # deduplicate

        return {"status": "Success", "results": lines[:1000]}

    except FileNotFoundError:
        install_hint = (
            "Windows: Install Wireshark from https://www.wireshark.org and add to PATH"
            if IS_WINDOWS else
            "Linux: sudo apt install tshark"
        )
        return {"error": f"tshark is not installed. {install_hint}"}
    except Exception as e:
        return {"error": str(e)}
