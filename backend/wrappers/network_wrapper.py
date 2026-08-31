import os
import sys
from pathlib import Path

# Add backend root to sys.path so we can run this file directly for testing
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

def analyze_pcap(file_path: str, scan_type: str = "dns"):
    """
    Analyse a PCAP/PCAPNG file using scapy (pure Python).
    """
    if not os.path.exists(file_path):
        return {"error": f"PCAP file not found: {file_path}"}

    try:
        from scapy.all import rdpcap, DNSQR, IP
    except ImportError:
        return {"error": "scapy is not installed. Run: pip install scapy"}

    try:
        packets = rdpcap(file_path)
        
        if scan_type == "dns":
            queries = set()
            for pkt in packets:
                if pkt.haslayer(DNSQR):
                    queries.add(pkt[DNSQR].qname.decode('utf-8', errors='ignore'))
            return {"status": "Success", "results": list(queries)[:1000]}
            
        elif scan_type == "endpoints":
            endpoints = set()
            for pkt in packets:
                if pkt.haslayer(IP):
                    endpoints.add(f"{pkt[IP].src} -> {pkt[IP].dst}")
            return {"status": "Success", "results": list(endpoints)[:1000]}
            
        elif scan_type == "hierarchy":
            # Simple protocol counting
            proto_counts = {}
            for pkt in packets:
                for layer in pkt.layers():
                    name = layer.__name__
                    proto_counts[name] = proto_counts.get(name, 0) + 1
            
            total = len(packets)
            hierarchy = [f"{k}: {v} packets ({(v/total)*100:.1f}%)" for k, v in proto_counts.items()]
            return {"status": "Success", "results": hierarchy}
            
        else:
            return {"error": "Unknown network scan type. Valid: dns, hierarchy, endpoints"}

    except Exception as e:
        return {"error": f"Error parsing PCAP with scapy: {str(e)}"}

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: uv run python network_wrapper.py <pcap_file> [scan_type]")
        sys.exit(1)
        
    pcap_path = sys.argv[1]
    s_type = sys.argv[2] if len(sys.argv) > 2 else "dns"
    
    import json
    print(f"[*] Testing network_wrapper.py on {pcap_path} with scan_type='{s_type}'")
    result = analyze_pcap(pcap_path, s_type)
    print(json.dumps(result, indent=2))
