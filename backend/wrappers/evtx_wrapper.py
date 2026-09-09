import os

try:
    from Evtx.Evtx import Evtx
    from Evtx.Views import evtx_file_xml_view
    HAS_EVTX = True
except ImportError:
    HAS_EVTX = False


def parse_evtx(file_path: str, max_records: int = 100):
    """
    Parses Windows EVTX event log files using the python-evtx library.
    """
    if not HAS_EVTX:
        return {
            "error": "python-evtx library is not installed.",
            "fix": "Run: pip install python-evtx"
        }

    if not os.path.exists(file_path):
        return {"error": f"EVTX file not found: {file_path}"}

    # Validate EVTX header magic bytes ('ElfFile\x00')
    try:
        with open(file_path, 'rb') as f:
            magic = f.read(8)
            if magic != b"ElfFile\x00":
                return {
                    "error": f"Invalid EVTX signature in '{os.path.basename(file_path)}'. The file is not a valid Windows Event Log file (.evtx)."
                }
    except Exception as e:
        return {"error": f"Could not read file header: {str(e)}"}

    records = []
    suspicious_logons = []

    try:
        with Evtx(file_path) as evtx:
            for xml_str, record in evtx_file_xml_view(evtx.get_file_header()):
                records.append(xml_str)
                
                # Check for suspicious logon events (Event ID 4624/4625/4672/4688)
                if '4625' in xml_str or 'An account failed to log on' in xml_str:
                    suspicious_logons.append({"event_id": 4625, "type": "Failed Logon", "xml": xml_str[:400]})
                elif '4672' in xml_str:
                    suspicious_logons.append({"event_id": 4672, "type": "Special Privileges Assigned", "xml": xml_str[:400]})

                if len(records) >= max_records:
                    break

        return {
            "status": "Success",
            "total_records_parsed": len(records),
            "suspicious_logon_count": len(suspicious_logons),
            "suspicious_logons": suspicious_logons,
            "records": records
        }

    except Exception as e:
        return {"error": f"EVTX Parsing Error: {str(e)}"}


analyze_evtx = parse_evtx
