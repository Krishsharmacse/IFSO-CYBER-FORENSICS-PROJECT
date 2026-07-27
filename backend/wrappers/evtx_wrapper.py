import mmap
import contextlib
import os

try:
    from Evtx.Evtx import Evtx
    from Evtx.Views import evtx_file_xml_view
    HAS_EVTX = True
except ImportError:
    HAS_EVTX = False


def parse_evtx(file_path: str, max_records: int = 50):
    """
    Parses Windows EVTX event log files using the python-evtx library.
    Cross-platform: works on both Windows and Linux (python-evtx is pure Python).
    """
    if not HAS_EVTX:
        return {
            "error": "python-evtx library is not installed.",
            "fix"  : "Run: pip install python-evtx"
        }

    if not os.path.exists(file_path):
        return {"error": f"EVTX file not found: {file_path}"}

    results = []
    try:
        with open(file_path, 'rb') as f:
            with contextlib.closing(
                mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            ) as buf:
                with Evtx(buf) as evtx:
                    for xml, record in evtx_file_xml_view(evtx.get_file_header()):
                        results.append(xml)
                        if len(results) >= max_records:
                            break

        return {"status": "Success", "records": results}

    except Exception as e:
        return {"error": str(e)}

analyze_evtx = parse_evtx
