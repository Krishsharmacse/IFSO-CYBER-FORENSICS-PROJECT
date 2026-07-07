import mmap
import contextlib
from Evtx.Evtx import Evtx
from Evtx.Views import evtx_file_xml_view
import os

def analyze_evtx(file_path: str, max_records: int = 50):
    if not os.path.exists(file_path):
        return {"error": f"EVTX file not found: {file_path}"}
    
    results = []
    try:
        with open(file_path, 'r') as f:
            with contextlib.closing(mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)) as buf:
                with Evtx(buf) as evtx:
                    for xml, record in evtx_file_xml_view(evtx.get_file_header()):
                        results.append(xml)
                        if len(results) >= max_records:
                            break
        return {"status": "Success", "records": results}
    except Exception as e:
        return {"error": str(e)}
