from typing import Dict, Any

def get_progress(file_path: str = None) -> Dict[str, Any]:
    return {"status": "disabled", "message": "Ghidra is disabled in the pure Python Lite version."}

def run_headless_analysis(file_path: str, extract_code: bool = True, timeout: int = 900) -> Dict[str, Any]:
    return {"error": "Ghidra (Java) is disabled in the pure Python Lite version. Use the full desktop version for binary reversing."}
