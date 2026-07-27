import os
import sys
from pathlib import Path

_BACKEND_DIR = str(Path(__file__).parent.resolve())
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy.orm import Session
import database, models, json

from dotenv import load_dotenv
from wrappers.platform_utils import get_platform_info
from wrappers import (
    exiftool_wrapper, yara_wrapper, autopsy_wrapper, ghidra_wrapper,
    androguard_wrapper, mobsf_wrapper, volatility_wrapper,
    threat_intel_wrapper, network_wrapper, email_wrapper,
    evtx_wrapper, stego_wrapper, hash_wrapper,
    brute_wrapper, registry_wrapper, ip_resolver_wrapper
)

load_dotenv()
models.Base.metadata.create_all(bind=database.engine)

app = FastAPI(
    title="CyberX Forensics Platform API",
    description="Unified cyber-police forensics suite — 15 analysis tools.",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=False,
    allow_methods=["*"], allow_headers=["*"],
)

os.makedirs("reports", exist_ok=True)
app.mount("/reports", StaticFiles(directory="reports"), name="reports")

def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

class ExiftoolRequest(BaseModel):
    file_path: str

class YaraRequest(BaseModel):
    file_path: str
    rules_path: str

class AutopsyRequest(BaseModel):
    image_path: str
    scan_type: str = "mmls"

class GhidraRequest(BaseModel):
    file_path: str
    extract_code: bool = True
    timeout: int = 900

class MobileRequest(BaseModel):
    file_path: str

class MemoryRequest(BaseModel):
    file_path: str
    scan_type: str = "info"

class ThreatIntelRequest(BaseModel):
    target: str
    scan_type: str = "ip"
    api_key: str = None

class NetworkRequest(BaseModel):
    file_path: str
    scan_type: str = "dns"

class GenericFileRequest(BaseModel):
    file_path: str

class BruteForceRequest(BaseModel):
    mode: str = "http"
    target: str
    username: str = "admin"
    username_field: str = "username"
    password_field: str = "password"
    success_string: str | None = None
    failure_string: str = "Invalid"
    port: int | None = None
    wordlist_path: str | None = None
    hash_type: str = "auto"
    max_attempts: int = 1000
    threads: int = 8

class RegistryRequest(BaseModel):
    sam_path: str
    system_path: str

class IPResolverRequest(BaseModel):
    target: str

def _save(db, filename, tool, results):
    inv = models.Investigation(filename=filename, tool_used=tool, status="Running")
    db.add(inv); db.commit(); db.refresh(inv)
    inv.status = "Failed" if "error" in results else results.get("status", "Completed")
    inv.results = json.dumps(results)
    db.commit()
    return inv

@app.get("/")
def root():
    return {"message": "CyberX Forensics Platform API v2.0 — 15 tools active"}

@app.get("/diagnostics")
def diagnostics():
    """Returns the resolved binary paths and OS info for all tools."""
    return get_platform_info()

@app.post("/analyze/exiftool")
def analyze_exif(req: ExiftoolRequest, db: Session = Depends(get_db)):
    results = exiftool_wrapper.run_exiftool(req.file_path)
    inv = _save(db, req.file_path, "exiftool", results)
    return {"id": inv.id, "status": inv.status, "results": results}

@app.post("/analyze/yara")
def analyze_yara(req: YaraRequest, db: Session = Depends(get_db)):
    results = yara_wrapper.run_yara(req.rules_path, req.file_path)
    inv = _save(db, req.file_path, "yara", results)
    return {"id": inv.id, "status": inv.status, "results": results}

@app.post("/analyze/autopsy")
def analyze_autopsy(req: AutopsyRequest, db: Session = Depends(get_db)):
    results = autopsy_wrapper.run_sleuthkit(req.image_path, req.scan_type)
    inv = _save(db, req.image_path, f"sleuthkit_{req.scan_type}", results)
    return {"id": inv.id, "status": inv.status, "results": results}

@app.get("/analyze/ghidra/progress")
def ghidra_progress(file_path: str = None):
    return ghidra_wrapper.get_progress(file_path)

@app.post("/analyze/ghidra")
def analyze_ghidra(req: GhidraRequest, db: Session = Depends(get_db)):
    results = ghidra_wrapper.run_headless_analysis(
        req.file_path, extract_code=req.extract_code, timeout=req.timeout
    )
    inv = _save(db, req.file_path, "ghidra", results)
    return {"id": inv.id, "status": inv.status, "results": results}


@app.post("/analyze/androguard")
def analyze_androguard(req: MobileRequest, db: Session = Depends(get_db)):
    results = androguard_wrapper.analyze_apk(req.file_path)
    inv = _save(db, req.file_path, "androguard", results)
    return {"id": inv.id, "status": inv.status, "results": results}

@app.post("/analyze/mobsf")
def analyze_mobsf(req: MobileRequest, db: Session = Depends(get_db)):
    results = mobsf_wrapper.run_mobsf_scan(req.file_path)
    
    if not isinstance(results, dict):
        results = {"error": str(results)}
    elif isinstance(results, str):
        results = {"error": results}
    
    if "error" in results:
        inv = models.Investigation(
            filename=req.file_path, 
            tool_used="mobsf", 
            status="Failed"
        )
        inv.results = json.dumps(results)
        db.add(inv)
        db.commit()
        db.refresh(inv)
        return {"id": inv.id, "status": inv.status, "results": results}
    
    inv = _save(db, req.file_path, "mobsf", results)
    return {"id": inv.id, "status": inv.status, "results": results}

class MobSFDynamicRequest(BaseModel):
    file_path: str
    wait_time: int = 30

@app.post("/analyze/mobsf_dynamic")
def analyze_mobsf_dynamic(req: MobSFDynamicRequest, db: Session = Depends(get_db)):
    results = mobsf_wrapper.run_mobsf_dynamic_scan(req.file_path, req.wait_time)
    
    if "error" in results and "APK file not found" in results["error"]:
        inv = models.Investigation(
            filename=req.file_path, 
            tool_used="mobsf_dynamic", 
            status="Failed"
        )
        inv.results = json.dumps(results)
        db.add(inv)
        db.commit()
        db.refresh(inv)
        return {"id": inv.id, "status": inv.status, "results": results}
    
    inv = _save(db, req.file_path, "mobsf_dynamic", results)
    return {"id": inv.id, "status": inv.status, "results": results}
@app.post("/analyze/volatility")
def analyze_volatility(req: MemoryRequest, db: Session = Depends(get_db)):
    results = volatility_wrapper.run_volatility(req.file_path, req.scan_type)
    inv = _save(db, req.file_path, f"volatility_{req.scan_type}", results)
    return {"id": inv.id, "status": inv.status, "results": results}

@app.post("/analyze/threat_intel")
def analyze_threat(req: ThreatIntelRequest, db: Session = Depends(get_db)):
    results = threat_intel_wrapper.run_intel_scan(req.target, req.scan_type, req.api_key)
    inv = _save(db, req.target, f"threat_{req.scan_type}", results)
    return {"id": inv.id, "status": inv.status, "results": results}

@app.post("/analyze/network")
def analyze_network(req: NetworkRequest, db: Session = Depends(get_db)):
    results = network_wrapper.analyze_pcap(req.file_path, req.scan_type)
    inv = _save(db, req.file_path, f"tshark_{req.scan_type}", results)
    return {"id": inv.id, "status": inv.status, "results": results}

@app.post("/analyze/email")
def analyze_email(req: GenericFileRequest, db: Session = Depends(get_db)):
    results = email_wrapper.analyze_email(req.file_path)
    inv = _save(db, req.file_path, "eml_parser", results)
    return {"id": inv.id, "status": inv.status, "results": results}

@app.post("/analyze/evtx")
def analyze_evtx(req: GenericFileRequest, db: Session = Depends(get_db)):
    results = evtx_wrapper.parse_evtx(req.file_path)
    inv = _save(db, req.file_path, "evtx_parser", results)
    return {"id": inv.id, "status": inv.status, "results": results}

@app.post("/analyze/stego")
def analyze_stego(req: GenericFileRequest, db: Session = Depends(get_db)):
    results = stego_wrapper.check_stego(req.file_path)
    inv = _save(db, req.file_path, "steghide", results)
    return {"id": inv.id, "status": inv.status, "results": results}

@app.post("/analyze/hash")
def analyze_hash(req: GenericFileRequest, db: Session = Depends(get_db)):
    results = hash_wrapper.crack_hash(req.file_path)
    inv = _save(db, req.file_path, "john_the_ripper", results)
    return {"id": inv.id, "status": inv.status, "results": results}

@app.post("/analyze/brute")
def analyze_brute(req: BruteForceRequest, db: Session = Depends(get_db)):
    results = brute_wrapper.run_brute_force(
        mode=req.mode, target=req.target, username=req.username,
        username_field=req.username_field, password_field=req.password_field,
        success_string=req.success_string, failure_string=req.failure_string,
        port=req.port, wordlist_path=req.wordlist_path, hash_type=req.hash_type,
        max_attempts=req.max_attempts, threads=req.threads
    )
    inv = _save(db, req.target, f"brute_{req.mode}", results)
    return {"id": inv.id, "status": inv.status, "results": results}

@app.post("/analyze/registry")
def analyze_registry(req: RegistryRequest, db: Session = Depends(get_db)):
    results = registry_wrapper.crack_registry(req.sam_path, req.system_path)
    inv = _save(db, req.sam_path, "registry_cracking", results)
    return {"id": inv.id, "status": inv.status, "results": results}

@app.post("/analyze/ip_resolver")
def analyze_ip_resolver(req: IPResolverRequest, db: Session = Depends(get_db)):
    results = ip_resolver_wrapper.resolve_ip(req.target)
    inv = _save(db, req.target, "ip_resolver", results)
    return {"id": inv.id, "status": inv.status, "results": results}

@app.get("/history")
def get_history(db: Session = Depends(get_db)):
    records = db.query(models.Investigation).order_by(models.Investigation.created_at.desc()).all()
    out = []
    for r in records:
        try:
            res_json = json.loads(r.results) if r.results else None
        except Exception:
            res_json = r.results
        out.append({"id": r.id, "filename": r.filename, "status": r.status,
                    "tool_used": r.tool_used, "created_at": r.created_at, "results": res_json})
    return out

import html as html_lib

@app.get("/report/{inv_id}", response_class=HTMLResponse)
def generate_report(inv_id: int, db: Session = Depends(get_db)):
    inv = db.query(models.Investigation).filter(models.Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    
    try:
        res_json = json.loads(inv.results) if inv.results else {}
        pretty_json = json.dumps(res_json, indent=4)
    except Exception:
        pretty_json = str(inv.results)
        
    safe_json = html_lib.escape(pretty_json)
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CyberX Forensics Report - {inv.filename}</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; background-color: #f4f4f9; color: #333; }}
            .container {{ max-width: 900px; margin: 40px auto; background: #fff; padding: 40px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); border-top: 6px solid #e74c3c; }}
            .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #eee; padding-bottom: 20px; margin-bottom: 30px; }}
            h1 {{ margin: 0; color: #2c3e50; font-size: 28px; }}
            .badge {{ background: #2c3e50; color: #fff; padding: 6px 12px; border-radius: 4px; font-weight: bold; font-size: 14px; text-transform: uppercase; }}
            .info-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 30px; background: #f8f9fa; padding: 20px; border-radius: 6px; border: 1px solid #dee2e6; }}
            .info-item label {{ font-weight: bold; color: #6c757d; font-size: 12px; text-transform: uppercase; display: block; margin-bottom: 4px; }}
            .info-item span {{ font-size: 16px; color: #212529; word-break: break-all; }}
            h2 {{ color: #2c3e50; font-size: 20px; border-bottom: 1px solid #eee; padding-bottom: 10px; margin-top: 40px; }}
            pre {{ background: #1e1e1e; color: #d4d4d4; padding: 20px; border-radius: 6px; overflow-x: auto; font-size: 14px; line-height: 1.5; border: 1px solid #333; }}
            .footer {{ margin-top: 40px; text-align: center; color: #7f8c8d; font-size: 12px; border-top: 1px solid #eee; padding-top: 20px; }}
            .print-btn {{ background: #e74c3c; color: #fff; border: none; padding: 10px 20px; font-size: 16px; border-radius: 4px; cursor: pointer; font-weight: bold; transition: background 0.3s; }}
            .print-btn:hover {{ background: #c0392b; }}
            @media print {{
                .print-btn {{ display: none; }}
                .container {{ box-shadow: none; margin: 0; border: none; }}
                body {{ background: #fff; }}
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div>
                    <h1>CyberX Forensics Report</h1>
                    <div style="margin-top: 8px; color: #7f8c8d;">Generated by IFSO Cyber Forensics Platform</div>
                </div>
                <button class="print-btn" onclick="window.print()">🖨️ Print to PDF</button>
            </div>
            
            <div class="info-grid">
                <div class="info-item">
                    <label>Investigation ID</label>
                    <span>CX-{inv.id:06d}</span>
                </div>
                <div class="info-item">
                    <label>Analysis Tool</label>
                    <span><span class="badge">{inv.tool_used}</span></span>
                </div>
                <div class="info-item">
                    <label>Target / Filename</label>
                    <span>{inv.filename}</span>
                </div>
                <div class="info-item">
                    <label>Timestamp</label>
                    <span>{inv.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}</span>
                </div>
                <div class="info-item">
                    <label>Status</label>
                    <span style="color: {'#27ae60' if inv.status == 'Completed' else '#e74c3c' if inv.status == 'Failed' else '#f39c12'}; font-weight: bold;">{inv.status}</span>
                </div>
            </div>

            <h2>Raw Analysis Artifacts</h2>
            <pre><code>{safe_json}</code></pre>

            <div class="footer">
                <strong>CONFIDENTIAL DOCUMENT</strong><br>
                This forensic report was automatically generated for authorized cyber-police investigations.
            </div>
        </div>
    </body>
    </html>
    """
    return html_content


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

