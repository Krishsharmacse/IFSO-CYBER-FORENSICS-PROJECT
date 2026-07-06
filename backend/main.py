from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import os
from pydantic import BaseModel
from sqlalchemy.orm import Session
import database
import models
from wrappers import exiftool_wrapper, yara_wrapper, autopsy_wrapper, ghidra_wrapper, androguard_wrapper, mobsf_wrapper
import json

# Initialize database schema
models.Base.metadata.create_all(bind=database.engine)

app = FastAPI(
    title="Cyber Forensics Unified Platform API",
    description="A central API to manage and run various cyber forensics tools.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

os.makedirs("reports", exist_ok=True)
app.mount("/reports", StaticFiles(directory="reports"), name="reports")

# Dependency to get DB session
def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Request Models
class ExiftoolRequest(BaseModel):
    file_path: str

class YaraRequest(BaseModel):
    file_path: str
    rules_path: str

class AutopsyRequest(BaseModel):
    image_path: str

class GhidraRequest(BaseModel):
    file_path: str

class MobileRequest(BaseModel):
    file_path: str

@app.get("/")
def read_root():
    return {"message": "Welcome to the Cyber Forensics Unified Platform Backend"}

@app.post("/analyze/exiftool")
def analyze_exif(req: ExiftoolRequest, db: Session = Depends(get_db)):
    # Create DB record
    investigation = models.Investigation(
        filename=req.file_path, 
        tool_used="exiftool", 
        status="Running"
    )
    db.add(investigation)
    db.commit()
    db.refresh(investigation)
    
    # Run tool
    results = exiftool_wrapper.run_exiftool(req.file_path)
    
    # Update DB
    investigation.status = "Failed" if "error" in results else "Completed"
    investigation.results = json.dumps(results)
    db.commit()
    
    return {"id": investigation.id, "status": investigation.status, "results": results}

@app.post("/analyze/yara")
def analyze_yara(req: YaraRequest, db: Session = Depends(get_db)):
    # Create DB record
    investigation = models.Investigation(
        filename=req.file_path, 
        tool_used="yara", 
        status="Running"
    )
    db.add(investigation)
    db.commit()
    db.refresh(investigation)
    
    # Run tool
    results = yara_wrapper.run_yara(req.rules_path, req.file_path)
    
    # Update DB
    investigation.status = "Failed" if "error" in results else "Completed"
    investigation.results = json.dumps(results)
    db.commit()
    
    return {"id": investigation.id, "status": investigation.status, "results": results}

@app.post("/analyze/autopsy")
def analyze_autopsy(req: AutopsyRequest, db: Session = Depends(get_db)):
    # Create DB record
    investigation = models.Investigation(
        filename=req.image_path, 
        tool_used="autopsy_sleuthkit", 
        status="Running"
    )
    db.add(investigation)
    db.commit()
    db.refresh(investigation)
    
    # Run tool
    results = autopsy_wrapper.analyze_image(req.image_path)
    
    # Update DB
    investigation.status = "Failed" if "error" in results else "Completed"
    investigation.results = json.dumps(results)
    db.commit()
    
    return {"id": investigation.id, "status": investigation.status, "results": results}

@app.post("/analyze/ghidra")
def analyze_ghidra(req: GhidraRequest, db: Session = Depends(get_db)):
    # Create DB record
    investigation = models.Investigation(
        filename=req.file_path, 
        tool_used="ghidra", 
        status="Running"
    )
    db.add(investigation)
    db.commit()
    db.refresh(investigation)
    
    # Run tool
    results = ghidra_wrapper.analyze_binary(req.file_path)
    
    # Update DB
    investigation.status = "Failed" if "error" in results else "Completed"
    investigation.results = json.dumps(results)
    db.commit()
    
    return {"id": investigation.id, "status": investigation.status, "results": results}

@app.post("/analyze/androguard")
def analyze_androguard(req: MobileRequest, db: Session = Depends(get_db)):
    # Create DB record
    investigation = models.Investigation(
        filename=req.file_path, 
        tool_used="androguard", 
        status="Running"
    )
    db.add(investigation)
    db.commit()
    db.refresh(investigation)
    
    # Run tool
    results = androguard_wrapper.analyze_apk(req.file_path)
    
    # Update DB
    investigation.status = "Failed" if "error" in results else "Completed"
    investigation.results = json.dumps(results)
    db.commit()
    
    return {"id": investigation.id, "status": investigation.status, "results": results}

@app.post("/analyze/mobsf")
def analyze_mobsf(req: MobileRequest, db: Session = Depends(get_db)):
    # Create DB record
    investigation = models.Investigation(
        filename=req.file_path, 
        tool_used="mobsf", 
        status="Running"
    )
    db.add(investigation)
    db.commit()
    db.refresh(investigation)
    
    # Run tool
    results = mobsf_wrapper.analyze_apk(req.file_path)
    
    # Update DB
    investigation.status = "Failed" if "error" in results else "Completed"
    investigation.results = json.dumps(results)
    db.commit()
    
    return {"id": investigation.id, "status": investigation.status, "results": results}

@app.get("/investigations/")
def list_investigations(skip: int = 0, limit: int = 10, db: Session = Depends(get_db)):
    records = db.query(models.Investigation).order_by(models.Investigation.created_at.desc()).offset(skip).limit(limit).all()
    # Parse results back to JSON for output
    out = []
    for r in records:
        try:
             res_json = json.loads(r.results) if r.results else None
        except:
             res_json = r.results
             
        out.append({
            "id": r.id,
            "filename": r.filename,
            "status": r.status,
            "tool_used": r.tool_used,
            "created_at": r.created_at,
            "results": res_json
        })
    return out
