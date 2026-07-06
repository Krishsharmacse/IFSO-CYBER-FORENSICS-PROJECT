import os
import requests

# Assuming MobSF is running locally. By default, it runs on port 8000.
# Because our FastAPI is also on 8000, you should run MobSF on port 8001:
# python manage.py runserver 127.0.0.1:8001
MOBSF_URL = "http://127.0.0.1:8001"
MOBSF_API_KEY = "fixed-mobsf-api-key"

def analyze_apk(file_path: str):
    """
    Uploads an APK to a running MobSF instance for deep automated malware analysis.
    """
    if not os.path.exists(file_path):
        return {"error": f"APK file not found: {file_path}"}
        
    if MOBSF_API_KEY == "YOUR_MOBSF_API_KEY":
        return {"error": "MobSF API key not configured. Please start MobSF, get the REST API Key from its dashboard, and update mobsf_wrapper.py"}
        
    try:
        headers = {'Authorization': MOBSF_API_KEY}
        
        # 1. Upload to MobSF
        upload_url = f"{MOBSF_URL}/api/v1/upload"
        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f, 'application/octet-stream')}
            upload_res = requests.post(upload_url, headers=headers, files=files)
            
        if upload_res.status_code != 200:
            return {"error": f"MobSF Upload Failed: {upload_res.text}"}
            
        upload_data = upload_res.json()
        hash_val = upload_data.get("hash")
        scan_type = upload_data.get("scan_type")
        
        # 2. Trigger Scan
        scan_url = f"{MOBSF_URL}/api/v1/scan"
        scan_res = requests.post(scan_url, headers=headers, data={'hash': hash_val, 'scan_type': scan_type})
        
        if scan_res.status_code != 200:
             return {"error": f"MobSF Scan Failed: {scan_res.text}"}
             
        # 3. Get JSON Report Summary
        report_url = f"{MOBSF_URL}/api/v1/report_json"
        report_res = requests.post(report_url, headers=headers, data={'hash': hash_val})
        
        # 4. Download PDF Report
        pdf_url = f"{MOBSF_URL}/api/v1/download_pdf"
        pdf_res = requests.post(pdf_url, headers=headers, data={'hash': hash_val}, stream=True)
        
        pdf_filename = None
        if pdf_res.status_code == 200:
            os.makedirs("reports", exist_ok=True)
            pdf_filename = f"{hash_val}_mobsf_report.pdf"
            pdf_path = os.path.abspath(f"reports/{pdf_filename}")
            with open(pdf_path, 'wb') as f:
                for chunk in pdf_res.iter_content(chunk_size=8192):
                    f.write(chunk)
                    
        return {
            "message": "Analysis Complete!",
            "pdf_report_url": f"/reports/{pdf_filename}" if pdf_filename else None,
            "mobsf_summary": report_res.json()
        }
        
    except requests.exceptions.ConnectionError:
        return {"error": f"Could not connect to MobSF. Please make sure MobSF is running on {MOBSF_URL}"}
    except Exception as e:
        return {"error": str(e)}
