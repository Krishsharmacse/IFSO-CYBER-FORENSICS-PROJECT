import eml_parser
import json
import datetime
import os

def json_serial(obj):
    if isinstance(obj, datetime.datetime):
        return obj.isoformat()

def analyze_email(file_path: str):
    if not os.path.exists(file_path):
        return {"error": f"Email file not found: {file_path}"}
    try:
        ep = eml_parser.EmlParser(include_attachment_data=False)
        parsed_eml = ep.decode_email(file_path)
        res_str = json.dumps(parsed_eml, default=json_serial)
        return {"status": "Success", "email_data": json.loads(res_str)}
    except Exception as e:
        return {"error": str(e)}
