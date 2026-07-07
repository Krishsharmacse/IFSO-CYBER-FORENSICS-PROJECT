import requests
import whois
import hashlib
import os

def analyze_threat(target: str, scan_type: str, api_key: str = None):
    """
    Performs Threat Intelligence lookups based on scan_type.
    - ip: Free IP-API lookup
    - whois: Python-whois lookup
    - virustotal: VT File Hash Lookup (Requires API Key)
    - abuseipdb: AbuseIPDB IP lookup (Requires API Key)
    - shodan: Shodan Host lookup (Requires API Key)
    - malwarebazaar: MalwareBazaar Hash Lookup (Free, no API key required)
    - alienvault: AlienVault OTX Lookup (Requires API Key)
    """
    results = {}
    try:
        if scan_type == "ip":
            # Free IP-API lookup
            res = requests.get(f"http://ip-api.com/json/{target}?fields=status,message,country,city,isp,as,org,lat,lon,reverse")
            if res.status_code == 200:
                results["ip_info"] = res.json()
            else:
                results["error"] = "Failed to fetch IP info"

        elif scan_type == "whois":
            # Python-whois lookup
            domain = whois.whois(target)
            results["whois_info"] = {
                "registrar": domain.registrar,
                "creation_date": str(domain.creation_date),
                "expiration_date": str(domain.expiration_date),
                "name_servers": domain.name_servers,
                "dnssec": domain.dnssec,
                "status": domain.status
            }
            
        elif scan_type == "virustotal":
            api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY")
            if not api_key:
                return {"error": "VirusTotal API key is required. Provide it in UI or .env"}
            
            # Target is expected to be a file path for VirusTotal
            if not os.path.exists(target):
                return {"error": f"File not found: {target}"}
                
            # Hash the file to lookup
            sha256_hash = hashlib.sha256()
            with open(target, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            file_hash = sha256_hash.hexdigest()
            
            headers = {"x-apikey": api_key}
            res = requests.get(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers=headers)
            
            if res.status_code == 200:
                data = res.json().get("data", {}).get("attributes", {})
                results["virustotal"] = {
                    "hash": file_hash,
                    "malicious_hits": data.get("last_analysis_stats", {}).get("malicious", 0),
                    "undetected_hits": data.get("last_analysis_stats", {}).get("undetected", 0),
                    "reputation": data.get("reputation", 0),
                    "suggested_threat_label": data.get("popular_threat_classification", {}).get("suggested_threat_label", "Unknown")
                }
            elif res.status_code == 404:
                 results["virustotal"] = {"message": "File hash not found in VirusTotal database. Uploading full files via API requires additional setup."}
            else:
                 results["error"] = f"VirusTotal API Error: {res.text}"

        elif scan_type == "abuseipdb":
            api_key = api_key or os.getenv("ABUSEIPDB_API_KEY")
            if not api_key:
                return {"error": "AbuseIPDB API key is required. Provide it in UI or .env"}
            
            headers = {
                'Accept': 'application/json',
                'Key': api_key
            }
            params = {
                'ipAddress': target,
                'maxAgeInDays': '90'
            }
            res = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params)
            if res.status_code == 200:
                results["abuseipdb"] = res.json().get("data", {})
            else:
                results["error"] = f"AbuseIPDB API Error: {res.text}"
                
        elif scan_type == "shodan":
            api_key = api_key or os.getenv("SHODAN_API_KEY")
            if not api_key:
                return {"error": "Shodan API key is required. Provide it in UI or .env"}
                
            res = requests.get(f"https://api.shodan.io/shodan/host/{target}?key={api_key}")
            if res.status_code == 200:
                data = res.json()
                results["shodan"] = {
                    "ip": data.get("ip_str"),
                    "organization": data.get("org"),
                    "os": data.get("os"),
                    "ports": data.get("ports", []),
                    "vulns": data.get("vulns", [])
                }
            elif res.status_code == 404:
                results["shodan"] = {"message": "No information available for that IP in Shodan."}
            else:
                results["error"] = f"Shodan API Error: {res.text}"

        elif scan_type == "malwarebazaar":
            api_key = api_key or os.getenv("MALWAREBAZAAR_API_KEY")
            if not api_key:
                return {"error": "MalwareBazaar API key is required. Provide it in UI or .env"}

            # Target is expected to be a file path for MalwareBazaar
            if not os.path.exists(target):
                return {"error": f"File not found: {target}"}
                
            sha256_hash = hashlib.sha256()
            with open(target, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            file_hash = sha256_hash.hexdigest()
            
            headers = {"Auth-Key": api_key}
            data = {'query': 'get_info', 'hash': file_hash}
            res = requests.post("https://mb-api.abuse.ch/api/v1/", headers=headers, data=data)
            if res.status_code == 200:
                mb_data = res.json()
                if mb_data.get("query_status") == "hash_not_found":
                    results["malwarebazaar"] = {"message": "File hash not found in MalwareBazaar database."}
                else:
                    results["malwarebazaar"] = mb_data
            else:
                results["error"] = f"MalwareBazaar API Error: {res.text}"

        elif scan_type == "alienvault":
            api_key = api_key or os.getenv("ALIENVAULT_API_KEY")
            if not api_key:
                return {"error": "AlienVault OTX API key is required. Provide it in UI or .env"}
            
            headers = {"X-OTX-API-KEY": api_key}
            
            # Simple heuristic: if it consists of digits and dots, assume IPv4
            if target.replace(".", "").isdigit():
                indicator_type = "IPv4"
            else:
                indicator_type = "domain"
                
            res = requests.get(f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{target}/general", headers=headers)
            if res.status_code == 200:
                data = res.json()
                results["alienvault"] = {
                    "pulse_count": data.get("pulse_info", {}).get("count", 0),
                    "pulses": [p.get("name") for p in data.get("pulse_info", {}).get("pulses", [])[:5]],
                    "base_indicator": data.get("base_indicator", {})
                }
            elif res.status_code == 404:
                results["alienvault"] = {"message": "No pulse information available for that target in AlienVault OTX."}
            else:
                results["error"] = f"AlienVault API Error: {res.text}"
                
        else:
            results["error"] = f"Unknown scan type: {scan_type}"

        results["status"] = "Success" if "error" not in results else "Failed"
    except Exception as e:
        results["error"] = str(e)
        results["status"] = "Failed"
        
    return results
