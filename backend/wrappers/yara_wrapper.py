import yara
import os

def run_yara(rules_path: str, file_path: str):
    """
    Compiles a YARA rule and scans a file for matches.
    """
    if not os.path.exists(rules_path):
        return {"error": f"Rules file not found: {rules_path}"}
    if not os.path.exists(file_path):
        return {"error": f"Target file not found: {file_path}"}
        
    try:
        rules = yara.compile(filepath=rules_path)
        matches = rules.match(file_path)
        
        # Format the matches into a dictionary list
        formatted_matches = []
        for match in matches:
            formatted_matches.append({
                "rule": match.rule,
                "namespace": match.namespace,
                "tags": match.tags,
                "meta": match.meta
            })
            
        return {"matches": formatted_matches}
    except yara.SyntaxError as e:
         return {"error": f"Yara Syntax Error: {e}"}
    except Exception as e:
        return {"error": str(e)}
