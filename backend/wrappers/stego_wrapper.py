import os

def check_stego(file_path: str):
    """
    Checks for hidden data inside images using stegano (pure Python).
    """
    if not os.path.exists(file_path):
        return {"error": f"Image file not found: {file_path}"}

    try:
        from stegano import lsb
    except ImportError:
        return {"error": "stegano is not installed. Run: pip install stegano"}

    try:
        secret = lsb.reveal(file_path)
        if secret:
            return {"status": "Success", "output": [f"Hidden data found: {secret}"]}
        else:
            return {"status": "Success", "output": ["No LSB steganography data found."]}

    except Exception as e:
        return {"error": f"Error during stego check (or file format not supported): {str(e)}"}

analyze_stego = check_stego
