import json
import os
import exifread

def run_exiftool(file_path: str):
    """
    Extracts EXIF metadata from an image file using the pure Python `exifread` library.
    This acts as a lightweight replacement for the Perl-based exiftool.
    """
    if not os.path.exists(file_path):
        return {"error": f"File not found: {file_path}"}

    try:
        if os.path.isdir(file_path):
            all_meta = []
            for root, _, files in os.walk(file_path):
                for file in files:
                    full_path = os.path.join(root, file)
                    meta = _process_single_file(full_path)
                    if meta:
                        meta["FileName"] = file
                        all_meta.append(meta)
            return {"total_files_scanned": len(all_meta), "all_metadata": all_meta}
        else:
            return _process_single_file(file_path)

    except Exception as e:
        return {"error": str(e)}

def _process_single_file(file_path: str):
    try:
        with open(file_path, 'rb') as f:
            tags = exifread.process_file(f, details=False)
            
            output = {}
            for tag, val in tags.items():
                if tag not in ('JPEGThumbnail', 'TIFFThumbnail', 'Filename', 'EXIF MakerNote'):
                    output[tag] = str(val)
            
            if not output:
                return {"message": "No EXIF metadata found or file format not supported by exifread."}
            return output
    except Exception as e:
        return {"error": f"Error parsing {file_path}: {str(e)}"}
