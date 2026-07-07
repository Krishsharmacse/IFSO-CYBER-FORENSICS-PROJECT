/*
===============================================================================
 YARA Rules for Android APK and PDF File Detection
 Author      : Forensics Platform
 Version     : 1.0
 Description : Detects APK files, suspicious modded APKs, PDF files,
               and potentially malicious PDF features.
===============================================================================
*/

import "pe"

/* ============================================================================
   ANDROID APK DETECTION
   ========================================================================== */

rule Is_APK_File
{
    meta:
        description = "Detects Android APK files by checking ZIP signature and Android components"
        author = "Forensics Platform"
        version = "1.0"

    strings:
        $zip_magic = { 50 4B 03 04 }     // PK\x03\x04
        $manifest = "AndroidManifest.xml" ascii
        $dex = "classes.dex" ascii
        $resources = "resources.arsc" ascii

    condition:
        $zip_magic at 0 and
        (2 of ($manifest, $dex, $resources))
}

/* ============================================================================
   SUSPICIOUS MODDED APK
   ========================================================================== */

rule Suspicious_Modded_APK
{
    meta:
        description = "Detects common modified APKs such as GBWhatsApp and similar mods"
        author = "Forensics Platform"
        severity = "medium"

    strings:
        $gb = "gbwhatsapp" ascii nocase
        $fm = "fmwhatsapp" ascii nocase
        $yo = "yowhatsapp" ascii nocase
        $fouad = "FouadMods" ascii nocase
        $alex = "AlexMods" ascii nocase
        $delta = "Delta WhatsApp" ascii nocase
        $plus = "WhatsApp Plus" ascii nocase

    condition:
        Is_APK_File and any of them
}

/* ============================================================================
   PDF FILE DETECTION
   ========================================================================== */

rule Is_PDF_File
{
    meta:
        description = "Detects PDF documents"
        author = "Forensics Platform"
        version = "1.0"

    strings:
        $header = {25 50 44 46 2D}       // %PDF-
        $xref = "xref" ascii
        $trailer = "trailer" ascii
        $catalog = "/Catalog" ascii
        $pages = "/Pages" ascii
        $eof = "%%EOF" ascii

    condition:
        $header at 0 and
        (2 of ($xref,$trailer,$catalog,$pages,$eof))
}

/* ============================================================================
   PDF WITH JAVASCRIPT
   ========================================================================== */

rule Suspicious_PDF_JavaScript
{
    meta:
        description = "Detects embedded JavaScript in PDF"
        author = "Forensics Platform"
        severity = "high"

    strings:
        $js1 = "/JavaScript" ascii nocase
        $js2 = "/JS" ascii
        $open = "/OpenAction" ascii
        $aa = "/AA" ascii

    condition:
        Is_PDF_File and any of them
}

/* ============================================================================
   PDF WITH EMBEDDED FILES
   ========================================================================== */

rule Suspicious_PDF_Embedded_File
{
    meta:
        description = "Detects embedded files in PDF"
        author = "Forensics Platform"
        severity = "high"

    strings:
        $embedded = "/EmbeddedFile" ascii
        $filespec = "/Filespec" ascii
        $ef = "/EF" ascii
        $launch = "/Launch" ascii
        $exe = ".exe" ascii nocase

    condition:
        Is_PDF_File and any of them
}

/* ============================================================================
   PDF WITH FLASH CONTENT
   ========================================================================== */

rule Suspicious_PDF_Flash
{
    meta:
        description = "Detects embedded Flash content"
        author = "Forensics Platform"

    strings:
        $flash1 = ".swf" ascii nocase
        $flash2 = "application/x-shockwave-flash" ascii

    condition:
        Is_PDF_File and any of them
}

/* ============================================================================
   COMMON PDF EXPLOIT FEATURES
   ========================================================================== */

rule Suspicious_PDF_Exploit
{
    meta:
        description = "Detects common malicious PDF exploit indicators"
        author = "Forensics Platform"
        severity = "critical"

    strings:
        $objstm = "/ObjStm" ascii
        $richmedia = "/RichMedia" ascii
        $launch = "/Launch" ascii
        $submit = "/SubmitForm" ascii
        $uri = "/URI" ascii
        $javascript = "/JavaScript" ascii
        $openaction = "/OpenAction" ascii

    condition:
        Is_PDF_File and
        2 of them
}

/* ============================================================================
   PDF WITH SUSPICIOUS URLS
   ========================================================================== */

rule Suspicious_PDF_URL
{
    meta:
        description = "Detects URLs embedded in PDF"
        author = "Forensics Platform"
        severity = "medium"

    strings:
        $http = "http://" ascii nocase
        $https = "https://" ascii nocase
        $uri = "/URI" ascii

    condition:
        Is_PDF_File and
        ($uri and (1 of ($http,$https)))
}

/* ============================================================================
   PDF WITH AUTO ACTIONS
   ========================================================================== */

rule Suspicious_PDF_AutoAction
{
    meta:
        description = "Detects automatic actions executed when opening a PDF"
        author = "Forensics Platform"
        severity = "high"

    strings:
        $open = "/OpenAction" ascii
        $aa = "/AA" ascii

    condition:
        Is_PDF_File and any of them
}

/* ============================================================================
   APK CONTAINING NATIVE LIBRARIES
   ========================================================================== */

rule APK_With_Native_Code
{
    meta:
        description = "Detects APK containing native shared libraries"
        author = "Forensics Platform"

    strings:
        $lib = "lib/" ascii
        $so = ".so" ascii

    condition:
        Is_APK_File and
        all of them
}

/* ============================================================================
   APK REQUESTING DANGEROUS PERMISSIONS
   ========================================================================== */

rule APK_Dangerous_Permissions
{
    meta:
        description = "Detects APK requesting dangerous Android permissions"
        author = "Forensics Platform"
        severity = "medium"

    strings:
        $sms = "android.permission.SEND_SMS" ascii
        $contacts = "android.permission.READ_CONTACTS" ascii
        $storage = "android.permission.WRITE_EXTERNAL_STORAGE" ascii
        $overlay = "android.permission.SYSTEM_ALERT_WINDOW" ascii
        $install = "android.permission.REQUEST_INSTALL_PACKAGES" ascii
        $accessibility = "android.permission.BIND_ACCESSIBILITY_SERVICE" ascii

    condition:
        Is_APK_File and
        any of them
}