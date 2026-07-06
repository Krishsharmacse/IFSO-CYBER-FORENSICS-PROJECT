rule TestRule {
    meta:
        description = "This is a sample rule to test the Yara wrapper"
        author = "Antigravity"
        date = "2026-07-06"
    strings:
        $a = "MALICIOUS_STRING" ascii
    condition:
        $a
}
