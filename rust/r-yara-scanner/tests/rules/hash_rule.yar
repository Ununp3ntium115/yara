import "hash"

rule CheckMD5Hash {
    meta:
        description = "Check for specific content via MD5"

    strings:
        $test = "Hello, YARA!"

    condition:
        $test
}

rule DetectKnownPattern {
    strings:
        $pattern1 = "malicious"
        $pattern2 = "suspicious"

    condition:
        any of them
}
