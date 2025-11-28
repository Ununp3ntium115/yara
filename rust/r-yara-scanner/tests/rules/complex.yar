import "pe"
import "hash"
import "math"

private rule HasMZHeader {
    strings:
        $mz = { 4D 5A }

    condition:
        $mz at 0
}

rule ComplexDetection : malware suspicious {
    meta:
        description = "Complex rule with all features"
        author = "R-YARA"
        version = 2
        severity = 8
        malicious = true

    strings:
        $mz = { 4D 5A }
        $text1 = "malware" nocase
        $text2 = "virus" wide
        $hex1 = { 90 90 90 90 }
        $hex2 = { E8 ?? ?? ?? ?? }
        $regex = /evil[0-9]+/i

    condition:
        HasMZHeader and
        (
            ($text1 or $text2) or
            (2 of ($hex*)) or
            $regex
        ) and
        filesize < 10485760 and
        filesize > 1024
}

rule ArithmeticCondition {
    condition:
        (10 + 20) * 2 == 60 and
        (5 << 2) == 20
}

rule StringCount {
    strings:
        $a = "test"
        $b = "example"

    condition:
        (#a >= 1 and #b >= 1) or
        #a > 5
}

rule StringAtOffset {
    strings:
        $header = { 4D 5A }
        $sig = "SIGN"

    condition:
        $header at 0 or
        $sig at 100
}

rule QuantifierExpression {
    strings:
        $s1 = "string1"
        $s2 = "string2"
        $s3 = "string3"
        $s4 = "string4"

    condition:
        3 of ($s*) or
        all of them
}
