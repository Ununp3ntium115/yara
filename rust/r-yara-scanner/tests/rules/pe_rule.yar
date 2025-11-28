import "pe"

rule DetectPE {
    meta:
        description = "Detect PE file format"
        filetype = "PE"

    strings:
        $mz = { 4D 5A }
        $pe = "PE"

    condition:
        $mz at 0 and $pe
}

rule PEwithSections {
    strings:
        $mz = { 4D 5A }

    condition:
        $mz at 0 and filesize > 64
}
