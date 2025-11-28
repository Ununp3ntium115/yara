import "elf"

rule DetectELF {
    meta:
        description = "Detect ELF file format"
        filetype = "ELF"

    strings:
        $elf_magic = { 7F 45 4C 46 }

    condition:
        $elf_magic at 0
}

rule ELF64Bit {
    strings:
        $elf_magic = { 7F 45 4C 46 }
        $elf_class_64 = { 02 }

    condition:
        $elf_magic at 0 and $elf_class_64 at 4
}
