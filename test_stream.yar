rule TestRule {
    meta:
        description = "Test streaming"
    condition:
        pe.number_of_sections > 10 and hash.md5("test") == "abc"
}
