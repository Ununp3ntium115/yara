rule SimpleTextMatch {
    meta:
        description = "Simple text pattern matching"
        author = "R-YARA"

    strings:
        $text1 = "Hello"
        $text2 = "World"

    condition:
        any of them
}

rule ExactMatch {
    strings:
        $exact = "YARA"

    condition:
        $exact
}

rule MultipleMatches {
    strings:
        $a = "test"

    condition:
        #a > 2
}
