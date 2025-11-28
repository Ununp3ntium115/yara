//! Example demonstrating module function usage in R-YARA
//!
//! This example shows how to use hash, math, pe, and elf module functions
//! in YARA rules.

use r_yara_compiler::Compiler;
use r_yara_matcher::PatternMatcher;
use r_yara_parser::parse;
use r_yara_vm::{ScanContext, VM};

fn main() {
    println!("R-YARA Module Functions Example\n");

    // Example 1: Hash module functions
    println!("=== Hash Module Example ===");
    let hash_rule = r#"
        import "hash"

        rule hash_detection {
            condition:
                hash.md5(0, filesize) == "098f6bcd4621d373cade4e832627b4f6" or
                hash.sha256(0, filesize) == "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        }
    "#;

    let data = b"test";
    run_rule(hash_rule, data, "test data");

    // Example 2: Math module functions
    println!("\n=== Math Module Example ===");
    let math_rule = r#"
        import "math"

        rule entropy_check {
            condition:
                math.entropy(0, filesize) > 3.0 and
                math.mean(0, filesize) > 50
        }
    "#;

    let random_data: Vec<u8> = (0..=255).cycle().take(1024).collect();
    run_rule(math_rule, &random_data, "random-looking data");

    // Example 3: PE module functions
    println!("\n=== PE Module Example ===");
    let pe_rule = r#"
        import "pe"

        rule pe_check {
            condition:
                not pe.is_pe()
        }
    "#;

    run_rule(pe_rule, b"not a PE file", "non-PE data");

    // Example 4: ELF module functions
    println!("\n=== ELF Module Example ===");
    let elf_rule = r#"
        import "elf"

        rule elf_check {
            condition:
                elf.is_elf()
        }
    "#;

    let elf_data = b"\x7fELF\x02\x01\x01\x00";
    run_rule(elf_rule, elf_data, "ELF header");

    // Example 5: Combined modules
    println!("\n=== Combined Modules Example ===");
    let combined_rule = r#"
        import "hash"
        import "math"
        import "pe"
        import "elf"

        rule comprehensive_check {
            strings:
                $magic = "test"
            condition:
                $magic and
                math.entropy(0, filesize) > 0 and
                hash.crc32(0, filesize) > 0 and
                not pe.is_pe() and
                not elf.is_elf()
        }
    "#;

    run_rule(combined_rule, b"test data", "test data");

    println!("\n=== All Examples Complete ===");
}

fn run_rule(source: &str, data: &[u8], description: &str) {
    println!("Scanning: {}", description);

    match parse(source) {
        Ok(ast) => {
            let mut compiler = Compiler::new();
            match compiler.compile(&ast) {
                Ok(compiled) => {
                    match PatternMatcher::new(compiled.patterns.clone()) {
                        Ok(matcher) => {
                            let pattern_matches = matcher.scan(data);
                            let ctx = ScanContext::new(data).with_matches(pattern_matches);
                            let vm = VM::new(&compiled, &matcher);

                            match vm.scan(&ctx) {
                                Ok(matches) => {
                                    if matches.is_empty() {
                                        println!("  ✗ No matches");
                                    } else {
                                        for m in matches {
                                            println!("  ✓ Rule matched: {}", m.name);
                                        }
                                    }
                                }
                                Err(e) => println!("  Error scanning: {}", e),
                            }
                        }
                        Err(e) => println!("  Error creating matcher: {}", e),
                    }
                }
                Err(e) => println!("  Error compiling: {}", e),
            }
        }
        Err(e) => println!("  Error parsing: {}", e),
    }
}
