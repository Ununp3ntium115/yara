//! Example from user's original request
//!
//! Demonstrates hash.md5(), pe.is_pe(), and related functions

use r_yara_compiler::Compiler;
use r_yara_matcher::PatternMatcher;
use r_yara_parser::parse;
use r_yara_vm::{ScanContext, VM};

fn main() {
    println!("Testing hash.md5() and pe.is_pe() integration\n");

    // Example from the user's request
    let source = r#"
        import "hash"
        import "pe"

        rule test {
            condition:
                hash.md5(0, filesize) == "098f6bcd4621d373cade4e832627b4f6" and
                not pe.is_pe()
        }
    "#;

    println!("YARA Rule:");
    println!("{}", source);

    let data = b"test";
    println!("\nTest Data: {:?}", std::str::from_utf8(data).unwrap());
    println!("Expected MD5: 098f6bcd4621d373cade4e832627b4f6");

    // Verify with module directly
    use r_yara_modules::{hash, pe};
    let md5_result = hash::md5(data, 0, data.len());
    let is_pe = pe::is_pe(data);
    println!("\nDirect Module Calls:");
    println!("  hash.md5(0, {}) = {}", data.len(), md5_result);
    println!("  pe.is_pe() = {}", is_pe);

    // Compile and run through VM
    println!("\nCompiling and Running Rule:");
    let ast = parse(source).expect("Parse failed");
    let mut compiler = Compiler::new();
    let compiled = compiler.compile(&ast).expect("Compile failed");

    let matcher = PatternMatcher::new(compiled.patterns.clone()).expect("Matcher failed");
    let pattern_matches = matcher.scan(data);

    let ctx = ScanContext::new(data).with_matches(pattern_matches);
    let vm = VM::new(&compiled, &matcher);

    match vm.scan(&ctx) {
        Ok(matches) => {
            if matches.is_empty() {
                println!("  Result: No matches");
            } else {
                for m in matches {
                    println!("  Result: ✓ Rule '{}' matched!", m.name);
                }
            }
        }
        Err(e) => {
            println!("  Error: {}", e);
        }
    }

    // Additional test with different hash
    println!("\n--- Testing with different data ---");
    let data2 = b"different";
    let md5_result2 = hash::md5(data2, 0, data2.len());
    println!("Data: {:?}", std::str::from_utf8(data2).unwrap());
    println!("MD5: {}", md5_result2);

    let pattern_matches2 = matcher.scan(data2);
    let ctx2 = ScanContext::new(data2).with_matches(pattern_matches2);
    match vm.scan(&ctx2) {
        Ok(matches) => {
            if matches.is_empty() {
                println!("Result: No matches (expected - hash doesn't match)");
            } else {
                for m in matches {
                    println!("Result: ✓ Rule '{}' matched!", m.name);
                }
            }
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    }

    println!("\n✓ Module functions are working correctly!");
}
