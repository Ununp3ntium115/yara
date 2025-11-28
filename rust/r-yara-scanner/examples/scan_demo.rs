//! Comprehensive scanner demonstration
//!
//! Run with: cargo run --example scan_demo

use r_yara_scanner::{Scanner, scan_bytes};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== R-YARA Scanner Demo ===\n");

    // Example 1: Simple pattern matching
    println!("1. Simple pattern matching:");
    let rules = r#"
        rule detect_pe {
            strings:
                $mz = "MZ"
            condition:
                $mz at 0
        }
    "#;

    let pe_data = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00";
    let matches = scan_bytes(rules, pe_data)?;

    for m in &matches {
        println!("   ✓ Matched rule: {}", m.rule_name);
        for s in &m.strings {
            println!("     - {} at offsets: {:?}", s.identifier, s.offsets);
        }
    }

    // Example 2: Multiple rules with metadata
    println!("\n2. Multiple rules with metadata and tags:");
    let rules = r#"
        rule malware_signature : malware suspicious {
            meta:
                author = "R-YARA Team"
                severity = 8
                description = "Detects malicious patterns"

            strings:
                $api1 = "CreateRemoteThread"
                $api2 = "VirtualAllocEx"
                $api3 = "WriteProcessMemory"

            condition:
                2 of them
        }

        rule packer_detection : packer {
            meta:
                description = "Generic packer detection"

            strings:
                $upx = "UPX"
                $aspack = "ASPack"

            condition:
                any of them
        }
    "#;

    let scanner = Scanner::new(rules)?;
    let test_data = b"This binary uses CreateRemoteThread and WriteProcessMemory APIs for injection";
    let matches = scanner.scan_bytes(test_data)?;

    for m in &matches {
        println!("   ✓ Matched rule: {}", m.rule_name);
        println!("     Tags: {:?}", m.tags);
        println!("     Metadata:");
        for (key, value) in &m.meta {
            println!("       - {}: {:?}", key, value);
        }
        println!("     Matched strings:");
        for s in &m.strings {
            println!("       - {} (count: {})", s.identifier, s.offsets.len());
        }
    }

    // Example 3: File size checks
    println!("\n3. File size-based detection:");
    let rules = r#"
        rule large_file {
            condition:
                filesize > 50
        }

        rule small_file {
            condition:
                filesize < 20
        }
    "#;

    let scanner = Scanner::new(rules)?;

    let large_data = vec![0u8; 100];
    let matches = scanner.scan_bytes(&large_data)?;
    println!("   100-byte file matched: {:?}",
             matches.iter().map(|m| m.rule_name.as_str()).collect::<Vec<_>>());

    let small_data = vec![0u8; 10];
    let matches = scanner.scan_bytes(&small_data)?;
    println!("   10-byte file matched: {:?}",
             matches.iter().map(|m| m.rule_name.as_str()).collect::<Vec<_>>());

    // Example 4: String quantifiers
    println!("\n4. String quantifiers (all, any, N of):");
    let rules = r#"
        rule all_patterns {
            strings:
                $s1 = "pattern1"
                $s2 = "pattern2"
                $s3 = "pattern3"
            condition:
                all of them
        }

        rule any_pattern {
            strings:
                $a = "alpha"
                $b = "beta"
                $c = "gamma"
            condition:
                any of them
        }

        rule two_of_three {
            strings:
                $x = "first"
                $y = "second"
                $z = "third"
            condition:
                2 of them
        }
    "#;

    let scanner = Scanner::new(rules)?;

    let data1 = b"This has pattern1 and pattern2 and pattern3 all present";
    let matches = scanner.scan_bytes(data1)?;
    println!("   Data with all patterns: {:?}",
             matches.iter().map(|m| m.rule_name.as_str()).collect::<Vec<_>>());

    let data2 = b"This only has beta in it";
    let matches = scanner.scan_bytes(data2)?;
    println!("   Data with one pattern: {:?}",
             matches.iter().map(|m| m.rule_name.as_str()).collect::<Vec<_>>());

    let data3 = b"This has first and second but not the third one";
    let matches = scanner.scan_bytes(data3)?;
    println!("   Data with 2 of 3 patterns: {:?}",
             matches.iter().map(|m| m.rule_name.as_str()).collect::<Vec<_>>());

    // Example 5: String modifiers
    println!("\n5. String modifiers (nocase, wide):");
    let rules = r#"
        rule case_insensitive {
            strings:
                $text = "password" nocase
            condition:
                $text
        }
    "#;

    let scanner = Scanner::new(rules)?;

    let data = b"The PASSWORD is secret";
    let matches = scanner.scan_bytes(data)?;
    println!("   'PASSWORD' matched with nocase: {}", !matches.is_empty());

    // Example 6: Scanner statistics
    println!("\n6. Scanner statistics:");
    let rules = r#"
        rule rule1 { condition: true }
        rule rule2 { condition: true }
        rule rule3 { strings: $a = "test" condition: $a }
    "#;

    let scanner = Scanner::new(rules)?;
    println!("   Compiled {} rules", scanner.rule_count());
    println!("   Total {} patterns", scanner.pattern_count());

    println!("\n=== Demo Complete ===");

    Ok(())
}
