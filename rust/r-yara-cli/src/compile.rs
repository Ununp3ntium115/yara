use anyhow::{Context, Result};
use colored::Colorize;
use r_yara_compiler::Compiler;
use r_yara_parser::parse;
use std::fs;
use std::path::Path;

pub fn compile(rules_path: impl AsRef<Path>, output_path: impl AsRef<Path>) -> Result<()> {
    let rules_path = rules_path.as_ref();
    let output_path = output_path.as_ref();

    println!("{}", "Loading YARA rules...".blue());
    let rules_source = fs::read_to_string(rules_path)
        .with_context(|| format!("Failed to read {}", rules_path.display()))?;

    println!("{}", "Parsing rules...".blue());
    let ast = parse(&rules_source)
        .context("Failed to parse YARA rules")?;

    println!("{}", "Compiling rules...".blue());
    let mut compiler = Compiler::new();
    let compiled = compiler
        .compile(&ast)
        .context("Failed to compile YARA rules")?;

    println!(
        "{}",
        format!(
            "Compiled {} rules with {} patterns",
            compiled.rules.len(),
            compiled.patterns.len()
        )
        .green()
    );

    // For now, we'll save the compiled rules as JSON
    // TODO: Implement proper binary serialization once serde is added to compiler types
    println!("{}", "Serializing compiled rules to JSON...".blue());
    let json = serde_json::json!({
        "rules": compiled.rules.iter().map(|r| {
            serde_json::json!({
                "name": r.name.as_str(),
                "tags": r.tags.iter().map(|t| t.as_str()).collect::<Vec<_>>(),
                "is_private": r.is_private,
                "is_global": r.is_global,
                "code_start": r.code_start,
                "code_len": r.code_len,
            })
        }).collect::<Vec<_>>(),
        "pattern_count": compiled.patterns.len(),
        "code_len": compiled.code.len(),
    });

    let serialized = serde_json::to_vec_pretty(&json)?;

    println!("{}", format!("Writing to {}...", output_path.display()).blue());
    fs::write(output_path, serialized)
        .with_context(|| format!("Failed to write to {}", output_path.display()))?;

    let file_size = fs::metadata(output_path)?.len();
    println!(
        "{}",
        format!(
            "Successfully compiled {} rules to {} ({} bytes)",
            compiled.rules.len(),
            output_path.display(),
            file_size
        )
        .green()
        .bold()
    );

    Ok(())
}
