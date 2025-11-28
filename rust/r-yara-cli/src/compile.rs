use anyhow::{Context, Result};
use colored::Colorize;
use r_yara_compiler::{CompiledRules, Compiler};
use r_yara_parser::parse;
use std::fs;
use std::path::Path;

/// Compile YARA rules to binary format
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

    // Determine output format based on file extension
    let extension = output_path.extension().and_then(|e| e.to_str()).unwrap_or("");

    match extension {
        "json" => {
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
            fs::write(output_path, serialized)
                .with_context(|| format!("Failed to write to {}", output_path.display()))?;
        }
        _ => {
            // Default to binary format (.yarc, .yar, or any other extension)
            println!("{}", "Serializing compiled rules to binary format...".blue());
            compiled.save(output_path)
                .with_context(|| format!("Failed to write to {}", output_path.display()))?;
        }
    }

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

/// Load pre-compiled YARA rules
pub fn load_compiled(path: impl AsRef<Path>) -> Result<CompiledRules> {
    let path = path.as_ref();

    println!("{}", format!("Loading compiled rules from {}...", path.display()).blue());

    let compiled = CompiledRules::load(path)
        .with_context(|| format!("Failed to load compiled rules from {}", path.display()))?;

    println!(
        "{}",
        format!(
            "Loaded {} rules with {} patterns",
            compiled.rules.len(),
            compiled.patterns.len()
        )
        .green()
    );

    Ok(compiled)
}

/// Display information about compiled rules
pub fn info(rules_path: impl AsRef<Path>) -> Result<()> {
    let rules_path = rules_path.as_ref();

    let compiled = load_compiled(rules_path)?;

    println!("\n{}", "Compiled Rules Info:".bold());
    println!("  Rules: {}", compiled.rule_count());
    println!("  Patterns: {}", compiled.pattern_count());
    println!("  Bytecode instructions: {}", compiled.code.len());
    println!("  String constants: {}", compiled.strings.len());
    println!("  Imports: {:?}", compiled.imports.iter().map(|i| i.as_str()).collect::<Vec<_>>());

    println!("\n{}", "Rules:".bold());
    for rule in &compiled.rules {
        let modifiers = [
            if rule.is_private { Some("private") } else { None },
            if rule.is_global { Some("global") } else { None },
        ].into_iter().flatten().collect::<Vec<_>>().join(" ");

        let tags = if rule.tags.is_empty() {
            String::new()
        } else {
            format!(" : {}", rule.tags.iter().map(|t| t.as_str()).collect::<Vec<_>>().join(" "))
        };

        println!(
            "  {} {}{}{}",
            if modifiers.is_empty() { "rule".to_string() } else { modifiers },
            rule.name.as_str().cyan(),
            tags.yellow(),
            format!(" ({} bytes)", rule.code_len).dimmed()
        );
    }

    Ok(())
}
