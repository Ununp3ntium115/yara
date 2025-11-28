use anyhow::Result;
use colored::Colorize;
use r_yara_compiler::Compiler;
use r_yara_parser::parse;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

pub fn check(rules_path: impl AsRef<Path>, warnings: bool, verbose: bool) -> Result<()> {
    let rules_path = rules_path.as_ref();

    let mut total_files = 0;
    let mut total_rules = 0;
    let mut total_errors = 0;
    let mut total_warnings = 0;

    let files = if rules_path.is_dir() {
        WalkDir::new(rules_path)
            .follow_links(true)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|ext| ext == "yar" || ext == "yara")
                    .unwrap_or(false)
            })
            .map(|e| e.path().to_path_buf())
            .collect::<Vec<_>>()
    } else {
        vec![rules_path.to_path_buf()]
    };

    for file in files {
        total_files += 1;

        if verbose {
            println!("{} {}", "Checking".blue(), file.display());
        }

        let source = match fs::read_to_string(&file) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "{} Failed to read {}: {}",
                    "ERROR:".red().bold(),
                    file.display(),
                    e
                );
                total_errors += 1;
                continue;
            }
        };

        // Parse
        let ast = match parse(&source) {
            Ok(ast) => ast,
            Err(e) => {
                eprintln!(
                    "{} Parse error in {}: {:?}",
                    "ERROR:".red().bold(),
                    file.display(),
                    e
                );
                total_errors += 1;
                continue;
            }
        };

        // Compile
        let mut compiler = Compiler::new();
        match compiler.compile(&ast) {
            Ok(compiled) => {
                total_rules += compiled.rules.len();

                if verbose {
                    println!(
                        "  {} {} rules compiled successfully",
                        "✓".green(),
                        compiled.rules.len()
                    );

                    for rule in &compiled.rules {
                        println!("    - {} ({}patterns)", rule.name, rule.strings.len());
                    }
                }
            }
            Err(e) => {
                eprintln!(
                    "{} Compile error in {}: {}",
                    "ERROR:".red().bold(),
                    file.display(),
                    e
                );
                total_errors += 1;
            }
        }

        // Check for warnings (if requested)
        if warnings {
            check_warnings(&ast, &file, &mut total_warnings);
        }
    }

    println!();
    println!("{}", "=".repeat(60).bright_black());
    println!("Checked {} files", total_files);
    println!("Total rules: {}", total_rules);

    if total_errors > 0 {
        println!("{} {}", "Errors:".red().bold(), total_errors);
    } else {
        println!("{}", "No errors found".green());
    }

    if warnings && total_warnings > 0 {
        println!("{} {}", "Warnings:".yellow().bold(), total_warnings);
    }
    println!("{}", "=".repeat(60).bright_black());

    if total_errors > 0 {
        anyhow::bail!("Found {} errors", total_errors);
    }

    Ok(())
}

fn check_warnings(ast: &r_yara_parser::SourceFile, file: &Path, total_warnings: &mut usize) {
    for rule in &ast.rules {
        // Warn about rules without strings
        if rule.strings.is_empty() {
            println!(
                "{} Rule '{}' in {} has no strings section",
                "WARNING:".yellow().bold(),
                rule.name,
                file.display()
            );
            *total_warnings += 1;
        }

        // Warn about rules without metadata
        if rule.meta.is_empty() {
            println!(
                "{} Rule '{}' in {} has no metadata",
                "WARNING:".yellow().bold(),
                rule.name,
                file.display()
            );
            *total_warnings += 1;
        }

        // Warn about very simple conditions
        match &rule.condition {
            r_yara_parser::Expression::Boolean(true) => {
                println!(
                    "{} Rule '{}' in {} has trivial condition (always true)",
                    "WARNING:".yellow().bold(),
                    rule.name,
                    file.display()
                );
                *total_warnings += 1;
            }
            r_yara_parser::Expression::Boolean(false) => {
                println!(
                    "{} Rule '{}' in {} has trivial condition (always false)",
                    "WARNING:".yellow().bold(),
                    rule.name,
                    file.display()
                );
                *total_warnings += 1;
            }
            _ => {}
        }
    }
}
