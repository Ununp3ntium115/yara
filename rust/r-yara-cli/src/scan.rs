use anyhow::{Context, Result};
use colored::Colorize;
use r_yara_compiler::Compiler;
use r_yara_matcher::PatternMatcher;
use r_yara_parser::parse;
use r_yara_vm::{RuleMatch, ScanContext, VM};
use rayon::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use walkdir::WalkDir;

pub struct ScanOptions {
    pub rules_path: PathBuf,
    pub target_path: PathBuf,
    pub recursive: bool,
    pub threads: usize,
    pub output_format: String,
    pub max_matches: usize,
    pub timeout: u64,
    pub negate: bool,
    pub print_strings: bool,
    pub print_string_length: bool,
    pub print_tags: bool,
    pub print_meta: bool,
    pub fast_scan: bool,
}

pub fn scan(options: ScanOptions) -> Result<()> {
    let start_time = Instant::now();

    // Load and compile rules
    println!("{}", "Loading YARA rules...".blue());
    let rules_source = load_rules(&options.rules_path)?;

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

    // Build pattern matcher
    println!("{}", "Building pattern matcher...".blue());
    let matcher = PatternMatcher::new(compiled.patterns.clone())
        .context("Failed to build pattern matcher")?;

    // Create VM
    let vm = VM::new(&compiled, &matcher);

    // Collect files to scan
    println!("{}", "Collecting files to scan...".blue());
    let files = collect_files(&options.target_path, options.recursive)?;
    println!("{}", format!("Found {} files to scan", files.len()).green());

    // Set up thread pool
    rayon::ThreadPoolBuilder::new()
        .num_threads(options.threads)
        .build_global()
        .ok();

    // Scan statistics
    let scanned_count = Arc::new(AtomicUsize::new(0));
    let matched_count = Arc::new(AtomicUsize::new(0));
    let results = Arc::new(Mutex::new(Vec::new()));

    // Scan files in parallel
    println!("{}", "Scanning files...".blue());
    files.par_iter().for_each(|file_path| {
        // Apply timeout if specified
        if options.timeout > 0 {
            // TODO: Implement per-file timeout
        }

        match scan_file(file_path, &matcher, &vm) {
            Ok(matches) => {
                let count = scanned_count.fetch_add(1, Ordering::Relaxed) + 1;

                if count % 100 == 0 {
                    eprintln!("Scanned {} files...", count);
                }

                if !matches.is_empty() {
                    matched_count.fetch_add(1, Ordering::Relaxed);

                    if !options.negate {
                        let mut results = results.lock().unwrap();
                        results.push(ScanResult {
                            file_path: file_path.clone(),
                            matches,
                        });
                    }
                } else if options.negate {
                    let mut results = results.lock().unwrap();
                    results.push(ScanResult {
                        file_path: file_path.clone(),
                        matches: Vec::new(),
                    });
                }
            }
            Err(e) => {
                eprintln!("Error scanning {}: {}", file_path.display(), e);
            }
        }
    });

    // Print results
    let results = Arc::try_unwrap(results).unwrap().into_inner().unwrap();
    let scanned = scanned_count.load(Ordering::Relaxed);
    let matched = matched_count.load(Ordering::Relaxed);

    println!();
    match options.output_format.as_str() {
        "json" => print_json_results(&results)?,
        "csv" => print_csv_results(&results)?,
        _ => print_text_results(&results, &options)?,
    }

    let elapsed = start_time.elapsed();
    println!();
    println!("{}", "=".repeat(60).bright_black());
    println!(
        "Scanned {} files in {:.2}s ({:.0} files/sec)",
        scanned,
        elapsed.as_secs_f64(),
        scanned as f64 / elapsed.as_secs_f64()
    );
    println!("{} files matched", matched);
    println!("{}", "=".repeat(60).bright_black());

    Ok(())
}

fn load_rules(path: &Path) -> Result<String> {
    if path.is_dir() {
        // Load all .yar and .yara files from directory
        let mut combined = String::new();
        for entry in WalkDir::new(path)
            .follow_links(true)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if path.is_file() {
                if let Some(ext) = path.extension() {
                    if ext == "yar" || ext == "yara" {
                        let content = fs::read_to_string(path)
                            .with_context(|| format!("Failed to read {}", path.display()))?;
                        combined.push_str(&content);
                        combined.push('\n');
                    }
                }
            }
        }
        Ok(combined)
    } else {
        fs::read_to_string(path)
            .with_context(|| format!("Failed to read {}", path.display()))
    }
}

fn collect_files(path: &Path, recursive: bool) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();

    if path.is_file() {
        files.push(path.to_path_buf());
    } else if path.is_dir() {
        let walker = if recursive {
            WalkDir::new(path).follow_links(true)
        } else {
            WalkDir::new(path).max_depth(1).follow_links(true)
        };

        for entry in walker.into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                files.push(entry.path().to_path_buf());
            }
        }
    } else {
        anyhow::bail!("Path does not exist: {}", path.display());
    }

    Ok(files)
}

fn scan_file(path: &Path, matcher: &PatternMatcher, vm: &VM) -> Result<Vec<RuleMatch>> {
    let data = fs::read(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;

    // Run pattern matcher
    let pattern_matches = matcher.scan(&data);

    // Create scan context
    let ctx = ScanContext::new(&data).with_matches(pattern_matches);

    // Run VM
    let matches = vm.scan(&ctx)
        .context("VM scan failed")?;

    Ok(matches)
}

#[derive(Debug)]
struct ScanResult {
    file_path: PathBuf,
    matches: Vec<RuleMatch>,
}

fn print_text_results(results: &[ScanResult], options: &ScanOptions) -> Result<()> {
    for result in results {
        if options.negate {
            // Just print file names that didn't match
            println!("{}", result.file_path.display());
        } else {
            // Print matches
            for rule_match in &result.matches {
                println!(
                    "{} {}",
                    rule_match.name.as_str().green().bold(),
                    result.file_path.display().to_string().bright_black()
                );

                if options.print_tags && !rule_match.tags.is_empty() {
                    println!("  Tags: {}", rule_match.tags.iter()
                        .map(|t| t.as_str())
                        .collect::<Vec<_>>()
                        .join(", "));
                }

                if options.print_meta && !rule_match.meta.is_empty() {
                    println!("  Metadata:");
                    for (key, value) in &rule_match.meta {
                        println!("    {}: {:?}", key, value);
                    }
                }

                if options.print_strings {
                    for string_match in &rule_match.strings {
                        println!(
                            "  {} at {}",
                            string_match.identifier.as_str().yellow(),
                            string_match.offsets.iter()
                                .map(|o| format!("0x{:x}", o))
                                .collect::<Vec<_>>()
                                .join(", ")
                        );

                        if options.print_string_length {
                            println!("    ({} occurrences)", string_match.offsets.len());
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn print_json_results(results: &[ScanResult]) -> Result<()> {
    let output: Vec<serde_json::Value> = results
        .iter()
        .map(|result| {
            serde_json::json!({
                "file": result.file_path.to_string_lossy(),
                "matches": result.matches.iter().map(|m| {
                    serde_json::json!({
                        "rule": m.name.as_str(),
                        "tags": m.tags.iter().map(|t| t.as_str()).collect::<Vec<_>>(),
                        "strings": m.strings.iter().map(|s| {
                            serde_json::json!({
                                "identifier": s.identifier.as_str(),
                                "offsets": s.offsets,
                            })
                        }).collect::<Vec<_>>(),
                    })
                }).collect::<Vec<_>>(),
            })
        })
        .collect();

    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn print_csv_results(results: &[ScanResult]) -> Result<()> {
    use csv::Writer;
    use std::io;

    let mut wtr = Writer::from_writer(io::stdout());
    wtr.write_record(&["file", "rule", "tags", "strings"])?;

    for result in results {
        for rule_match in &result.matches {
            let tags = rule_match.tags.iter()
                .map(|t| t.as_str())
                .collect::<Vec<_>>()
                .join(";");

            let strings = rule_match.strings.iter()
                .map(|s| format!("{}@{}",
                    s.identifier.as_str(),
                    s.offsets.iter()
                        .map(|o| format!("0x{:x}", o))
                        .collect::<Vec<_>>()
                        .join("|")
                ))
                .collect::<Vec<_>>()
                .join(";");

            wtr.write_record(&[
                result.file_path.to_string_lossy().as_ref(),
                rule_match.name.as_str(),
                &tags,
                &strings,
            ])?;
        }
    }

    wtr.flush()?;
    Ok(())
}
