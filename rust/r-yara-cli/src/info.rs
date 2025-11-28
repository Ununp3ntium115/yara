use anyhow::{Context, Result};
use colored::Colorize;
use goblin::Object;
use std::fs;

pub struct InfoOptions {
    pub file_path: std::path::PathBuf,
    pub show_pe: bool,
    pub show_elf: bool,
    pub show_macho: bool,
    pub show_dex: bool,
    pub show_hashes: bool,
}

pub fn show_info(options: InfoOptions) -> Result<()> {
    let path = &options.file_path;

    println!("{}", format!("File: {}", path.display()).bold());
    println!();

    // Read file
    let data = fs::read(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;

    // File size
    let size = data.len();
    println!("{} {} bytes ({} KB)", "Size:".blue(), size, size / 1024);

    // Entropy
    let entropy = calculate_entropy(&data);
    println!("{} {:.4}", "Entropy:".blue(), entropy);

    // File type detection
    println!();
    println!("{}", "File Type Analysis:".bold());
    println!("{}", "-".repeat(60).bright_black());

    match Object::parse(&data) {
        Ok(Object::PE(pe)) => {
            println!("{} {}", "Type:".blue(), "PE (Windows Executable)".green());
            if options.show_pe {
                show_pe_info(&pe);
            }
        }
        Ok(Object::Elf(elf)) => {
            println!("{} {}", "Type:".blue(), "ELF (Unix Executable)".green());
            if options.show_elf {
                show_elf_info(&elf);
            }
        }
        Ok(Object::Mach(mach)) => {
            println!("{} {}", "Type:".blue(), "Mach-O (macOS Executable)".green());
            if options.show_macho {
                show_macho_info(&mach);
            }
        }
        Ok(Object::Archive(_)) => {
            println!("{} {}", "Type:".blue(), "Archive".yellow());
        }
        Ok(Object::Unknown(magic)) => {
            println!("{} Unknown (magic: 0x{:x})", "Type:".blue(), magic);
        }
        Ok(_) => {
            // Handle other object types (COFF, etc.)
            println!("{} {}", "Type:".blue(), "Other binary format".yellow());
        }
        Err(_) => {
            println!("{} {}", "Type:".blue(), "Unknown or unsupported format".red());

            // Try DEX detection
            if data.len() >= 8 && &data[0..4] == b"dex\n" {
                println!("{} {}", "Type:".blue(), "DEX (Android Executable)".green());
                if options.show_dex {
                    show_dex_info(&data);
                }
            }
        }
    }

    // Hashes
    if options.show_hashes || size < 100 * 1024 * 1024 {
        // Auto-compute for files < 100MB
        println!();
        println!("{}", "Hashes:".bold());
        println!("{}", "-".repeat(60).bright_black());

        // Use r-yara-modules hash functions for consistency
        let md5_hash = r_yara_modules::hash::md5(&data, 0, data.len());
        println!("{} {}", "MD5:".blue(), md5_hash);

        let sha256_hash = r_yara_modules::hash::sha256(&data, 0, data.len());
        println!("{} {}", "SHA256:".blue(), sha256_hash);
    }

    // Use r-yara-modules for additional analysis
    println!();
    println!("{}", "R-YARA Module Analysis:".bold());
    println!("{}", "-".repeat(60).bright_black());

    // Hash module
    let md5 = r_yara_modules::hash::md5(&data, 0, data.len());
    println!("{} {}", "hash.md5:".blue(), md5);

    let sha1 = r_yara_modules::hash::sha1(&data, 0, data.len());
    println!("{} {}", "hash.sha1:".blue(), sha1);

    let sha256 = r_yara_modules::hash::sha256(&data, 0, data.len());
    println!("{} {}", "hash.sha256:".blue(), sha256);

    // Math module
    let entropy = r_yara_modules::math::entropy(&data, 0, data.len());
    println!("{} {:.6}", "math.entropy:".blue(), entropy);

    let mean = r_yara_modules::math::mean(&data, 0, data.len());
    println!("{} {:.2}", "math.mean:".blue(), mean);

    Ok(())
}

fn calculate_entropy(data: &[u8]) -> f64 {
    let mut counts = [0u32; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

fn show_pe_info(pe: &goblin::pe::PE) {
    println!("  {}", "PE Information:".yellow());

    // DOS header is not an Option in goblin
    println!("    DOS Stub: Present (e_magic: 0x{:04x})", pe.header.dos_header.signature);

    println!(
        "    Machine: {:?}",
        pe.header.coff_header.machine
    );

    println!(
        "    Subsystem: {:?}",
        pe.header.optional_header.as_ref()
            .map(|h| format!("{:?}", h.windows_fields.subsystem))
            .unwrap_or_else(|| "Unknown".to_string())
    );

    println!("    Sections: {}", pe.sections.len());
    for section in &pe.sections {
        let name = String::from_utf8_lossy(&section.name).trim_end_matches('\0').to_string();
        println!(
            "      - {} (size: {} bytes, virtual: 0x{:x})",
            name, section.size_of_raw_data, section.virtual_address
        );
    }

    if !pe.libraries.is_empty() {
        println!("    Imported Libraries: {}", pe.libraries.len());
        for lib in &pe.libraries {
            println!("      - {}", lib);
        }
    }

    if !pe.exports.is_empty() {
        println!("    Exports: {}", pe.exports.len());
    }
}

fn show_elf_info(elf: &goblin::elf::Elf) {
    println!("  {}", "ELF Information:".yellow());

    println!("    Class: {:?}", elf.header.e_ident[4]);
    println!("    Data: {:?}", elf.header.e_ident[5]);
    println!("    Type: {:?}", elf.header.e_type);
    println!("    Machine: {:?}", elf.header.e_machine);
    println!("    Entry Point: 0x{:x}", elf.entry);

    println!("    Program Headers: {}", elf.program_headers.len());
    println!("    Section Headers: {}", elf.section_headers.len());

    if !elf.libraries.is_empty() {
        println!("    Libraries: {}", elf.libraries.len());
        for lib in &elf.libraries {
            println!("      - {}", lib);
        }
    }

    if !elf.dynsyms.is_empty() {
        println!("    Dynamic Symbols: {}", elf.dynsyms.len());
    }
}

fn show_macho_info(mach: &goblin::mach::Mach) {
    println!("  {}", "Mach-O Information:".yellow());

    match mach {
        goblin::mach::Mach::Binary(macho) => {
            println!("    Architecture: {:?}", macho.header.cputype());
            println!("    File Type: {:?}", macho.header.filetype);
            println!("    Load Commands: {}", macho.load_commands.len());

            if !macho.segments.is_empty() {
                println!("    Segments: {}", macho.segments.len());
                for segment in &macho.segments {
                    println!(
                        "      - {} (sections: {})",
                        segment.name().unwrap_or("?"),
                        segment.sections().unwrap_or_default().len()
                    );
                }
            }
        }
        goblin::mach::Mach::Fat(fat) => {
            // MultiArch doesn't have len(), count the iterator
            let count = fat.iter_arches().count();
            println!("    Universal Binary with {} architectures", count);
        }
    }
}

fn show_dex_info(data: &[u8]) {
    println!("  {}", "DEX Information:".yellow());

    if data.len() >= 0x70 {
        // Parse DEX header
        let version = String::from_utf8_lossy(&data[4..7]);
        println!("    Version: {}", version);

        // Checksum
        let checksum = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        println!("    Checksum: 0x{:08x}", checksum);

        // File size
        let file_size = u32::from_le_bytes([data[0x20], data[0x21], data[0x22], data[0x23]]);
        println!("    File Size: {} bytes", file_size);

        // String IDs count
        let string_ids_size = u32::from_le_bytes([data[0x38], data[0x39], data[0x3a], data[0x3b]]);
        println!("    String IDs: {}", string_ids_size);

        // Type IDs count
        let type_ids_size = u32::from_le_bytes([data[0x40], data[0x41], data[0x42], data[0x43]]);
        println!("    Type IDs: {}", type_ids_size);

        // Method IDs count
        let method_ids_size = u32::from_le_bytes([data[0x58], data[0x59], data[0x5a], data[0x5b]]);
        println!("    Method IDs: {}", method_ids_size);

        // Class definitions count
        let class_defs_size = u32::from_le_bytes([data[0x60], data[0x61], data[0x62], data[0x63]]);
        println!("    Class Definitions: {}", class_defs_size);
    }
}
