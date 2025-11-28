//! Scan context management

use goblin::{elf::Elf, mach::Mach, pe::PE, Object};
use r_yara_matcher::Match;
use r_yara_modules::{hash, math};
use smol_str::SmolStr;
use std::collections::HashMap;

/// File type detected from scan data
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Unknown,
    PE,
    ELF,
    MachO,
    DEX,
    Text,
    Binary,
}

/// Module data extracted from the scanned file
#[derive(Debug, Clone, Default)]
pub struct ModuleData {
    /// PE module data
    pub pe_info: Option<PEInfo>,
    /// ELF module data
    pub elf_info: Option<ELFInfo>,
    /// Mach-O module data
    pub macho_info: Option<MachoInfo>,
    /// DEX module data
    pub dex_info: Option<DexInfo>,
    /// Hash module data
    pub hashes: HashMap<SmolStr, String>,
    /// Math module data
    pub math_stats: MathStats,
}

/// PE file information
#[derive(Debug, Clone)]
pub struct PEInfo {
    pub is_pe: bool,
    pub is_dll: bool,
    pub is_exe: bool,
    pub machine: u16,
    pub subsystem: u16,
    pub sections: Vec<String>,
    pub imports: Vec<String>,
    pub exports: Vec<String>,
    pub entry_point: u64,
}

/// ELF file information
#[derive(Debug, Clone)]
pub struct ELFInfo {
    pub is_elf: bool,
    pub machine: u16,
    pub elf_type: u16,
    pub sections: Vec<String>,
    pub entry_point: u64,
}

/// Mach-O file information
#[derive(Debug, Clone)]
pub struct MachoInfo {
    pub is_macho: bool,
    pub cputype: u32,
    pub filetype: u32,
    pub entry_point: u64,
}

/// DEX file information
#[derive(Debug, Clone)]
pub struct DexInfo {
    pub is_dex: bool,
    pub version: u32,
    pub classes_count: usize,
}

/// Mathematical statistics
#[derive(Debug, Clone, Default)]
pub struct MathStats {
    pub entropy: f64,
    pub mean: f64,
}

/// Scan context holding all data needed for a scan
pub struct ScanContext<'a> {
    /// The data being scanned
    pub data: &'a [u8],
    /// Detected file type
    pub file_type: FileType,
    /// Module data extracted from file
    pub module_data: ModuleData,
    /// Pattern matches
    pub matches: Vec<Match>,
    /// Entry point for executable files
    pub entry_point: u64,
}

impl<'a> ScanContext<'a> {
    /// Create a new scan context from data
    pub fn new(data: &'a [u8]) -> Self {
        let file_type = detect_file_type(data);
        let mut module_data = ModuleData::default();
        let entry_point = extract_module_data(data, file_type, &mut module_data);

        Self {
            data,
            file_type,
            module_data,
            matches: Vec::new(),
            entry_point,
        }
    }

    /// Set pattern matches
    pub fn with_matches(mut self, matches: Vec<Match>) -> Self {
        self.matches = matches;
        self
    }

    /// Get file size
    pub fn filesize(&self) -> u64 {
        self.data.len() as u64
    }

    /// Check if this is a PE file
    pub fn is_pe(&self) -> bool {
        self.file_type == FileType::PE
    }

    /// Check if this is an ELF file
    pub fn is_elf(&self) -> bool {
        self.file_type == FileType::ELF
    }

    /// Check if this is a Mach-O file
    pub fn is_macho(&self) -> bool {
        self.file_type == FileType::MachO
    }

    /// Check if this is a DEX file
    pub fn is_dex(&self) -> bool {
        self.file_type == FileType::DEX
    }

    /// Calculate hash for the entire file
    pub fn md5(&self) -> String {
        hash::md5(self.data, 0, self.data.len())
    }

    /// Calculate SHA1 hash
    pub fn sha1(&self) -> String {
        hash::sha1(self.data, 0, self.data.len())
    }

    /// Calculate SHA256 hash
    pub fn sha256(&self) -> String {
        hash::sha256(self.data, 0, self.data.len())
    }

    /// Get entropy
    pub fn entropy(&self) -> f64 {
        self.module_data.math_stats.entropy
    }
}

/// Detect file type from data
fn detect_file_type(data: &[u8]) -> FileType {
    if data.len() < 4 {
        return FileType::Unknown;
    }

    // Try to parse as various formats
    match Object::parse(data) {
        Ok(Object::PE(_)) => FileType::PE,
        Ok(Object::Elf(_)) => FileType::ELF,
        Ok(Object::Mach(_)) => FileType::MachO,
        _ => {
            // Check for DEX magic
            if data.len() >= 8 && &data[0..4] == b"dex\n" {
                FileType::DEX
            } else if is_likely_text(data) {
                FileType::Text
            } else {
                FileType::Binary
            }
        }
    }
}

/// Check if data is likely text
fn is_likely_text(data: &[u8]) -> bool {
    let sample_size = data.len().min(512);
    let sample = &data[..sample_size];

    let printable_count = sample.iter()
        .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
        .count();

    (printable_count as f64 / sample_size as f64) > 0.85
}

/// Extract module data and return entry point
fn extract_module_data(data: &[u8], file_type: FileType, module_data: &mut ModuleData) -> u64 {
    let mut entry_point = 0u64;

    // Calculate hashes
    module_data.hashes.insert(SmolStr::new("md5"), hash::md5(data, 0, data.len()));
    module_data.hashes.insert(SmolStr::new("sha1"), hash::sha1(data, 0, data.len()));
    module_data.hashes.insert(SmolStr::new("sha256"), hash::sha256(data, 0, data.len()));

    // Calculate math stats
    module_data.math_stats.entropy = math::entropy(data, 0, data.len());
    module_data.math_stats.mean = math::mean(data, 0, data.len());

    // Parse file format specific data
    match file_type {
        FileType::PE => {
            if let Ok(pe_obj) = PE::parse(data) {
                entry_point = pe_obj.entry as u64;

                let is_dll = pe_obj.is_lib;
                let is_exe = !is_dll;

                let sections = pe_obj.sections
                    .iter()
                    .filter_map(|s| String::from_utf8(s.name.to_vec()).ok())
                    .collect();

                let imports = pe_obj.imports
                    .iter()
                    .map(|imp| imp.name.to_string())
                    .collect();

                let exports = pe_obj.exports
                    .iter()
                    .filter_map(|exp| exp.name.map(|n| n.to_string()))
                    .collect();

                module_data.pe_info = Some(PEInfo {
                    is_pe: true,
                    is_dll,
                    is_exe,
                    machine: pe_obj.header.coff_header.machine,
                    subsystem: pe_obj.header.optional_header
                        .map(|oh| oh.windows_fields.subsystem)
                        .unwrap_or(0),
                    sections,
                    imports,
                    exports,
                    entry_point,
                });
            }
        }
        FileType::ELF => {
            if let Ok(elf_obj) = Elf::parse(data) {
                entry_point = elf_obj.entry;

                let sections = elf_obj.section_headers
                    .iter()
                    .filter_map(|s| {
                        elf_obj.shdr_strtab.get_at(s.sh_name)
                            .map(|n| n.to_string())
                    })
                    .collect();

                module_data.elf_info = Some(ELFInfo {
                    is_elf: true,
                    machine: elf_obj.header.e_machine,
                    elf_type: elf_obj.header.e_type,
                    sections,
                    entry_point,
                });
            }
        }
        FileType::MachO => {
            if let Ok(Mach::Binary(macho_obj)) = Mach::parse(data) {
                entry_point = macho_obj.entry as u64;

                module_data.macho_info = Some(MachoInfo {
                    is_macho: true,
                    cputype: macho_obj.header.cputype,
                    filetype: macho_obj.header.filetype,
                    entry_point,
                });
            }
        }
        FileType::DEX => {
            // Parse DEX header
            if data.len() >= 112 && &data[0..4] == b"dex\n" {
                let version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

                module_data.dex_info = Some(DexInfo {
                    is_dex: true,
                    version,
                    classes_count: 0, // Would need full DEX parser
                });
            }
        }
        _ => {}
    }

    entry_point
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_text_file() {
        let data = b"Hello, this is plain text content!\n";
        let file_type = detect_file_type(data);
        assert_eq!(file_type, FileType::Text);
    }

    #[test]
    fn test_detect_binary_file() {
        let data = b"\x00\x01\x02\x03\x04\x05\x06\x07";
        let file_type = detect_file_type(data);
        assert_eq!(file_type, FileType::Binary);
    }

    #[test]
    fn test_scan_context_creation() {
        let data = b"Test data";
        let ctx = ScanContext::new(data);

        assert_eq!(ctx.filesize(), 9);
        assert_eq!(ctx.data, data);
    }

    #[test]
    fn test_scan_context_hashes() {
        let data = b"Test data";
        let ctx = ScanContext::new(data);

        // Verify hashes are calculated
        assert!(!ctx.module_data.hashes.is_empty());
        assert!(ctx.module_data.hashes.contains_key("md5"));
        assert!(ctx.module_data.hashes.contains_key("sha256"));
    }

    #[test]
    fn test_scan_context_math_stats() {
        let data = b"AAAAAAAAAA"; // Low entropy
        let ctx = ScanContext::new(data);

        // Low entropy data
        assert!(ctx.entropy() < 1.0);
        assert_eq!(ctx.module_data.math_stats.mean, b'A' as f64);
    }
}
