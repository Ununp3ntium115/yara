//! PE Module
//!
//! Provides PE (Portable Executable) file analysis compatible with YARA's pe module.
//!
//! # YARA Compatibility
//!
//! This module implements YARA's built-in pe module functions:
//!
//! ```yara
//! import "pe"
//!
//! rule IsPE {
//!     condition:
//!         pe.is_pe and
//!         pe.is_64bit() and
//!         pe.number_of_sections > 3
//! }
//! ```
//!
//! # Example
//!
//! ```no_run
//! use r_yara_modules::pe::PeInfo;
//!
//! let data = std::fs::read("sample.exe").unwrap();
//! if let Some(pe) = PeInfo::parse(&data) {
//!     println!("Is PE: {}", pe.is_pe());
//!     println!("Is 64-bit: {}", pe.is_64bit());
//!     println!("Entry point: 0x{:x}", pe.entry_point());
//!     println!("Sections: {}", pe.number_of_sections());
//! }
//! ```

use goblin::pe::PE;
use smol_str::SmolStr;

/// PE file characteristics flags
pub mod characteristics {
    pub const RELOCS_STRIPPED: u16 = 0x0001;
    pub const EXECUTABLE_IMAGE: u16 = 0x0002;
    pub const LINE_NUMS_STRIPPED: u16 = 0x0004;
    pub const LOCAL_SYMS_STRIPPED: u16 = 0x0008;
    pub const AGGRESSIVE_WS_TRIM: u16 = 0x0010;
    pub const LARGE_ADDRESS_AWARE: u16 = 0x0020;
    pub const BYTES_REVERSED_LO: u16 = 0x0080;
    pub const MACHINE_32BIT: u16 = 0x0100;
    pub const DEBUG_STRIPPED: u16 = 0x0200;
    pub const REMOVABLE_RUN_FROM_SWAP: u16 = 0x0400;
    pub const NET_RUN_FROM_SWAP: u16 = 0x0800;
    pub const SYSTEM: u16 = 0x1000;
    pub const DLL: u16 = 0x2000;
    pub const UP_SYSTEM_ONLY: u16 = 0x4000;
    pub const BYTES_REVERSED_HI: u16 = 0x8000;
}

/// Machine types
pub mod machine {
    pub const UNKNOWN: u16 = 0x0;
    pub const I386: u16 = 0x14c;
    pub const R3000: u16 = 0x162;
    pub const R4000: u16 = 0x166;
    pub const R10000: u16 = 0x168;
    pub const WCEMIPSV2: u16 = 0x169;
    pub const ALPHA: u16 = 0x184;
    pub const SH3: u16 = 0x1a2;
    pub const SH3DSP: u16 = 0x1a3;
    pub const SH3E: u16 = 0x1a4;
    pub const SH4: u16 = 0x1a6;
    pub const SH5: u16 = 0x1a8;
    pub const ARM: u16 = 0x1c0;
    pub const THUMB: u16 = 0x1c2;
    pub const ARMNT: u16 = 0x1c4;
    pub const AM33: u16 = 0x1d3;
    pub const POWERPC: u16 = 0x1f0;
    pub const POWERPCFP: u16 = 0x1f1;
    pub const IA64: u16 = 0x200;
    pub const MIPS16: u16 = 0x266;
    pub const ALPHA64: u16 = 0x284;
    pub const MIPSFPU: u16 = 0x366;
    pub const MIPSFPU16: u16 = 0x466;
    pub const TRICORE: u16 = 0x520;
    pub const CEF: u16 = 0xcef;
    pub const EBC: u16 = 0xebc;
    pub const AMD64: u16 = 0x8664;
    pub const M32R: u16 = 0x9041;
    pub const ARM64: u16 = 0xaa64;
    pub const CEE: u16 = 0xc0ee;
}

/// Subsystem types
pub mod subsystem {
    pub const UNKNOWN: u16 = 0;
    pub const NATIVE: u16 = 1;
    pub const WINDOWS_GUI: u16 = 2;
    pub const WINDOWS_CUI: u16 = 3;
    pub const OS2_CUI: u16 = 5;
    pub const POSIX_CUI: u16 = 7;
    pub const NATIVE_WINDOWS: u16 = 8;
    pub const WINDOWS_CE_GUI: u16 = 9;
    pub const EFI_APPLICATION: u16 = 10;
    pub const EFI_BOOT_SERVICE_DRIVER: u16 = 11;
    pub const EFI_RUNTIME_DRIVER: u16 = 12;
    pub const EFI_ROM: u16 = 13;
    pub const XBOX: u16 = 14;
    pub const WINDOWS_BOOT_APPLICATION: u16 = 16;
}

/// Section characteristics flags
pub mod section_characteristics {
    pub const CNT_CODE: u32 = 0x00000020;
    pub const CNT_INITIALIZED_DATA: u32 = 0x00000040;
    pub const CNT_UNINITIALIZED_DATA: u32 = 0x00000080;
    pub const LNK_INFO: u32 = 0x00000200;
    pub const LNK_REMOVE: u32 = 0x00000800;
    pub const LNK_COMDAT: u32 = 0x00001000;
    pub const GPREL: u32 = 0x00008000;
    pub const ALIGN_1BYTES: u32 = 0x00100000;
    pub const ALIGN_2BYTES: u32 = 0x00200000;
    pub const ALIGN_4BYTES: u32 = 0x00300000;
    pub const ALIGN_8BYTES: u32 = 0x00400000;
    pub const ALIGN_16BYTES: u32 = 0x00500000;
    pub const ALIGN_32BYTES: u32 = 0x00600000;
    pub const ALIGN_64BYTES: u32 = 0x00700000;
    pub const ALIGN_128BYTES: u32 = 0x00800000;
    pub const ALIGN_256BYTES: u32 = 0x00900000;
    pub const ALIGN_512BYTES: u32 = 0x00a00000;
    pub const ALIGN_1024BYTES: u32 = 0x00b00000;
    pub const ALIGN_2048BYTES: u32 = 0x00c00000;
    pub const ALIGN_4096BYTES: u32 = 0x00d00000;
    pub const ALIGN_8192BYTES: u32 = 0x00e00000;
    pub const LNK_NRELOC_OVFL: u32 = 0x01000000;
    pub const MEM_DISCARDABLE: u32 = 0x02000000;
    pub const MEM_NOT_CACHED: u32 = 0x04000000;
    pub const MEM_NOT_PAGED: u32 = 0x08000000;
    pub const MEM_SHARED: u32 = 0x10000000;
    pub const MEM_EXECUTE: u32 = 0x20000000;
    pub const MEM_READ: u32 = 0x40000000;
    pub const MEM_WRITE: u32 = 0x80000000;
}

/// Information about a PE section
#[derive(Debug, Clone)]
pub struct Section {
    /// Section name (up to 8 characters)
    pub name: SmolStr,
    /// Virtual address (RVA)
    pub virtual_address: u32,
    /// Virtual size
    pub virtual_size: u32,
    /// Raw data offset in file
    pub raw_data_offset: u32,
    /// Raw data size
    pub raw_data_size: u32,
    /// Section characteristics
    pub characteristics: u32,
}

/// Information about an import
#[derive(Debug, Clone)]
pub struct Import {
    /// DLL name
    pub library: SmolStr,
    /// Function name or ordinal
    pub functions: Vec<ImportFunction>,
}

/// Import function information
#[derive(Debug, Clone)]
pub struct ImportFunction {
    /// Function name (None if imported by ordinal)
    pub name: Option<SmolStr>,
    /// Ordinal number
    pub ordinal: Option<u16>,
}

/// Information about an export
#[derive(Debug, Clone)]
pub struct Export {
    /// Export name
    pub name: Option<SmolStr>,
    /// Export ordinal
    pub ordinal: u32,
    /// Export RVA
    pub rva: u32,
}

/// Rich header entry
#[derive(Debug, Clone)]
pub struct RichEntry {
    /// Tool ID
    pub tool_id: u16,
    /// Tool version
    pub version: u16,
    /// Usage count
    pub count: u32,
}

/// Parsed PE information
pub struct PeInfo<'a> {
    data: &'a [u8],
    pe: PE<'a>,
}

impl<'a> PeInfo<'a> {
    /// Parse PE data
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        let pe = PE::parse(data).ok()?;
        Some(Self { data, pe })
    }

    /// Check if this is a valid PE file
    pub fn is_pe(&self) -> bool {
        true // If we parsed successfully, it's a PE
    }

    /// Check if this is a 32-bit PE
    pub fn is_32bit(&self) -> bool {
        !self.pe.is_64
    }

    /// Check if this is a 64-bit PE
    pub fn is_64bit(&self) -> bool {
        self.pe.is_64
    }

    /// Check if this is a DLL
    pub fn is_dll(&self) -> bool {
        self.pe.is_lib
    }

    /// Get the machine type
    pub fn machine(&self) -> u16 {
        self.pe.header.coff_header.machine
    }

    /// Get the subsystem
    pub fn subsystem(&self) -> u16 {
        self.pe
            .header
            .optional_header
            .map(|oh| oh.windows_fields.subsystem)
            .unwrap_or(0)
    }

    /// Get file characteristics
    pub fn characteristics(&self) -> u16 {
        self.pe.header.coff_header.characteristics
    }

    /// Get the entry point RVA
    pub fn entry_point(&self) -> u64 {
        self.pe
            .header
            .optional_header
            .map(|oh| oh.standard_fields.address_of_entry_point as u64)
            .unwrap_or(0)
    }

    /// Get the image base
    pub fn image_base(&self) -> u64 {
        self.pe
            .header
            .optional_header
            .map(|oh| oh.windows_fields.image_base)
            .unwrap_or(0)
    }

    /// Get the number of sections
    pub fn number_of_sections(&self) -> usize {
        self.pe.sections.len()
    }

    /// Get section information by index
    pub fn section(&self, index: usize) -> Option<Section> {
        self.pe.sections.get(index).map(|s| {
            let name = std::str::from_utf8(&s.name)
                .unwrap_or("")
                .trim_end_matches('\0');
            Section {
                name: SmolStr::new(name),
                virtual_address: s.virtual_address,
                virtual_size: s.virtual_size,
                raw_data_offset: s.pointer_to_raw_data,
                raw_data_size: s.size_of_raw_data,
                characteristics: s.characteristics,
            }
        })
    }

    /// Get all sections
    pub fn sections(&self) -> Vec<Section> {
        (0..self.number_of_sections())
            .filter_map(|i| self.section(i))
            .collect()
    }

    /// Get section by name
    pub fn section_by_name(&self, name: &str) -> Option<Section> {
        self.sections().into_iter().find(|s| s.name.as_str() == name)
    }

    /// Get the timestamp from the COFF header
    pub fn timestamp(&self) -> u32 {
        self.pe.header.coff_header.time_date_stamp
    }

    /// Get the number of symbols
    pub fn number_of_symbols(&self) -> u32 {
        self.pe.header.coff_header.number_of_symbol_table
    }

    /// Get the pointer to symbol table
    pub fn pointer_to_symbol_table(&self) -> u32 {
        self.pe.header.coff_header.pointer_to_symbol_table
    }

    /// Get the size of optional header
    pub fn size_of_optional_header(&self) -> u16 {
        self.pe.header.coff_header.size_of_optional_header
    }

    /// Get checksum
    pub fn checksum(&self) -> u32 {
        self.pe
            .header
            .optional_header
            .map(|oh| oh.windows_fields.check_sum)
            .unwrap_or(0)
    }

    /// Get size of image
    pub fn size_of_image(&self) -> u32 {
        self.pe
            .header
            .optional_header
            .map(|oh| oh.windows_fields.size_of_image)
            .unwrap_or(0)
    }

    /// Get size of headers
    pub fn size_of_headers(&self) -> u32 {
        self.pe
            .header
            .optional_header
            .map(|oh| oh.windows_fields.size_of_headers)
            .unwrap_or(0)
    }

    /// Get DLL characteristics
    pub fn dll_characteristics(&self) -> u16 {
        self.pe
            .header
            .optional_header
            .map(|oh| oh.windows_fields.dll_characteristics)
            .unwrap_or(0)
    }

    /// Get size of stack reserve
    pub fn size_of_stack_reserve(&self) -> u64 {
        self.pe
            .header
            .optional_header
            .map(|oh| oh.windows_fields.size_of_stack_reserve)
            .unwrap_or(0)
    }

    /// Get size of stack commit
    pub fn size_of_stack_commit(&self) -> u64 {
        self.pe
            .header
            .optional_header
            .map(|oh| oh.windows_fields.size_of_stack_commit)
            .unwrap_or(0)
    }

    /// Get size of heap reserve
    pub fn size_of_heap_reserve(&self) -> u64 {
        self.pe
            .header
            .optional_header
            .map(|oh| oh.windows_fields.size_of_heap_reserve)
            .unwrap_or(0)
    }

    /// Get size of heap commit
    pub fn size_of_heap_commit(&self) -> u64 {
        self.pe
            .header
            .optional_header
            .map(|oh| oh.windows_fields.size_of_heap_commit)
            .unwrap_or(0)
    }

    /// Get number of RVA and sizes (data directories)
    pub fn number_of_rva_and_sizes(&self) -> u32 {
        self.pe
            .header
            .optional_header
            .map(|oh| oh.windows_fields.number_of_rva_and_sizes)
            .unwrap_or(0)
    }

    /// Get imports
    pub fn imports(&self) -> Vec<Import> {
        let mut result = Vec::new();
        for import in &self.pe.imports {
            let lib_name = SmolStr::new(import.dll);

            // Find existing or create new
            let lib_import = result
                .iter_mut()
                .find(|i: &&mut Import| i.library == lib_name);

            let func = ImportFunction {
                name: Some(SmolStr::new(import.name.as_ref())),
                ordinal: None,
            };

            if let Some(lib) = lib_import {
                lib.functions.push(func);
            } else {
                result.push(Import {
                    library: lib_name,
                    functions: vec![func],
                });
            }
        }
        result
    }

    /// Get number of imports
    pub fn number_of_imports(&self) -> usize {
        self.pe.imports.len()
    }

    /// Check if a specific DLL is imported
    pub fn imports_dll(&self, dll_name: &str) -> bool {
        let dll_lower = dll_name.to_lowercase();
        self.pe
            .imports
            .iter()
            .any(|i| i.dll.to_lowercase() == dll_lower)
    }

    /// Check if a specific function is imported
    pub fn imports_function(&self, dll_name: &str, func_name: &str) -> bool {
        let dll_lower = dll_name.to_lowercase();
        let func_lower = func_name.to_lowercase();
        self.pe.imports.iter().any(|i| {
            i.dll.to_lowercase() == dll_lower && i.name.as_ref().to_lowercase() == func_lower
        })
    }

    /// Get exports
    pub fn exports(&self) -> Vec<Export> {
        self.pe
            .exports
            .iter()
            .enumerate()
            .map(|(idx, e)| Export {
                name: e.name.map(SmolStr::new),
                ordinal: idx as u32,
                rva: e.rva as u32,
            })
            .collect()
    }

    /// Get number of exports
    pub fn number_of_exports(&self) -> usize {
        self.pe.exports.len()
    }

    /// Check if a function is exported
    pub fn exports_function(&self, name: &str) -> bool {
        let name_lower = name.to_lowercase();
        self.pe
            .exports
            .iter()
            .any(|e| e.name.map(|n| n.to_lowercase()) == Some(name_lower.clone()))
    }

    /// Get the DOS header e_magic
    pub fn dos_header_e_magic(&self) -> u16 {
        // MZ signature
        if self.data.len() >= 2 {
            u16::from_le_bytes([self.data[0], self.data[1]])
        } else {
            0
        }
    }

    /// Get the offset to PE header (e_lfanew)
    pub fn dos_header_e_lfanew(&self) -> u32 {
        if self.data.len() >= 64 {
            u32::from_le_bytes([self.data[60], self.data[61], self.data[62], self.data[63]])
        } else {
            0
        }
    }

    /// Calculate the actual checksum of the file
    pub fn calculate_checksum(&self) -> u32 {
        let mut checksum: u64 = 0;
        let checksum_offset = self.dos_header_e_lfanew() as usize + 88; // Offset to checksum field

        for (i, chunk) in self.data.chunks(2).enumerate() {
            if i * 2 == checksum_offset {
                continue; // Skip the checksum field itself
            }
            let val = if chunk.len() == 2 {
                u16::from_le_bytes([chunk[0], chunk[1]]) as u64
            } else {
                chunk[0] as u64
            };
            checksum += val;
            checksum = (checksum & 0xFFFF) + (checksum >> 16);
        }

        checksum = (checksum & 0xFFFF) + (checksum >> 16);
        (checksum + self.data.len() as u64) as u32
    }

    /// Get the entry point raw file offset
    pub fn entry_point_raw(&self) -> Option<u64> {
        let entry_rva = self.entry_point() as u32;
        self.rva_to_offset(entry_rva).map(|o| o as u64)
    }

    /// Convert RVA to file offset
    pub fn rva_to_offset(&self, rva: u32) -> Option<u32> {
        for section in &self.pe.sections {
            let section_start = section.virtual_address;
            let section_end = section_start + section.virtual_size;
            if rva >= section_start && rva < section_end {
                let offset_in_section = rva - section_start;
                return Some(section.pointer_to_raw_data + offset_in_section);
            }
        }
        None
    }

    /// Get overlay offset (data after PE structure)
    pub fn overlay_offset(&self) -> Option<u64> {
        let mut max_offset = 0u64;
        for section in &self.pe.sections {
            let end = section.pointer_to_raw_data as u64 + section.size_of_raw_data as u64;
            if end > max_offset {
                max_offset = end;
            }
        }
        if max_offset < self.data.len() as u64 {
            Some(max_offset)
        } else {
            None
        }
    }

    /// Get overlay size
    pub fn overlay_size(&self) -> u64 {
        self.overlay_offset()
            .map(|offset| self.data.len() as u64 - offset)
            .unwrap_or(0)
    }

    /// Check for common packer signatures
    pub fn is_packed(&self) -> bool {
        // Check for common packer section names
        let packer_sections = [".upx", "UPX0", "UPX1", ".aspack", ".adata", ".themida"];
        for section in self.sections() {
            if packer_sections.iter().any(|&p| section.name.contains(p)) {
                return true;
            }
        }

        // Check for high entropy sections (> 7.0)
        // This would require the math module

        // Check for unusual section characteristics
        for section in &self.pe.sections {
            // Writable and executable is suspicious
            let chars = section.characteristics;
            if (chars & section_characteristics::MEM_WRITE != 0)
                && (chars & section_characteristics::MEM_EXECUTE != 0)
            {
                return true;
            }
        }

        false
    }

    /// Get linker version
    pub fn linker_version(&self) -> (u8, u8) {
        self.pe
            .header
            .optional_header
            .map(|oh| {
                (
                    oh.standard_fields.major_linker_version,
                    oh.standard_fields.minor_linker_version,
                )
            })
            .unwrap_or((0, 0))
    }

    /// Get OS version
    pub fn os_version(&self) -> (u16, u16) {
        self.pe
            .header
            .optional_header
            .map(|oh| {
                (
                    oh.windows_fields.major_operating_system_version,
                    oh.windows_fields.minor_operating_system_version,
                )
            })
            .unwrap_or((0, 0))
    }

    /// Get image version
    pub fn image_version(&self) -> (u16, u16) {
        self.pe
            .header
            .optional_header
            .map(|oh| {
                (
                    oh.windows_fields.major_image_version,
                    oh.windows_fields.minor_image_version,
                )
            })
            .unwrap_or((0, 0))
    }

    /// Get subsystem version
    pub fn subsystem_version(&self) -> (u16, u16) {
        self.pe
            .header
            .optional_header
            .map(|oh| {
                (
                    oh.windows_fields.major_subsystem_version,
                    oh.windows_fields.minor_subsystem_version,
                )
            })
            .unwrap_or((0, 0))
    }
}

/// Check if data is a PE file
pub fn is_pe(data: &[u8]) -> bool {
    PeInfo::parse(data).is_some()
}

/// Check if data is a 32-bit PE
pub fn is_32bit(data: &[u8]) -> bool {
    PeInfo::parse(data).map(|pe| pe.is_32bit()).unwrap_or(false)
}

/// Check if data is a 64-bit PE
pub fn is_64bit(data: &[u8]) -> bool {
    PeInfo::parse(data).map(|pe| pe.is_64bit()).unwrap_or(false)
}

/// Check if data is a DLL
pub fn is_dll(data: &[u8]) -> bool {
    PeInfo::parse(data).map(|pe| pe.is_dll()).unwrap_or(false)
}

/// Get machine type
pub fn get_machine(data: &[u8]) -> u16 {
    PeInfo::parse(data).map(|pe| pe.machine()).unwrap_or(0)
}

/// Get subsystem
pub fn get_subsystem(data: &[u8]) -> u16 {
    PeInfo::parse(data).map(|pe| pe.subsystem()).unwrap_or(0)
}

/// Get entry point
pub fn get_entry_point(data: &[u8]) -> u64 {
    PeInfo::parse(data).map(|pe| pe.entry_point()).unwrap_or(0)
}

/// Get number of sections
pub fn get_number_of_sections(data: &[u8]) -> usize {
    PeInfo::parse(data)
        .map(|pe| pe.number_of_sections())
        .unwrap_or(0)
}

/// Get number of imports
pub fn get_number_of_imports(data: &[u8]) -> usize {
    PeInfo::parse(data)
        .map(|pe| pe.number_of_imports())
        .unwrap_or(0)
}

/// Get number of exports
pub fn get_number_of_exports(data: &[u8]) -> usize {
    PeInfo::parse(data)
        .map(|pe| pe.number_of_exports())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_pe_invalid() {
        // Test invalid PE detection
        assert!(!is_pe(b"not a PE file"));
        assert!(!is_pe(b"MZ")); // Too short
        assert!(!is_pe(b"\x00\x00\x00\x00")); // Wrong magic
        assert!(!is_pe(&[])); // Empty
    }

    #[test]
    fn test_convenience_functions_invalid_data() {
        // All convenience functions should return safe defaults for invalid data
        let bad_data = b"not a PE file";
        assert!(!is_pe(bad_data));
        assert!(!is_32bit(bad_data));
        assert!(!is_64bit(bad_data));
        assert!(!is_dll(bad_data));
        assert_eq!(get_machine(bad_data), 0);
        assert_eq!(get_subsystem(bad_data), 0);
        assert_eq!(get_entry_point(bad_data), 0);
        assert_eq!(get_number_of_sections(bad_data), 0);
        assert_eq!(get_number_of_imports(bad_data), 0);
        assert_eq!(get_number_of_exports(bad_data), 0);
    }

    #[test]
    fn test_constants() {
        // Test that constants are defined correctly
        assert_eq!(characteristics::EXECUTABLE_IMAGE, 0x0002);
        assert_eq!(characteristics::DLL, 0x2000);
        assert_eq!(machine::I386, 0x14c);
        assert_eq!(machine::AMD64, 0x8664);
        assert_eq!(subsystem::WINDOWS_GUI, 2);
        assert_eq!(subsystem::WINDOWS_CUI, 3);
        assert_eq!(section_characteristics::MEM_EXECUTE, 0x20000000);
        assert_eq!(section_characteristics::MEM_READ, 0x40000000);
        assert_eq!(section_characteristics::MEM_WRITE, 0x80000000);
    }

    #[test]
    fn test_section_struct() {
        let section = Section {
            name: SmolStr::new(".text"),
            virtual_address: 0x1000,
            virtual_size: 0x500,
            raw_data_offset: 0x400,
            raw_data_size: 0x200,
            characteristics: section_characteristics::CNT_CODE | section_characteristics::MEM_EXECUTE,
        };
        assert_eq!(section.name.as_str(), ".text");
        assert!(section.characteristics & section_characteristics::CNT_CODE != 0);
    }

    #[test]
    fn test_import_struct() {
        let import = Import {
            library: SmolStr::new("kernel32.dll"),
            functions: vec![
                ImportFunction {
                    name: Some(SmolStr::new("GetProcAddress")),
                    ordinal: None,
                },
                ImportFunction {
                    name: None,
                    ordinal: Some(123),
                },
            ],
        };
        assert_eq!(import.library.as_str(), "kernel32.dll");
        assert_eq!(import.functions.len(), 2);
    }

    #[test]
    fn test_export_struct() {
        let export = Export {
            name: Some(SmolStr::new("DllMain")),
            ordinal: 1,
            rva: 0x1000,
        };
        assert_eq!(export.name.as_ref().unwrap().as_str(), "DllMain");
        assert_eq!(export.ordinal, 1);
    }
}
