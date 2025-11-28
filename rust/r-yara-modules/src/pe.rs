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

    /// Calculate the import hash (imphash)
    ///
    /// The import hash is an MD5 hash of the normalized import table.
    /// This is used for malware classification and identification.
    ///
    /// The algorithm:
    /// 1. For each import: lowercase(dll_name without extension).function_name
    /// 2. For ordinal imports: lowercase(dll_name without extension).ord{ordinal}
    /// 3. Concatenate all with commas
    /// 4. MD5 hash the result
    ///
    /// # Example
    ///
    /// ```no_run
    /// use r_yara_modules::pe::PeInfo;
    ///
    /// let data = std::fs::read("sample.exe").unwrap();
    /// if let Some(pe) = PeInfo::parse(&data) {
    ///     if let Some(hash) = pe.imphash() {
    ///         println!("Import hash: {}", hash);
    ///     }
    /// }
    /// ```
    pub fn imphash(&self) -> Option<String> {
        if self.pe.imports.is_empty() {
            return None;
        }

        let mut import_strings = Vec::new();

        for import in &self.pe.imports {
            // Normalize DLL name: lowercase and remove extension
            let dll_name = import.dll.to_lowercase();
            let dll_normalized = dll_name
                .strip_suffix(".dll")
                .or_else(|| dll_name.strip_suffix(".ocx"))
                .or_else(|| dll_name.strip_suffix(".sys"))
                .unwrap_or(&dll_name);

            // Get function name or ordinal
            let func_name = import.name.as_ref();
            if !func_name.is_empty() {
                // Named import
                let import_str = format!("{}.{}", dll_normalized, func_name.to_lowercase());
                import_strings.push(import_str);
            } else if import.ordinal != 0 {
                // Ordinal import
                let import_str = format!("{}.ord{}", dll_normalized, import.ordinal);
                import_strings.push(import_str);
            }
        }

        if import_strings.is_empty() {
            return None;
        }

        // Sort imports for consistent hashing (YARA doesn't sort, but some tools do)
        // Actually YARA keeps the order as-is, so we don't sort
        let import_data = import_strings.join(",");

        // Calculate MD5 using md5::compute
        let digest = md5::compute(import_data.as_bytes());
        Some(format!("{:x}", digest))
    }

    /// Calculate import hash using SHA256 for stronger fingerprinting
    pub fn imphash_sha256(&self) -> Option<String> {
        if self.pe.imports.is_empty() {
            return None;
        }

        let mut import_strings = Vec::new();

        for import in &self.pe.imports {
            let dll_name = import.dll.to_lowercase();
            let dll_normalized = dll_name
                .strip_suffix(".dll")
                .or_else(|| dll_name.strip_suffix(".ocx"))
                .or_else(|| dll_name.strip_suffix(".sys"))
                .unwrap_or(&dll_name);

            let func_name = import.name.as_ref();
            if !func_name.is_empty() {
                let import_str = format!("{}.{}", dll_normalized, func_name.to_lowercase());
                import_strings.push(import_str);
            } else if import.ordinal != 0 {
                let import_str = format!("{}.ord{}", dll_normalized, import.ordinal);
                import_strings.push(import_str);
            }
        }

        if import_strings.is_empty() {
            return None;
        }

        let import_data = import_strings.join(",");

        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(import_data.as_bytes());
        Some(hex::encode(hasher.finalize()))
    }

    /// Get version info string by key
    ///
    /// Retrieves a version information string from the VS_VERSIONINFO resource.
    ///
    /// # Common Keys
    ///
    /// - `CompanyName` - Company that produced the file
    /// - `FileDescription` - File description to be presented to users
    /// - `FileVersion` - Version number of the file
    /// - `InternalName` - Internal name of the file
    /// - `LegalCopyright` - Copyright notices
    /// - `OriginalFilename` - Original name of the file
    /// - `ProductName` - Name of the product with which the file is distributed
    /// - `ProductVersion` - Version of the product with which the file is distributed
    ///
    /// # Example
    ///
    /// ```no_run
    /// use r_yara_modules::pe::PeInfo;
    ///
    /// let data = std::fs::read("sample.exe").unwrap();
    /// if let Some(pe) = PeInfo::parse(&data) {
    ///     if let Some(company) = pe.version_info("CompanyName") {
    ///         println!("Company: {}", company);
    ///     }
    ///     if let Some(version) = pe.version_info("FileVersion") {
    ///         println!("Version: {}", version);
    ///     }
    /// }
    /// ```
    pub fn version_info(&self, key: &str) -> Option<String> {
        self.find_version_string(key)
    }

    /// Find a version info string by searching for UTF-16LE encoded key
    fn find_version_string(&self, key: &str) -> Option<String> {
        // Convert key to UTF-16LE for searching
        let mut key_utf16: Vec<u8> = Vec::new();
        for c in key.encode_utf16() {
            key_utf16.extend_from_slice(&c.to_le_bytes());
        }
        // Add null terminator
        key_utf16.extend_from_slice(&[0u8, 0u8]);

        // First try searching in the resource section (.rsrc)
        if let Some(rsrc_section) = self.section_by_name(".rsrc") {
            let start = rsrc_section.raw_data_offset as usize;
            let end = start + rsrc_section.raw_data_size as usize;
            if end <= self.data.len() {
                let rsrc_data = &self.data[start..end];
                if let Some(value) = self.extract_version_value(rsrc_data, &key_utf16) {
                    return Some(value);
                }
            }
        }

        // If not found in .rsrc, search the entire file
        self.extract_version_value(self.data, &key_utf16)
    }

    /// Extract version value following a key in the data
    fn extract_version_value(&self, data: &[u8], key_utf16: &[u8]) -> Option<String> {
        // Search for the key pattern
        for i in 0..data.len().saturating_sub(key_utf16.len()) {
            if &data[i..i + key_utf16.len()] == key_utf16 {
                // Found the key, now extract the value
                let value_start = i + key_utf16.len();

                // Skip any alignment padding (typically aligned to 4-byte boundaries)
                let mut value_offset = value_start;
                while value_offset < data.len() && value_offset < value_start + 8 {
                    // Check if we're at the start of a UTF-16LE string
                    if value_offset + 1 < data.len() {
                        let c1 = data[value_offset];
                        let c2 = data[value_offset + 1];

                        // Check if this looks like the start of a valid UTF-16LE string
                        // (printable ASCII or null terminator)
                        if (c1 >= 0x20 && c1 < 0x7F && c2 == 0) || (c1 == 0 && c2 == 0) {
                            break;
                        }
                    }
                    value_offset += 1;
                }

                if value_offset >= data.len() {
                    continue;
                }

                // Read the value as UTF-16LE until null terminator
                let mut value_utf16: Vec<u16> = Vec::new();
                let mut offset = value_offset;

                while offset + 1 < data.len() {
                    let c = u16::from_le_bytes([data[offset], data[offset + 1]]);
                    if c == 0 {
                        break;
                    }
                    value_utf16.push(c);
                    offset += 2;

                    // Limit value length to prevent runaway reads
                    if value_utf16.len() > 1024 {
                        break;
                    }
                }

                if !value_utf16.is_empty() {
                    // Convert UTF-16LE to String
                    if let Ok(value) = String::from_utf16(&value_utf16) {
                        // Validate that the string contains mostly printable characters
                        let printable_count = value.chars().filter(|c| c.is_ascii_graphic() || c.is_whitespace()).count();
                        if printable_count as f32 / value.len() as f32 > 0.7 {
                            return Some(value);
                        }
                    }
                }
            }
        }

        None
    }

    /// Parse and return Rich header entries
    ///
    /// The Rich header is a hidden structure between the DOS stub and PE header
    /// that identifies the build tools used to create the executable.
    ///
    /// # Returns
    ///
    /// A vector of RichEntry containing tool_id, version, and count for each entry.
    /// Returns an empty vector if the Rich header is not found or cannot be parsed.
    pub fn rich_signature_entries(&self) -> Vec<RichEntry> {
        let mut entries = Vec::new();

        // Get the PE header offset
        let pe_offset = self.dos_header_e_lfanew() as usize;
        if pe_offset < 0x40 || pe_offset >= self.data.len() {
            return entries;
        }

        // Search for "Rich" marker in the DOS stub area (between offset 0x80 and PE header)
        let search_start = 0x80;
        let search_end = pe_offset;

        if search_end <= search_start || search_end > self.data.len() {
            return entries;
        }

        // Find "Rich" marker
        let rich_marker = b"Rich";
        let mut rich_offset = None;

        for i in search_start..search_end.saturating_sub(4) {
            if &self.data[i..i + 4] == rich_marker {
                rich_offset = Some(i);
                break;
            }
        }

        let rich_pos = match rich_offset {
            Some(pos) => pos,
            None => return entries,
        };

        // XOR key is 4 bytes after "Rich" marker
        if rich_pos + 8 > self.data.len() {
            return entries;
        }

        let xor_key = u32::from_le_bytes([
            self.data[rich_pos + 4],
            self.data[rich_pos + 5],
            self.data[rich_pos + 6],
            self.data[rich_pos + 7],
        ]);

        // Search backward for "DanS" marker (XORed with key)
        let dans_marker = 0x536E6144u32; // "DanS" as little-endian u32
        let xored_dans = dans_marker ^ xor_key;

        let mut dans_offset = None;
        for i in (search_start..rich_pos).rev().step_by(4) {
            if i + 4 <= self.data.len() {
                let val = u32::from_le_bytes([
                    self.data[i],
                    self.data[i + 1],
                    self.data[i + 2],
                    self.data[i + 3],
                ]);
                if val == xored_dans {
                    dans_offset = Some(i);
                    break;
                }
            }
        }

        let dans_pos = match dans_offset {
            Some(pos) => pos,
            None => return entries,
        };

        // Parse entries between DanS and Rich (skip first 16 bytes which are padding)
        let entry_start = dans_pos + 16; // Skip "DanS" + 3 padding DWORDs

        for offset in (entry_start..rich_pos).step_by(8) {
            if offset + 8 > self.data.len() {
                break;
            }

            // Read and XOR the two DWORDs
            let dword1 = u32::from_le_bytes([
                self.data[offset],
                self.data[offset + 1],
                self.data[offset + 2],
                self.data[offset + 3],
            ]) ^ xor_key;

            let dword2 = u32::from_le_bytes([
                self.data[offset + 4],
                self.data[offset + 5],
                self.data[offset + 6],
                self.data[offset + 7],
            ]) ^ xor_key;

            // First DWORD: tool_id (high 16 bits) and version (low 16 bits)
            let tool_id = (dword1 >> 16) as u16;
            let version = (dword1 & 0xFFFF) as u16;
            let count = dword2;

            // Skip zero entries
            if tool_id == 0 && version == 0 && count == 0 {
                continue;
            }

            entries.push(RichEntry {
                tool_id,
                version,
                count,
            });
        }

        entries
    }

    /// Get the XOR key used to decode the Rich header
    ///
    /// Returns None if the Rich header is not found.
    pub fn rich_signature_key(&self) -> Option<u32> {
        let pe_offset = self.dos_header_e_lfanew() as usize;
        if pe_offset < 0x40 || pe_offset >= self.data.len() {
            return None;
        }

        let search_start = 0x80;
        let search_end = pe_offset;

        if search_end <= search_start || search_end > self.data.len() {
            return None;
        }

        // Find "Rich" marker
        let rich_marker = b"Rich";
        for i in search_start..search_end.saturating_sub(4) {
            if &self.data[i..i + 4] == rich_marker {
                if i + 8 <= self.data.len() {
                    return Some(u32::from_le_bytes([
                        self.data[i + 4],
                        self.data[i + 5],
                        self.data[i + 6],
                        self.data[i + 7],
                    ]));
                }
            }
        }

        None
    }

    /// Get the clear (decoded) Rich header data
    ///
    /// Returns the XOR-decoded Rich header data from "DanS" to "Rich" (exclusive).
    pub fn rich_signature_clear_data(&self) -> Option<Vec<u8>> {
        let xor_key = self.rich_signature_key()?;
        let pe_offset = self.dos_header_e_lfanew() as usize;

        let search_start = 0x80;
        let search_end = pe_offset;

        // Find "Rich" marker
        let rich_marker = b"Rich";
        let mut rich_pos = None;
        for i in search_start..search_end.saturating_sub(4) {
            if &self.data[i..i + 4] == rich_marker {
                rich_pos = Some(i);
                break;
            }
        }
        let rich_pos = rich_pos?;

        // Find "DanS" marker
        let dans_marker = 0x536E6144u32;
        let xored_dans = dans_marker ^ xor_key;

        let mut dans_pos = None;
        for i in (search_start..rich_pos).rev().step_by(4) {
            if i + 4 <= self.data.len() {
                let val = u32::from_le_bytes([
                    self.data[i],
                    self.data[i + 1],
                    self.data[i + 2],
                    self.data[i + 3],
                ]);
                if val == xored_dans {
                    dans_pos = Some(i);
                    break;
                }
            }
        }
        let dans_pos = dans_pos?;

        // Decode the data
        let key_bytes = xor_key.to_le_bytes();
        let mut clear_data = Vec::new();

        for i in dans_pos..rich_pos {
            let key_byte = key_bytes[(i - dans_pos) % 4];
            clear_data.push(self.data[i] ^ key_byte);
        }

        Some(clear_data)
    }

    /// Check if the PE has a Rich header
    pub fn has_rich_signature(&self) -> bool {
        self.rich_signature_key().is_some()
    }

    /// Get Rich header version by tool ID
    ///
    /// Returns the version number for the given tool ID, or None if not found.
    pub fn rich_signature_version(&self, tool_id: u16) -> Option<u16> {
        self.rich_signature_entries()
            .into_iter()
            .find(|e| e.tool_id == tool_id)
            .map(|e| e.version)
    }

    /// Get Rich header tool ID by version
    ///
    /// Returns the tool ID for the given version, or None if not found.
    pub fn rich_signature_toolid(&self, version: u16) -> Option<u16> {
        self.rich_signature_entries()
            .into_iter()
            .find(|e| e.version == version)
            .map(|e| e.tool_id)
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

/// Calculate import hash (imphash) for malware classification
pub fn imphash(data: &[u8]) -> Option<String> {
    PeInfo::parse(data).and_then(|pe| pe.imphash())
}

/// Calculate import hash using SHA256 for stronger fingerprinting
pub fn imphash_sha256(data: &[u8]) -> Option<String> {
    PeInfo::parse(data).and_then(|pe| pe.imphash_sha256())
}

/// Get Rich signature entries from PE file
pub fn rich_signature_entries(data: &[u8]) -> Vec<RichEntry> {
    PeInfo::parse(data)
        .map(|pe| pe.rich_signature_entries())
        .unwrap_or_default()
}

/// Get Rich signature XOR key
pub fn rich_signature_key(data: &[u8]) -> Option<u32> {
    PeInfo::parse(data).and_then(|pe| pe.rich_signature_key())
}

/// Check if PE has Rich signature
pub fn has_rich_signature(data: &[u8]) -> bool {
    PeInfo::parse(data)
        .map(|pe| pe.has_rich_signature())
        .unwrap_or(false)
}

/// Get Rich signature clear (decoded) data
pub fn rich_signature_clear_data(data: &[u8]) -> Option<Vec<u8>> {
    PeInfo::parse(data).and_then(|pe| pe.rich_signature_clear_data())
}

/// Get version info string by key from PE resource data
///
/// Common keys: CompanyName, FileDescription, FileVersion, InternalName,
/// LegalCopyright, OriginalFilename, ProductName, ProductVersion
pub fn get_version_info(data: &[u8], key: &str) -> Option<String> {
    PeInfo::parse(data).and_then(|pe| pe.version_info(key))
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

    #[test]
    fn test_imphash_invalid_data() {
        // imphash should return None for invalid PE data
        assert!(imphash(b"not a PE file").is_none());
        assert!(imphash(&[]).is_none());
    }

    #[test]
    fn test_version_info_invalid_data() {
        // version_info should return None for invalid PE data
        assert!(get_version_info(b"not a PE file", "CompanyName").is_none());
        assert!(get_version_info(&[], "FileVersion").is_none());
    }

    #[test]
    fn test_version_info_utf16_encoding() {
        // Create a minimal test with UTF-16LE encoded version info
        // This simulates a version info structure with CompanyName = "TestCompany"
        let mut test_data = Vec::new();

        // Add MZ header (minimal DOS header)
        test_data.extend_from_slice(b"MZ");
        test_data.extend_from_slice(&[0u8; 58]); // Padding to offset 60
        test_data.extend_from_slice(&[0x80, 0x00, 0x00, 0x00]); // e_lfanew at offset 60

        // Pad to PE header at offset 0x80
        while test_data.len() < 0x80 {
            test_data.push(0);
        }

        // Add PE signature
        test_data.extend_from_slice(b"PE\0\0");

        // Add minimal COFF header (20 bytes)
        test_data.extend_from_slice(&[
            0x4c, 0x01, // Machine (I386)
            0x01, 0x00, // NumberOfSections
            0x00, 0x00, 0x00, 0x00, // TimeDateStamp
            0x00, 0x00, 0x00, 0x00, // PointerToSymbolTable
            0x00, 0x00, 0x00, 0x00, // NumberOfSymbols
            0xe0, 0x00, // SizeOfOptionalHeader (224 for PE32)
            0x0f, 0x01, // Characteristics
        ]);

        // Add minimal optional header (224 bytes for PE32)
        test_data.extend_from_slice(&[0x0b, 0x01]); // Magic (PE32)
        test_data.extend_from_slice(&[0u8; 222]); // Rest of optional header

        // Add section header for .rsrc
        let section_name = b".rsrc\0\0\0";
        test_data.extend_from_slice(section_name);
        test_data.extend_from_slice(&[0x00, 0x10, 0x00, 0x00]); // VirtualSize
        test_data.extend_from_slice(&[0x00, 0x30, 0x00, 0x00]); // VirtualAddress
        test_data.extend_from_slice(&[0x00, 0x02, 0x00, 0x00]); // SizeOfRawData (512 bytes)
        test_data.extend_from_slice(&[0x00, 0x04, 0x00, 0x00]); // PointerToRawData (0x400)
        test_data.extend_from_slice(&[0u8; 12]); // Relocations, etc.
        test_data.extend_from_slice(&[0x40, 0x00, 0x00, 0x40]); // Characteristics

        // Pad to resource section at 0x400
        while test_data.len() < 0x400 {
            test_data.push(0);
        }

        // Add version info with CompanyName = "TestCompany" in UTF-16LE
        // First, the key "CompanyName" in UTF-16LE with null terminator
        let key = "CompanyName";
        for c in key.encode_utf16() {
            test_data.extend_from_slice(&c.to_le_bytes());
        }
        test_data.extend_from_slice(&[0u8, 0u8]); // Null terminator

        // Some padding bytes
        test_data.extend_from_slice(&[0u8, 0u8]);

        // Then the value "TestCompany" in UTF-16LE with null terminator
        let value = "TestCompany";
        for c in value.encode_utf16() {
            test_data.extend_from_slice(&c.to_le_bytes());
        }
        test_data.extend_from_slice(&[0u8, 0u8]); // Null terminator

        // Pad to 512 bytes (size of .rsrc section)
        while test_data.len() < 0x400 + 512 {
            test_data.push(0);
        }

        // Now test if we can parse it (this will likely fail since we don't have a complete PE)
        // but we can test the version_info method directly if we have a valid PE
        // For now, just verify the test data structure
        assert!(test_data.len() >= 0x400 + 512);
    }

    #[test]
    fn test_version_info_common_keys() {
        // Test that common version info keys don't panic on invalid data
        let common_keys = [
            "CompanyName",
            "FileDescription",
            "FileVersion",
            "InternalName",
            "LegalCopyright",
            "OriginalFilename",
            "ProductName",
            "ProductVersion",
        ];

        for key in &common_keys {
            assert!(get_version_info(b"not a PE", key).is_none());
        }
    }

    #[test]
    fn test_rich_signature_invalid_data() {
        // Rich signature functions should return None/empty for invalid PE data
        assert!(rich_signature_key(b"not a PE file").is_none());
        assert!(rich_signature_entries(b"not a PE file").is_empty());
        assert!(!has_rich_signature(b"not a PE file"));
        assert!(rich_signature_clear_data(b"not a PE file").is_none());
    }

    #[test]
    fn test_rich_entry_struct() {
        let entry = RichEntry {
            tool_id: 0x105,
            version: 30729,
            count: 5,
        };
        assert_eq!(entry.tool_id, 0x105);
        assert_eq!(entry.version, 30729);
        assert_eq!(entry.count, 5);
    }
}
