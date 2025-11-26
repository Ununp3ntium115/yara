//! Mach-O Module
//!
//! Provides Mach-O (macOS/iOS executable) file analysis compatible with YARA's macho module.
//!
//! # YARA Compatibility
//!
//! This module is compatible with YARA's built-in macho module:
//!
//! ```yara
//! import "macho"
//!
//! rule MachoExample {
//!     condition:
//!         macho.cputype == macho.CPU_TYPE_X86_64 and
//!         macho.filetype == macho.MH_EXECUTE
//! }
//! ```

use goblin::mach::{Mach, MachO};
use smol_str::SmolStr;

// ============================================================================
// Mach-O Constants (matching YARA's macho module)
// ============================================================================

/// CPU Types
pub mod cpu_type {
    pub const CPU_TYPE_MC680X0: u32 = 0x00000006;
    pub const CPU_TYPE_X86: u32 = 0x00000007;
    pub const CPU_TYPE_I386: u32 = CPU_TYPE_X86;
    pub const CPU_TYPE_X86_64: u32 = 0x01000007;
    pub const CPU_TYPE_MIPS: u32 = 0x00000008;
    pub const CPU_TYPE_MC98000: u32 = 0x0000000A;
    pub const CPU_TYPE_ARM: u32 = 0x0000000C;
    pub const CPU_TYPE_ARM64: u32 = 0x0100000C;
    pub const CPU_TYPE_MC88000: u32 = 0x0000000D;
    pub const CPU_TYPE_SPARC: u32 = 0x0000000E;
    pub const CPU_TYPE_POWERPC: u32 = 0x00000012;
    pub const CPU_TYPE_POWERPC64: u32 = 0x01000012;
}

/// CPU Subtypes for X86
pub mod cpu_subtype_x86 {
    pub const CPU_SUBTYPE_I386_ALL: u32 = 3;
    pub const CPU_SUBTYPE_386: u32 = 3;
    pub const CPU_SUBTYPE_486: u32 = 4;
    pub const CPU_SUBTYPE_486SX: u32 = 0x84;
    pub const CPU_SUBTYPE_586: u32 = 5;
    pub const CPU_SUBTYPE_PENTPRO: u32 = 0x16;
    pub const CPU_SUBTYPE_PENTII_M3: u32 = 0x36;
    pub const CPU_SUBTYPE_PENTII_M5: u32 = 0x56;
    pub const CPU_SUBTYPE_CELERON: u32 = 0x67;
    pub const CPU_SUBTYPE_CELERON_MOBILE: u32 = 0x77;
    pub const CPU_SUBTYPE_PENTIUM_3: u32 = 0x08;
    pub const CPU_SUBTYPE_PENTIUM_3_M: u32 = 0x18;
    pub const CPU_SUBTYPE_PENTIUM_3_XEON: u32 = 0x28;
    pub const CPU_SUBTYPE_PENTIUM_M: u32 = 0x09;
    pub const CPU_SUBTYPE_PENTIUM_4: u32 = 0x0A;
    pub const CPU_SUBTYPE_PENTIUM_4_M: u32 = 0x1A;
    pub const CPU_SUBTYPE_XEON: u32 = 0x0B;
    pub const CPU_SUBTYPE_XEON_MP: u32 = 0x1B;
}

/// CPU Subtypes for ARM
pub mod cpu_subtype_arm {
    pub const CPU_SUBTYPE_ARM_ALL: u32 = 0;
    pub const CPU_SUBTYPE_ARM_V4T: u32 = 5;
    pub const CPU_SUBTYPE_ARM_V6: u32 = 6;
    pub const CPU_SUBTYPE_ARM_V5TEJ: u32 = 7;
    pub const CPU_SUBTYPE_ARM_XSCALE: u32 = 8;
    pub const CPU_SUBTYPE_ARM_V7: u32 = 9;
    pub const CPU_SUBTYPE_ARM_V7F: u32 = 10;
    pub const CPU_SUBTYPE_ARM_V7S: u32 = 11;
    pub const CPU_SUBTYPE_ARM_V7K: u32 = 12;
    pub const CPU_SUBTYPE_ARM_V6M: u32 = 14;
    pub const CPU_SUBTYPE_ARM_V7M: u32 = 15;
    pub const CPU_SUBTYPE_ARM_V7EM: u32 = 16;
}

/// CPU Subtypes for ARM64
pub mod cpu_subtype_arm64 {
    pub const CPU_SUBTYPE_ARM64_ALL: u32 = 0;
    pub const CPU_SUBTYPE_ARM64_V8: u32 = 1;
    pub const CPU_SUBTYPE_ARM64E: u32 = 2;
}

/// File Types
pub mod file_type {
    pub const MH_OBJECT: u32 = 0x1;
    pub const MH_EXECUTE: u32 = 0x2;
    pub const MH_FVMLIB: u32 = 0x3;
    pub const MH_CORE: u32 = 0x4;
    pub const MH_PRELOAD: u32 = 0x5;
    pub const MH_DYLIB: u32 = 0x6;
    pub const MH_DYLINKER: u32 = 0x7;
    pub const MH_BUNDLE: u32 = 0x8;
    pub const MH_DYLIB_STUB: u32 = 0x9;
    pub const MH_DSYM: u32 = 0xA;
    pub const MH_KEXT_BUNDLE: u32 = 0xB;
}

/// Header Flags
pub mod flags {
    pub const MH_NOUNDEFS: u32 = 0x00000001;
    pub const MH_INCRLINK: u32 = 0x00000002;
    pub const MH_DYLDLINK: u32 = 0x00000004;
    pub const MH_BINDATLOAD: u32 = 0x00000008;
    pub const MH_PREBOUND: u32 = 0x00000010;
    pub const MH_SPLIT_SEGS: u32 = 0x00000020;
    pub const MH_LAZY_INIT: u32 = 0x00000040;
    pub const MH_TWOLEVEL: u32 = 0x00000080;
    pub const MH_FORCE_FLAT: u32 = 0x00000100;
    pub const MH_NOMULTIDEFS: u32 = 0x00000200;
    pub const MH_NOFIXPREBINDING: u32 = 0x00000400;
    pub const MH_PREBINDABLE: u32 = 0x00000800;
    pub const MH_ALLMODSBOUND: u32 = 0x00001000;
    pub const MH_SUBSECTIONS_VIA_SYMBOLS: u32 = 0x00002000;
    pub const MH_CANONICAL: u32 = 0x00004000;
    pub const MH_WEAK_DEFINES: u32 = 0x00008000;
    pub const MH_BINDS_TO_WEAK: u32 = 0x00010000;
    pub const MH_ALLOW_STACK_EXECUTION: u32 = 0x00020000;
    pub const MH_ROOT_SAFE: u32 = 0x00040000;
    pub const MH_SETUID_SAFE: u32 = 0x00080000;
    pub const MH_NO_REEXPORTED_DYLIBS: u32 = 0x00100000;
    pub const MH_PIE: u32 = 0x00200000;
    pub const MH_DEAD_STRIPPABLE_DYLIB: u32 = 0x00400000;
    pub const MH_HAS_TLV_DESCRIPTORS: u32 = 0x00800000;
    pub const MH_NO_HEAP_EXECUTION: u32 = 0x01000000;
    pub const MH_APP_EXTENSION_SAFE: u32 = 0x02000000;
}

/// Load Command Types
pub mod load_command {
    pub const LC_SEGMENT: u32 = 0x1;
    pub const LC_SYMTAB: u32 = 0x2;
    pub const LC_SYMSEG: u32 = 0x3;
    pub const LC_THREAD: u32 = 0x4;
    pub const LC_UNIXTHREAD: u32 = 0x5;
    pub const LC_LOADFVMLIB: u32 = 0x6;
    pub const LC_IDFVMLIB: u32 = 0x7;
    pub const LC_IDENT: u32 = 0x8;
    pub const LC_FVMFILE: u32 = 0x9;
    pub const LC_PREPAGE: u32 = 0xA;
    pub const LC_DYSYMTAB: u32 = 0xB;
    pub const LC_LOAD_DYLIB: u32 = 0xC;
    pub const LC_ID_DYLIB: u32 = 0xD;
    pub const LC_LOAD_DYLINKER: u32 = 0xE;
    pub const LC_ID_DYLINKER: u32 = 0xF;
    pub const LC_PREBOUND_DYLIB: u32 = 0x10;
    pub const LC_ROUTINES: u32 = 0x11;
    pub const LC_SUB_FRAMEWORK: u32 = 0x12;
    pub const LC_SUB_UMBRELLA: u32 = 0x13;
    pub const LC_SUB_CLIENT: u32 = 0x14;
    pub const LC_SUB_LIBRARY: u32 = 0x15;
    pub const LC_TWOLEVEL_HINTS: u32 = 0x16;
    pub const LC_PREBIND_CKSUM: u32 = 0x17;
    pub const LC_LOAD_WEAK_DYLIB: u32 = 0x80000018;
    pub const LC_SEGMENT_64: u32 = 0x19;
    pub const LC_ROUTINES_64: u32 = 0x1A;
    pub const LC_UUID: u32 = 0x1B;
    pub const LC_RPATH: u32 = 0x8000001C;
    pub const LC_CODE_SIGNATURE: u32 = 0x1D;
    pub const LC_SEGMENT_SPLIT_INFO: u32 = 0x1E;
    pub const LC_REEXPORT_DYLIB: u32 = 0x8000001F;
    pub const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
    pub const LC_ENCRYPTION_INFO: u32 = 0x21;
    pub const LC_DYLD_INFO: u32 = 0x22;
    pub const LC_DYLD_INFO_ONLY: u32 = 0x80000022;
    pub const LC_LOAD_UPWARD_DYLIB: u32 = 0x80000023;
    pub const LC_VERSION_MIN_MACOSX: u32 = 0x24;
    pub const LC_VERSION_MIN_IPHONEOS: u32 = 0x25;
    pub const LC_FUNCTION_STARTS: u32 = 0x26;
    pub const LC_DYLD_ENVIRONMENT: u32 = 0x27;
    pub const LC_MAIN: u32 = 0x80000028;
    pub const LC_DATA_IN_CODE: u32 = 0x29;
    pub const LC_SOURCE_VERSION: u32 = 0x2A;
    pub const LC_DYLIB_CODE_SIGN_DRS: u32 = 0x2B;
    pub const LC_ENCRYPTION_INFO_64: u32 = 0x2C;
    pub const LC_LINKER_OPTION: u32 = 0x2D;
    pub const LC_LINKER_OPTIMIZATION_HINT: u32 = 0x2E;
    pub const LC_VERSION_MIN_TVOS: u32 = 0x2F;
    pub const LC_VERSION_MIN_WATCHOS: u32 = 0x30;
    pub const LC_BUILD_VERSION: u32 = 0x32;
}

// ============================================================================
// Data Structures
// ============================================================================

/// Segment information
#[derive(Debug, Clone)]
pub struct Segment {
    pub segname: SmolStr,
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub maxprot: u32,
    pub initprot: u32,
    pub nsects: u32,
    pub flags: u32,
}

/// Section information
#[derive(Debug, Clone)]
pub struct Section {
    pub sectname: SmolStr,
    pub segname: SmolStr,
    pub addr: u64,
    pub size: u64,
    pub offset: u32,
    pub align: u32,
    pub reloff: u32,
    pub nreloc: u32,
    pub flags: u32,
}

/// Library dependency
#[derive(Debug, Clone)]
pub struct Library {
    pub name: SmolStr,
    pub timestamp: u32,
    pub current_version: u32,
    pub compatibility_version: u32,
}

/// Symbol information
#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: SmolStr,
    pub n_type: u8,
    pub n_sect: u8,
    pub n_desc: u16,
    pub n_value: u64,
}

/// Parsed Mach-O file information
#[derive(Debug, Clone)]
pub struct MachoInfo {
    pub is_macho: bool,
    pub is_64bit: bool,
    pub is_fat: bool,
    pub magic: u32,
    pub cputype: u32,
    pub cpusubtype: u32,
    pub filetype: u32,
    pub ncmds: u32,
    pub sizeofcmds: u32,
    pub flags: u32,
    pub entry_point: u64,
    pub segments: Vec<Segment>,
    pub sections: Vec<Section>,
    pub libraries: Vec<Library>,
    pub symbols: Vec<Symbol>,
    pub uuid: Option<[u8; 16]>,
    pub min_version: Option<(u32, u32)>, // (version, sdk)
    /// For fat binaries, the number of architectures
    pub nfat_arch: u32,
}

impl Default for MachoInfo {
    fn default() -> Self {
        Self {
            is_macho: false,
            is_64bit: false,
            is_fat: false,
            magic: 0,
            cputype: 0,
            cpusubtype: 0,
            filetype: 0,
            ncmds: 0,
            sizeofcmds: 0,
            flags: 0,
            entry_point: 0,
            segments: Vec::new(),
            sections: Vec::new(),
            libraries: Vec::new(),
            symbols: Vec::new(),
            uuid: None,
            min_version: None,
            nfat_arch: 0,
        }
    }
}

impl MachoInfo {
    /// Parse a Mach-O file from bytes
    pub fn parse(data: &[u8]) -> Self {
        match goblin::mach::Mach::parse(data) {
            Ok(Mach::Binary(macho)) => Self::from_macho(&macho, data),
            Ok(Mach::Fat(fat)) => {
                // For fat binaries, parse the first architecture
                let nfat = fat.narches as u32;
                let mut info = if let Ok(arches) = fat.arches() {
                    if let Some(arch) = arches.first() {
                        // Get the slice for this architecture and parse it
                        let start = arch.offset as usize;
                        let end = start + arch.size as usize;
                        if end <= data.len() {
                            match MachO::parse(&data[start..end], 0) {
                                Ok(macho) => Self::from_macho(&macho, data),
                                Err(_) => Self::default(),
                            }
                        } else {
                            Self::default()
                        }
                    } else {
                        Self::default()
                    }
                } else {
                    Self::default()
                };
                info.is_fat = true;
                info.nfat_arch = nfat;
                info
            }
            Err(_) => Self::default(),
        }
    }

    fn from_macho(macho: &MachO, _data: &[u8]) -> Self {
        let header = &macho.header;

        let mut info = Self {
            is_macho: true,
            is_64bit: macho.is_64,
            is_fat: false,
            magic: header.magic,
            cputype: header.cputype as u32,
            cpusubtype: header.cpusubtype as u32,
            filetype: header.filetype,
            ncmds: header.ncmds as u32,
            sizeofcmds: header.sizeofcmds as u32,
            flags: header.flags,
            entry_point: macho.entry,
            segments: Vec::new(),
            sections: Vec::new(),
            libraries: Vec::new(),
            symbols: Vec::new(),
            uuid: None,
            min_version: None,
            nfat_arch: 0,
        };

        // Parse segments and sections
        for segment in &macho.segments {
            let segname = segment.name().unwrap_or("").to_string();
            info.segments.push(Segment {
                segname: SmolStr::new(&segname),
                vmaddr: segment.vmaddr,
                vmsize: segment.vmsize,
                fileoff: segment.fileoff,
                filesize: segment.filesize,
                maxprot: segment.maxprot,
                initprot: segment.initprot,
                nsects: segment.nsects,
                flags: segment.flags,
            });

            // Parse sections within segment
            if let Ok(sections) = segment.sections() {
                for (section, _) in sections {
                    let sectname = section.name().unwrap_or("").to_string();
                    let seg_name = section.segname().unwrap_or("").to_string();
                    info.sections.push(Section {
                        sectname: SmolStr::new(&sectname),
                        segname: SmolStr::new(&seg_name),
                        addr: section.addr,
                        size: section.size,
                        offset: section.offset,
                        align: section.align,
                        reloff: section.reloff,
                        nreloc: section.nreloc,
                        flags: section.flags,
                    });
                }
            }
        }

        // Parse libraries
        for lib in &macho.libs {
            if !lib.is_empty() {
                info.libraries.push(Library {
                    name: SmolStr::new(*lib),
                    timestamp: 0,
                    current_version: 0,
                    compatibility_version: 0,
                });
            }
        }

        // Parse symbols
        if let Some(ref symbols) = macho.symbols {
            for symbol in symbols.iter() {
                if let Ok((name, nlist)) = symbol {
                    info.symbols.push(Symbol {
                        name: SmolStr::new(name),
                        n_type: nlist.n_type,
                        n_sect: nlist.n_sect as u8,
                        n_desc: nlist.n_desc as u16,
                        n_value: nlist.n_value,
                    });
                }
            }
        }

        info
    }

    /// Check if the file is a valid Mach-O
    pub fn is_macho(&self) -> bool {
        self.is_macho
    }

    /// Check if the binary is 64-bit
    pub fn is_64bit(&self) -> bool {
        self.is_64bit
    }

    /// Check if the binary is a fat/universal binary
    pub fn is_fat(&self) -> bool {
        self.is_fat
    }

    /// Check if the binary is an executable
    pub fn is_executable(&self) -> bool {
        self.filetype == file_type::MH_EXECUTE
    }

    /// Check if the binary is a dynamic library
    pub fn is_dylib(&self) -> bool {
        self.filetype == file_type::MH_DYLIB
    }

    /// Check if the binary is a bundle (plugin)
    pub fn is_bundle(&self) -> bool {
        self.filetype == file_type::MH_BUNDLE
    }

    /// Check if the binary is an object file
    pub fn is_object(&self) -> bool {
        self.filetype == file_type::MH_OBJECT
    }

    /// Check if the binary is a kernel extension
    pub fn is_kext(&self) -> bool {
        self.filetype == file_type::MH_KEXT_BUNDLE
    }

    /// Check if the binary has Position Independent Execution (PIE)
    pub fn has_pie(&self) -> bool {
        self.flags & flags::MH_PIE != 0
    }

    /// Check if the binary allows stack execution
    pub fn has_stack_execution(&self) -> bool {
        self.flags & flags::MH_ALLOW_STACK_EXECUTION != 0
    }

    /// Check if the binary has no heap execution
    pub fn has_no_heap_execution(&self) -> bool {
        self.flags & flags::MH_NO_HEAP_EXECUTION != 0
    }

    /// Check if the binary is app extension safe
    pub fn is_app_extension_safe(&self) -> bool {
        self.flags & flags::MH_APP_EXTENSION_SAFE != 0
    }

    /// Get CPU type name
    pub fn cpu_type_name(&self) -> &'static str {
        match self.cputype {
            cpu_type::CPU_TYPE_X86 => "x86",
            cpu_type::CPU_TYPE_X86_64 => "x86_64",
            cpu_type::CPU_TYPE_ARM => "arm",
            cpu_type::CPU_TYPE_ARM64 => "arm64",
            cpu_type::CPU_TYPE_POWERPC => "powerpc",
            cpu_type::CPU_TYPE_POWERPC64 => "powerpc64",
            _ => "unknown",
        }
    }

    /// Get file type name
    pub fn file_type_name(&self) -> &'static str {
        match self.filetype {
            file_type::MH_OBJECT => "object",
            file_type::MH_EXECUTE => "execute",
            file_type::MH_FVMLIB => "fvmlib",
            file_type::MH_CORE => "core",
            file_type::MH_PRELOAD => "preload",
            file_type::MH_DYLIB => "dylib",
            file_type::MH_DYLINKER => "dylinker",
            file_type::MH_BUNDLE => "bundle",
            file_type::MH_DYLIB_STUB => "dylib_stub",
            file_type::MH_DSYM => "dsym",
            file_type::MH_KEXT_BUNDLE => "kext",
            _ => "unknown",
        }
    }

    /// Get entry point address
    pub fn entry_point(&self) -> u64 {
        self.entry_point
    }

    /// Get number of segments
    pub fn num_segments(&self) -> usize {
        self.segments.len()
    }

    /// Get number of sections
    pub fn num_sections(&self) -> usize {
        self.sections.len()
    }

    /// Get segment by name
    pub fn segment(&self, name: &str) -> Option<&Segment> {
        self.segments.iter().find(|s| s.segname.as_str() == name)
    }

    /// Get section by name
    pub fn section(&self, segname: &str, sectname: &str) -> Option<&Section> {
        self.sections.iter().find(|s| {
            s.segname.as_str() == segname && s.sectname.as_str() == sectname
        })
    }

    /// Get all imported libraries
    pub fn imported_libraries(&self) -> &[Library] {
        &self.libraries
    }

    /// Check if a specific library is imported
    pub fn imports_library(&self, name: &str) -> bool {
        self.libraries.iter().any(|lib| lib.name.contains(name))
    }

    /// Get all symbols
    pub fn get_symbols(&self) -> &[Symbol] {
        &self.symbols
    }

    /// Check if a symbol exists
    pub fn has_symbol(&self, name: &str) -> bool {
        self.symbols.iter().any(|s| s.name.as_str() == name)
    }

    /// Get the __TEXT segment (main code segment)
    pub fn text_segment(&self) -> Option<&Segment> {
        self.segment("__TEXT")
    }

    /// Get the __DATA segment
    pub fn data_segment(&self) -> Option<&Segment> {
        self.segment("__DATA")
    }

    /// Get the __LINKEDIT segment
    pub fn linkedit_segment(&self) -> Option<&Segment> {
        self.segment("__LINKEDIT")
    }
}

// ============================================================================
// Convenience Functions
// ============================================================================

/// Parse a Mach-O file and return basic info
pub fn parse(data: &[u8]) -> MachoInfo {
    MachoInfo::parse(data)
}

/// Check if data is a valid Mach-O file
pub fn is_macho(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    matches!(
        magic,
        0xFEEDFACE | 0xFEEDFACF | 0xCEFAEDFE | 0xCFFAEDFE | 0xCAFEBABE | 0xBEBAFECA
    )
}

/// Get the magic number from data
pub fn magic(data: &[u8]) -> u32 {
    if data.len() < 4 {
        return 0;
    }
    u32::from_le_bytes([data[0], data[1], data[2], data[3]])
}

/// Get the CPU type
pub fn cputype(data: &[u8]) -> u32 {
    MachoInfo::parse(data).cputype
}

/// Get the CPU subtype
pub fn cpusubtype(data: &[u8]) -> u32 {
    MachoInfo::parse(data).cpusubtype
}

/// Get the file type
pub fn filetype(data: &[u8]) -> u32 {
    MachoInfo::parse(data).filetype
}

/// Get the number of load commands
pub fn ncmds(data: &[u8]) -> u32 {
    MachoInfo::parse(data).ncmds
}

/// Get header flags
pub fn header_flags(data: &[u8]) -> u32 {
    MachoInfo::parse(data).flags
}

/// Get entry point
pub fn entry_point(data: &[u8]) -> u64 {
    MachoInfo::parse(data).entry_point
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(cpu_type::CPU_TYPE_X86_64, 0x01000007);
        assert_eq!(cpu_type::CPU_TYPE_ARM64, 0x0100000C);
        assert_eq!(file_type::MH_EXECUTE, 0x2);
        assert_eq!(file_type::MH_DYLIB, 0x6);
        assert_eq!(flags::MH_PIE, 0x00200000);
    }

    #[test]
    fn test_invalid_data() {
        let data = b"not a macho file";
        let info = MachoInfo::parse(data);
        assert!(!info.is_macho());
    }

    #[test]
    fn test_is_macho_magic() {
        // MH_MAGIC (32-bit little endian)
        assert!(is_macho(&[0xCE, 0xFA, 0xED, 0xFE]));
        // MH_MAGIC_64 (64-bit little endian)
        assert!(is_macho(&[0xCF, 0xFA, 0xED, 0xFE]));
        // FAT_MAGIC
        assert!(is_macho(&[0xCA, 0xFE, 0xBA, 0xBE]));
        // Invalid
        assert!(!is_macho(&[0x00, 0x00, 0x00, 0x00]));
        // Too short
        assert!(!is_macho(&[0xCE, 0xFA]));
    }

    #[test]
    fn test_default_info() {
        let info = MachoInfo::default();
        assert!(!info.is_macho);
        assert!(!info.is_64bit);
        assert!(!info.is_fat);
        assert_eq!(info.filetype, 0);
        assert!(info.segments.is_empty());
        assert!(info.sections.is_empty());
    }

    #[test]
    fn test_segment_struct() {
        let segment = Segment {
            segname: SmolStr::new("__TEXT"),
            vmaddr: 0x100000000,
            vmsize: 0x1000,
            fileoff: 0,
            filesize: 0x1000,
            maxprot: 7,
            initprot: 5,
            nsects: 2,
            flags: 0,
        };
        assert_eq!(segment.segname.as_str(), "__TEXT");
        assert_eq!(segment.vmsize, 0x1000);
    }

    #[test]
    fn test_section_struct() {
        let section = Section {
            sectname: SmolStr::new("__text"),
            segname: SmolStr::new("__TEXT"),
            addr: 0x100000000,
            size: 0x500,
            offset: 0,
            align: 4,
            reloff: 0,
            nreloc: 0,
            flags: 0,
        };
        assert_eq!(section.sectname.as_str(), "__text");
        assert_eq!(section.segname.as_str(), "__TEXT");
    }

    #[test]
    fn test_library_struct() {
        let lib = Library {
            name: SmolStr::new("/usr/lib/libSystem.B.dylib"),
            timestamp: 0,
            current_version: 0x100000,
            compatibility_version: 0x10000,
        };
        assert!(lib.name.contains("libSystem"));
    }

    #[test]
    fn test_symbol_struct() {
        let sym = Symbol {
            name: SmolStr::new("_main"),
            n_type: 0x0F,
            n_sect: 1,
            n_desc: 0,
            n_value: 0x100000000,
        };
        assert_eq!(sym.name.as_str(), "_main");
    }

    #[test]
    fn test_file_type_helpers() {
        let mut info = MachoInfo::default();

        info.filetype = file_type::MH_EXECUTE;
        assert!(info.is_executable());
        assert!(!info.is_dylib());

        info.filetype = file_type::MH_DYLIB;
        assert!(info.is_dylib());
        assert!(!info.is_executable());

        info.filetype = file_type::MH_BUNDLE;
        assert!(info.is_bundle());

        info.filetype = file_type::MH_OBJECT;
        assert!(info.is_object());

        info.filetype = file_type::MH_KEXT_BUNDLE;
        assert!(info.is_kext());
    }

    #[test]
    fn test_flags_helpers() {
        let mut info = MachoInfo::default();

        info.flags = flags::MH_PIE;
        assert!(info.has_pie());
        assert!(!info.has_stack_execution());

        info.flags = flags::MH_ALLOW_STACK_EXECUTION;
        assert!(info.has_stack_execution());
        assert!(!info.has_pie());

        info.flags = flags::MH_NO_HEAP_EXECUTION;
        assert!(info.has_no_heap_execution());

        info.flags = flags::MH_APP_EXTENSION_SAFE;
        assert!(info.is_app_extension_safe());
    }

    #[test]
    fn test_cpu_type_name() {
        let mut info = MachoInfo::default();

        info.cputype = cpu_type::CPU_TYPE_X86_64;
        assert_eq!(info.cpu_type_name(), "x86_64");

        info.cputype = cpu_type::CPU_TYPE_ARM64;
        assert_eq!(info.cpu_type_name(), "arm64");

        info.cputype = cpu_type::CPU_TYPE_ARM;
        assert_eq!(info.cpu_type_name(), "arm");

        info.cputype = 0xFFFFFFFF;
        assert_eq!(info.cpu_type_name(), "unknown");
    }

    #[test]
    fn test_file_type_name() {
        let mut info = MachoInfo::default();

        info.filetype = file_type::MH_EXECUTE;
        assert_eq!(info.file_type_name(), "execute");

        info.filetype = file_type::MH_DYLIB;
        assert_eq!(info.file_type_name(), "dylib");

        info.filetype = file_type::MH_BUNDLE;
        assert_eq!(info.file_type_name(), "bundle");

        info.filetype = file_type::MH_KEXT_BUNDLE;
        assert_eq!(info.file_type_name(), "kext");

        info.filetype = 0xFF;
        assert_eq!(info.file_type_name(), "unknown");
    }

    #[test]
    fn test_segment_lookup() {
        let mut info = MachoInfo::default();
        info.segments.push(Segment {
            segname: SmolStr::new("__TEXT"),
            vmaddr: 0x1000,
            vmsize: 0x1000,
            fileoff: 0,
            filesize: 0x1000,
            maxprot: 7,
            initprot: 5,
            nsects: 0,
            flags: 0,
        });
        info.segments.push(Segment {
            segname: SmolStr::new("__DATA"),
            vmaddr: 0x2000,
            vmsize: 0x1000,
            fileoff: 0x1000,
            filesize: 0x1000,
            maxprot: 7,
            initprot: 3,
            nsects: 0,
            flags: 0,
        });

        assert!(info.segment("__TEXT").is_some());
        assert!(info.segment("__DATA").is_some());
        assert!(info.segment("__LINKEDIT").is_none());
        assert!(info.text_segment().is_some());
        assert!(info.data_segment().is_some());
        assert!(info.linkedit_segment().is_none());
    }

    #[test]
    fn test_section_lookup() {
        let mut info = MachoInfo::default();
        info.sections.push(Section {
            sectname: SmolStr::new("__text"),
            segname: SmolStr::new("__TEXT"),
            addr: 0x1000,
            size: 0x500,
            offset: 0,
            align: 4,
            reloff: 0,
            nreloc: 0,
            flags: 0,
        });

        assert!(info.section("__TEXT", "__text").is_some());
        assert!(info.section("__TEXT", "__data").is_none());
        assert!(info.section("__DATA", "__text").is_none());
    }

    #[test]
    fn test_library_check() {
        let mut info = MachoInfo::default();
        info.libraries.push(Library {
            name: SmolStr::new("/usr/lib/libSystem.B.dylib"),
            timestamp: 0,
            current_version: 0,
            compatibility_version: 0,
        });
        info.libraries.push(Library {
            name: SmolStr::new("/usr/lib/libobjc.A.dylib"),
            timestamp: 0,
            current_version: 0,
            compatibility_version: 0,
        });

        assert!(info.imports_library("libSystem"));
        assert!(info.imports_library("libobjc"));
        assert!(!info.imports_library("libfoo"));
    }

    #[test]
    fn test_symbol_check() {
        let mut info = MachoInfo::default();
        info.symbols.push(Symbol {
            name: SmolStr::new("_main"),
            n_type: 0x0F,
            n_sect: 1,
            n_desc: 0,
            n_value: 0x1000,
        });
        info.symbols.push(Symbol {
            name: SmolStr::new("_printf"),
            n_type: 0x01,
            n_sect: 0,
            n_desc: 0,
            n_value: 0,
        });

        assert!(info.has_symbol("_main"));
        assert!(info.has_symbol("_printf"));
        assert!(!info.has_symbol("_nonexistent"));
    }
}
