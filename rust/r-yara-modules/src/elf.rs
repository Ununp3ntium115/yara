//! ELF Module
//!
//! Provides ELF (Executable and Linkable Format) file analysis compatible with YARA's elf module.
//!
//! # YARA Compatibility
//!
//! This module implements YARA's built-in elf module functions:
//!
//! ```yara
//! import "elf"
//!
//! rule IsELF {
//!     condition:
//!         elf.type == elf.ET_EXEC and
//!         elf.machine == elf.EM_X86_64
//! }
//! ```
//!
//! # Example
//!
//! ```no_run
//! use r_yara_modules::elf::ElfInfo;
//!
//! let data = std::fs::read("sample").unwrap();
//! if let Some(elf) = ElfInfo::parse(&data) {
//!     println!("Type: {}", elf.elf_type());
//!     println!("Machine: {}", elf.machine());
//!     println!("Entry point: 0x{:x}", elf.entry_point());
//! }
//! ```

use goblin::elf::Elf;
use smol_str::SmolStr;

/// ELF type constants
pub mod elf_type {
    pub const ET_NONE: u16 = 0;
    pub const ET_REL: u16 = 1;
    pub const ET_EXEC: u16 = 2;
    pub const ET_DYN: u16 = 3;
    pub const ET_CORE: u16 = 4;
}

/// ELF machine constants
pub mod machine {
    pub const EM_NONE: u16 = 0;
    pub const EM_M32: u16 = 1;
    pub const EM_SPARC: u16 = 2;
    pub const EM_386: u16 = 3;
    pub const EM_68K: u16 = 4;
    pub const EM_88K: u16 = 5;
    pub const EM_860: u16 = 7;
    pub const EM_MIPS: u16 = 8;
    pub const EM_S370: u16 = 9;
    pub const EM_MIPS_RS3_LE: u16 = 10;
    pub const EM_PARISC: u16 = 15;
    pub const EM_VPP500: u16 = 17;
    pub const EM_SPARC32PLUS: u16 = 18;
    pub const EM_960: u16 = 19;
    pub const EM_PPC: u16 = 20;
    pub const EM_PPC64: u16 = 21;
    pub const EM_S390: u16 = 22;
    pub const EM_V800: u16 = 36;
    pub const EM_FR20: u16 = 37;
    pub const EM_RH32: u16 = 38;
    pub const EM_RCE: u16 = 39;
    pub const EM_ARM: u16 = 40;
    pub const EM_ALPHA: u16 = 41;
    pub const EM_SH: u16 = 42;
    pub const EM_SPARCV9: u16 = 43;
    pub const EM_TRICORE: u16 = 44;
    pub const EM_ARC: u16 = 45;
    pub const EM_H8_300: u16 = 46;
    pub const EM_H8_300H: u16 = 47;
    pub const EM_H8S: u16 = 48;
    pub const EM_H8_500: u16 = 49;
    pub const EM_IA_64: u16 = 50;
    pub const EM_MIPS_X: u16 = 51;
    pub const EM_COLDFIRE: u16 = 52;
    pub const EM_68HC12: u16 = 53;
    pub const EM_MMA: u16 = 54;
    pub const EM_PCP: u16 = 55;
    pub const EM_NCPU: u16 = 56;
    pub const EM_NDR1: u16 = 57;
    pub const EM_STARCORE: u16 = 58;
    pub const EM_ME16: u16 = 59;
    pub const EM_ST100: u16 = 60;
    pub const EM_TINYJ: u16 = 61;
    pub const EM_X86_64: u16 = 62;
    pub const EM_AARCH64: u16 = 183;
    pub const EM_RISCV: u16 = 243;
}

/// Section header type constants
pub mod sh_type {
    pub const SHT_NULL: u32 = 0;
    pub const SHT_PROGBITS: u32 = 1;
    pub const SHT_SYMTAB: u32 = 2;
    pub const SHT_STRTAB: u32 = 3;
    pub const SHT_RELA: u32 = 4;
    pub const SHT_HASH: u32 = 5;
    pub const SHT_DYNAMIC: u32 = 6;
    pub const SHT_NOTE: u32 = 7;
    pub const SHT_NOBITS: u32 = 8;
    pub const SHT_REL: u32 = 9;
    pub const SHT_SHLIB: u32 = 10;
    pub const SHT_DYNSYM: u32 = 11;
    pub const SHT_INIT_ARRAY: u32 = 14;
    pub const SHT_FINI_ARRAY: u32 = 15;
    pub const SHT_PREINIT_ARRAY: u32 = 16;
    pub const SHT_GROUP: u32 = 17;
    pub const SHT_SYMTAB_SHNDX: u32 = 18;
}

/// Section header flags
pub mod sh_flags {
    pub const SHF_WRITE: u64 = 0x1;
    pub const SHF_ALLOC: u64 = 0x2;
    pub const SHF_EXECINSTR: u64 = 0x4;
    pub const SHF_MERGE: u64 = 0x10;
    pub const SHF_STRINGS: u64 = 0x20;
    pub const SHF_INFO_LINK: u64 = 0x40;
    pub const SHF_LINK_ORDER: u64 = 0x80;
    pub const SHF_OS_NONCONFORMING: u64 = 0x100;
    pub const SHF_GROUP: u64 = 0x200;
    pub const SHF_TLS: u64 = 0x400;
}

/// Program header type constants
pub mod pt_type {
    pub const PT_NULL: u32 = 0;
    pub const PT_LOAD: u32 = 1;
    pub const PT_DYNAMIC: u32 = 2;
    pub const PT_INTERP: u32 = 3;
    pub const PT_NOTE: u32 = 4;
    pub const PT_SHLIB: u32 = 5;
    pub const PT_PHDR: u32 = 6;
    pub const PT_TLS: u32 = 7;
    pub const PT_GNU_EH_FRAME: u32 = 0x6474e550;
    pub const PT_GNU_STACK: u32 = 0x6474e551;
    pub const PT_GNU_RELRO: u32 = 0x6474e552;
}

/// Program header flags
pub mod pf_flags {
    pub const PF_X: u32 = 0x1;
    pub const PF_W: u32 = 0x2;
    pub const PF_R: u32 = 0x4;
}

/// Information about an ELF section
#[derive(Debug, Clone)]
pub struct Section {
    /// Section name
    pub name: SmolStr,
    /// Section type
    pub sh_type: u32,
    /// Section flags
    pub flags: u64,
    /// Virtual address
    pub address: u64,
    /// File offset
    pub offset: u64,
    /// Section size
    pub size: u64,
}

/// Information about an ELF segment (program header)
#[derive(Debug, Clone)]
pub struct Segment {
    /// Segment type
    pub p_type: u32,
    /// Segment flags
    pub flags: u32,
    /// File offset
    pub offset: u64,
    /// Virtual address
    pub virtual_address: u64,
    /// Physical address
    pub physical_address: u64,
    /// File size
    pub file_size: u64,
    /// Memory size
    pub memory_size: u64,
    /// Alignment
    pub alignment: u64,
}

/// Symbol information
#[derive(Debug, Clone)]
pub struct Symbol {
    /// Symbol name
    pub name: SmolStr,
    /// Symbol value
    pub value: u64,
    /// Symbol size
    pub size: u64,
    /// Symbol type
    pub sym_type: u8,
    /// Symbol binding
    pub bind: u8,
    /// Section index
    pub section_index: u16,
}

/// Dynamic entry
#[derive(Debug, Clone)]
pub struct Dynamic {
    /// Tag
    pub tag: u64,
    /// Value
    pub val: u64,
}

/// Parsed ELF information
pub struct ElfInfo<'a> {
    #[allow(dead_code)]
    data: &'a [u8],
    elf: Elf<'a>,
}

impl<'a> ElfInfo<'a> {
    /// Parse ELF data
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        let elf = Elf::parse(data).ok()?;
        Some(Self { data, elf })
    }

    /// Get ELF type (ET_EXEC, ET_DYN, etc.)
    pub fn elf_type(&self) -> u16 {
        self.elf.header.e_type
    }

    /// Get machine type
    pub fn machine(&self) -> u16 {
        self.elf.header.e_machine
    }

    /// Get ELF version
    pub fn version(&self) -> u32 {
        self.elf.header.e_version
    }

    /// Get entry point
    pub fn entry_point(&self) -> u64 {
        self.elf.header.e_entry
    }

    /// Check if this is a 32-bit ELF
    pub fn is_32bit(&self) -> bool {
        !self.elf.is_64
    }

    /// Check if this is a 64-bit ELF
    pub fn is_64bit(&self) -> bool {
        self.elf.is_64
    }

    /// Check if this is little endian
    pub fn is_little_endian(&self) -> bool {
        self.elf.little_endian
    }

    /// Check if this is big endian
    pub fn is_big_endian(&self) -> bool {
        !self.elf.little_endian
    }

    /// Get program header offset
    pub fn ph_offset(&self) -> u64 {
        self.elf.header.e_phoff
    }

    /// Get section header offset
    pub fn sh_offset(&self) -> u64 {
        self.elf.header.e_shoff
    }

    /// Get number of program headers
    pub fn number_of_segments(&self) -> usize {
        self.elf.program_headers.len()
    }

    /// Get number of section headers
    pub fn number_of_sections(&self) -> usize {
        self.elf.section_headers.len()
    }

    /// Get section by index
    pub fn section(&self, index: usize) -> Option<Section> {
        self.elf.section_headers.get(index).map(|sh| {
            let name = self
                .elf
                .shdr_strtab
                .get_at(sh.sh_name)
                .unwrap_or("");
            Section {
                name: SmolStr::new(name),
                sh_type: sh.sh_type,
                flags: sh.sh_flags,
                address: sh.sh_addr,
                offset: sh.sh_offset,
                size: sh.sh_size,
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

    /// Get segment by index
    pub fn segment(&self, index: usize) -> Option<Segment> {
        self.elf.program_headers.get(index).map(|ph| Segment {
            p_type: ph.p_type,
            flags: ph.p_flags,
            offset: ph.p_offset,
            virtual_address: ph.p_vaddr,
            physical_address: ph.p_paddr,
            file_size: ph.p_filesz,
            memory_size: ph.p_memsz,
            alignment: ph.p_align,
        })
    }

    /// Get all segments
    pub fn segments(&self) -> Vec<Segment> {
        (0..self.number_of_segments())
            .filter_map(|i| self.segment(i))
            .collect()
    }

    /// Get ELF flags
    pub fn flags(&self) -> u32 {
        self.elf.header.e_flags
    }

    /// Get interpreter path
    pub fn interpreter(&self) -> Option<&str> {
        self.elf.interpreter
    }

    /// Get dynamic linker libraries
    pub fn libraries(&self) -> Vec<&str> {
        self.elf.libraries.clone()
    }

    /// Get number of dynamic symbols
    pub fn number_of_dynsyms(&self) -> usize {
        self.elf.dynsyms.len()
    }

    /// Get dynamic symbol by index
    pub fn dynsym(&self, index: usize) -> Option<Symbol> {
        self.elf.dynsyms.get(index).map(|sym| {
            let name = self
                .elf
                .dynstrtab
                .get_at(sym.st_name)
                .unwrap_or("");
            Symbol {
                name: SmolStr::new(name),
                value: sym.st_value,
                size: sym.st_size,
                sym_type: sym.st_type(),
                bind: sym.st_bind(),
                section_index: sym.st_shndx as u16,
            }
        })
    }

    /// Get all dynamic symbols
    pub fn dynsyms(&self) -> Vec<Symbol> {
        (0..self.number_of_dynsyms())
            .filter_map(|i| self.dynsym(i))
            .collect()
    }

    /// Get number of symbols
    pub fn number_of_syms(&self) -> usize {
        self.elf.syms.len()
    }

    /// Get symbol by index
    pub fn sym(&self, index: usize) -> Option<Symbol> {
        self.elf.syms.get(index).map(|sym| {
            let name = self
                .elf
                .strtab
                .get_at(sym.st_name)
                .unwrap_or("");
            Symbol {
                name: SmolStr::new(name),
                value: sym.st_value,
                size: sym.st_size,
                sym_type: sym.st_type(),
                bind: sym.st_bind(),
                section_index: sym.st_shndx as u16,
            }
        })
    }

    /// Get all symbols
    pub fn syms(&self) -> Vec<Symbol> {
        (0..self.number_of_syms())
            .filter_map(|i| self.sym(i))
            .collect()
    }

    /// Check if a symbol exists
    pub fn has_symbol(&self, name: &str) -> bool {
        self.syms().iter().any(|s| s.name.as_str() == name)
            || self.dynsyms().iter().any(|s| s.name.as_str() == name)
    }

    /// Check if the binary imports a specific library
    pub fn imports_library(&self, name: &str) -> bool {
        let name_lower = name.to_lowercase();
        self.libraries()
            .iter()
            .any(|lib| lib.to_lowercase().contains(&name_lower))
    }

    /// Get dynamic entries
    pub fn dynamic(&self) -> Vec<Dynamic> {
        self.elf
            .dynamic
            .as_ref()
            .map(|d| {
                d.dyns
                    .iter()
                    .map(|dyn_| Dynamic {
                        tag: dyn_.d_tag,
                        val: dyn_.d_val,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Check if binary has RELRO
    pub fn has_relro(&self) -> bool {
        self.segments()
            .iter()
            .any(|s| s.p_type == pt_type::PT_GNU_RELRO)
    }

    /// Check if stack is executable
    pub fn has_executable_stack(&self) -> bool {
        self.segments()
            .iter()
            .filter(|s| s.p_type == pt_type::PT_GNU_STACK)
            .any(|s| s.flags & pf_flags::PF_X != 0)
    }

    /// Check if binary is PIE (Position Independent Executable)
    pub fn is_pie(&self) -> bool {
        self.elf_type() == elf_type::ET_DYN
    }
}

/// Check if data is an ELF file
pub fn is_elf(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    // Check for ELF magic number
    data[0] == 0x7f && data[1] == b'E' && data[2] == b'L' && data[3] == b'F'
}

/// Get ELF type
pub fn get_type(data: &[u8]) -> u16 {
    ElfInfo::parse(data).map(|e| e.elf_type()).unwrap_or(0)
}

/// Get machine type
pub fn get_machine(data: &[u8]) -> u16 {
    ElfInfo::parse(data).map(|e| e.machine()).unwrap_or(0)
}

/// Get entry point
pub fn get_entry_point(data: &[u8]) -> u64 {
    ElfInfo::parse(data).map(|e| e.entry_point()).unwrap_or(0)
}

/// Get number of sections
pub fn get_number_of_sections(data: &[u8]) -> usize {
    ElfInfo::parse(data)
        .map(|e| e.number_of_sections())
        .unwrap_or(0)
}

/// Get number of segments
pub fn get_number_of_segments(data: &[u8]) -> usize {
    ElfInfo::parse(data)
        .map(|e| e.number_of_segments())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal valid ELF64 file
    const MINIMAL_ELF64: &[u8] = &[
        // ELF Header (64 bytes)
        0x7f, 0x45, 0x4c, 0x46, // e_ident[EI_MAG0..EI_MAG3] = "\x7fELF"
        0x02, // e_ident[EI_CLASS] = ELFCLASS64
        0x01, // e_ident[EI_DATA] = ELFDATA2LSB
        0x01, // e_ident[EI_VERSION] = EV_CURRENT
        0x00, // e_ident[EI_OSABI] = ELFOSABI_NONE
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_ident padding
        0x02, 0x00, // e_type = ET_EXEC
        0x3e, 0x00, // e_machine = EM_X86_64
        0x01, 0x00, 0x00, 0x00, // e_version = EV_CURRENT
        0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // e_entry = 0x401000
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_phoff = 64
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_shoff = 0 (no section headers)
        0x00, 0x00, 0x00, 0x00, // e_flags = 0
        0x40, 0x00, // e_ehsize = 64
        0x38, 0x00, // e_phentsize = 56
        0x01, 0x00, // e_phnum = 1
        0x40, 0x00, // e_shentsize = 64
        0x00, 0x00, // e_shnum = 0
        0x00, 0x00, // e_shstrndx = 0
        // Program Header (56 bytes)
        0x01, 0x00, 0x00, 0x00, // p_type = PT_LOAD
        0x05, 0x00, 0x00, 0x00, // p_flags = PF_R | PF_X
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_offset = 0
        0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // p_vaddr = 0x400000
        0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // p_paddr = 0x400000
        0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_filesz = 120
        0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_memsz = 120
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_align = 0x1000
    ];

    // Minimal valid ELF32 file
    const MINIMAL_ELF32: &[u8] = &[
        // ELF Header (52 bytes)
        0x7f, 0x45, 0x4c, 0x46, // e_ident[EI_MAG0..EI_MAG3] = "\x7fELF"
        0x01, // e_ident[EI_CLASS] = ELFCLASS32
        0x01, // e_ident[EI_DATA] = ELFDATA2LSB
        0x01, // e_ident[EI_VERSION] = EV_CURRENT
        0x00, // e_ident[EI_OSABI] = ELFOSABI_NONE
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_ident padding
        0x02, 0x00, // e_type = ET_EXEC
        0x03, 0x00, // e_machine = EM_386
        0x01, 0x00, 0x00, 0x00, // e_version = EV_CURRENT
        0x00, 0x80, 0x04, 0x08, // e_entry = 0x08048000
        0x34, 0x00, 0x00, 0x00, // e_phoff = 52
        0x00, 0x00, 0x00, 0x00, // e_shoff = 0
        0x00, 0x00, 0x00, 0x00, // e_flags = 0
        0x34, 0x00, // e_ehsize = 52
        0x20, 0x00, // e_phentsize = 32
        0x01, 0x00, // e_phnum = 1
        0x28, 0x00, // e_shentsize = 40
        0x00, 0x00, // e_shnum = 0
        0x00, 0x00, // e_shstrndx = 0
        // Program Header (32 bytes)
        0x01, 0x00, 0x00, 0x00, // p_type = PT_LOAD
        0x00, 0x00, 0x00, 0x00, // p_offset = 0
        0x00, 0x80, 0x04, 0x08, // p_vaddr = 0x08048000
        0x00, 0x80, 0x04, 0x08, // p_paddr = 0x08048000
        0x54, 0x00, 0x00, 0x00, // p_filesz = 84
        0x54, 0x00, 0x00, 0x00, // p_memsz = 84
        0x05, 0x00, 0x00, 0x00, // p_flags = PF_R | PF_X
        0x00, 0x10, 0x00, 0x00, // p_align = 0x1000
    ];

    #[test]
    fn test_is_elf() {
        assert!(is_elf(MINIMAL_ELF64));
        assert!(is_elf(MINIMAL_ELF32));
        assert!(!is_elf(b"not an ELF file"));
        assert!(!is_elf(b"\x7fEL")); // Too short
        assert!(!is_elf(b""));
    }

    #[test]
    fn test_parse_elf64() {
        let elf = ElfInfo::parse(MINIMAL_ELF64).unwrap();
        assert!(elf.is_64bit());
        assert!(!elf.is_32bit());
        assert!(elf.is_little_endian());
        assert_eq!(elf.elf_type(), elf_type::ET_EXEC);
        assert_eq!(elf.machine(), machine::EM_X86_64);
    }

    #[test]
    fn test_parse_elf32() {
        let elf = ElfInfo::parse(MINIMAL_ELF32).unwrap();
        assert!(elf.is_32bit());
        assert!(!elf.is_64bit());
        assert_eq!(elf.elf_type(), elf_type::ET_EXEC);
        assert_eq!(elf.machine(), machine::EM_386);
    }

    #[test]
    fn test_entry_point() {
        let elf64 = ElfInfo::parse(MINIMAL_ELF64).unwrap();
        assert_eq!(elf64.entry_point(), 0x401000);

        let elf32 = ElfInfo::parse(MINIMAL_ELF32).unwrap();
        assert_eq!(elf32.entry_point(), 0x08048000);
    }

    #[test]
    fn test_segments() {
        let elf = ElfInfo::parse(MINIMAL_ELF64).unwrap();
        assert_eq!(elf.number_of_segments(), 1);

        let segment = elf.segment(0).unwrap();
        assert_eq!(segment.p_type, pt_type::PT_LOAD);
        assert_eq!(segment.flags, pf_flags::PF_R | pf_flags::PF_X);
    }

    #[test]
    fn test_non_elf_data() {
        assert!(!is_elf(b"MZ")); // PE file
        assert!(!is_elf(b"\x00\x00\x00\x00")); // Wrong magic
        assert_eq!(get_type(b"not elf"), 0);
    }

    #[test]
    fn test_convenience_functions() {
        assert_eq!(get_type(MINIMAL_ELF64), elf_type::ET_EXEC);
        assert_eq!(get_machine(MINIMAL_ELF64), machine::EM_X86_64);
        assert_eq!(get_entry_point(MINIMAL_ELF64), 0x401000);
        assert_eq!(get_number_of_segments(MINIMAL_ELF64), 1);
    }
}
