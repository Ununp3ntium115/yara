# R-YARA Module Implementation Pseudocode

**Purpose:** Detailed pseudocode for implementing YARA-compatible modules in R-YARA.

---

## PE Module Implementation

### Data Structures

```pseudocode
// PE file format structures (Windows Portable Executable)

STRUCT DosHeader:
    e_magic: u16           // "MZ" = 0x5A4D
    e_cblp: u16
    e_cp: u16
    e_crlc: u16
    e_cparhdr: u16
    e_minalloc: u16
    e_maxalloc: u16
    e_ss: u16
    e_sp: u16
    e_csum: u16
    e_ip: u16
    e_cs: u16
    e_lfarlc: u16
    e_ovno: u16
    e_res: [u16; 4]
    e_oemid: u16
    e_oeminfo: u16
    e_res2: [u16; 10]
    e_lfanew: i32          // Offset to PE header

STRUCT PeSignature:
    signature: u32         // "PE\0\0" = 0x00004550

STRUCT CoffHeader:
    machine: u16           // Target architecture
    number_of_sections: u16
    time_date_stamp: u32
    pointer_to_symbol_table: u32
    number_of_symbols: u32
    size_of_optional_header: u16
    characteristics: u16

STRUCT OptionalHeader32:
    magic: u16             // 0x10b = PE32
    major_linker_version: u8
    minor_linker_version: u8
    size_of_code: u32
    size_of_initialized_data: u32
    size_of_uninitialized_data: u32
    address_of_entry_point: u32
    base_of_code: u32
    base_of_data: u32
    image_base: u32
    section_alignment: u32
    file_alignment: u32
    // ... more fields
    number_of_rva_and_sizes: u32
    data_directory: [DataDirectory; 16]

STRUCT OptionalHeader64:
    magic: u16             // 0x20b = PE32+
    // Similar to 32-bit but with 64-bit fields
    image_base: u64
    // ...

STRUCT DataDirectory:
    virtual_address: u32
    size: u32

STRUCT SectionHeader:
    name: [u8; 8]
    virtual_size: u32
    virtual_address: u32
    size_of_raw_data: u32
    pointer_to_raw_data: u32
    pointer_to_relocations: u32
    pointer_to_linenumbers: u32
    number_of_relocations: u16
    number_of_linenumbers: u16
    characteristics: u32

STRUCT ImportDescriptor:
    original_first_thunk: u32  // RVA to INT
    time_date_stamp: u32
    forwarder_chain: u32
    name: u32                  // RVA to DLL name
    first_thunk: u32           // RVA to IAT

STRUCT ExportDirectory:
    characteristics: u32
    time_date_stamp: u32
    major_version: u16
    minor_version: u16
    name: u32                  // RVA to DLL name
    base: u32
    number_of_functions: u32
    number_of_names: u32
    address_of_functions: u32  // RVA to function addresses
    address_of_names: u32      // RVA to name pointers
    address_of_name_ordinals: u32
```

### PE Parsing Implementation

```pseudocode
STRUCT PeParser<'data>:
    data: &'data [u8]
    dos_header: Option<&'data DosHeader>
    pe_offset: usize
    coff_header: Option<&'data CoffHeader>
    optional_header: Option<OptionalHeaderVariant<'data>>
    sections: Vec<&'data SectionHeader>
    is_64bit: bool

ENUM OptionalHeaderVariant<'data>:
    Pe32(&'data OptionalHeader32)
    Pe64(&'data OptionalHeader64)

FUNCTION parse_pe<'a>(data: &'a [u8]) -> Result<PeParser<'a>>:
    // Validate minimum size
    IF data.len() < 64:
        RETURN Err(TooSmall)

    // Parse DOS header
    dos = cast::<DosHeader>(&data[0..64])

    IF dos.e_magic != 0x5A4D:
        RETURN Err(InvalidDosSignature)

    pe_offset = dos.e_lfanew as usize

    IF pe_offset + 4 > data.len():
        RETURN Err(InvalidPeOffset)

    // Check PE signature
    pe_sig = read_u32_le(&data[pe_offset..])
    IF pe_sig != 0x00004550:  // "PE\0\0"
        RETURN Err(InvalidPeSignature)

    // Parse COFF header
    coff_offset = pe_offset + 4
    coff = cast::<CoffHeader>(&data[coff_offset..])

    // Parse optional header
    opt_offset = coff_offset + 20
    opt_magic = read_u16_le(&data[opt_offset..])

    optional_header = MATCH opt_magic:
        0x10b => {
            opt32 = cast::<OptionalHeader32>(&data[opt_offset..])
            OptionalHeaderVariant::Pe32(opt32)
        }
        0x20b => {
            opt64 = cast::<OptionalHeader64>(&data[opt_offset..])
            OptionalHeaderVariant::Pe64(opt64)
        }
        _ => RETURN Err(InvalidOptionalHeader)

    is_64bit = opt_magic == 0x20b

    // Parse sections
    section_offset = opt_offset + coff.size_of_optional_header as usize
    sections = Vec::new()

    FOR i IN 0..coff.number_of_sections:
        section = cast::<SectionHeader>(
            &data[section_offset + i * 40..]
        )
        sections.push(section)

    RETURN Ok(PeParser {
        data, dos_header: Some(dos), pe_offset, coff_header: Some(coff),
        optional_header: Some(optional_header), sections, is_64bit
    })

// RVA to file offset conversion
FUNCTION rva_to_offset(pe: &PeParser, rva: u32) -> Option<usize>:
    FOR section IN pe.sections:
        section_start = section.virtual_address
        section_end = section_start + section.virtual_size

        IF rva >= section_start AND rva < section_end:
            offset_in_section = rva - section_start
            file_offset = section.pointer_to_raw_data + offset_in_section
            RETURN Some(file_offset as usize)

    RETURN None

// Parse imports
FUNCTION parse_imports(pe: &PeParser) -> Vec<Import>:
    imports = Vec::new()

    // Get import directory from data directories
    import_dir_rva = pe.get_data_directory(1).virtual_address
    import_dir_size = pe.get_data_directory(1).size

    IF import_dir_rva == 0:
        RETURN imports

    import_offset = rva_to_offset(pe, import_dir_rva)?

    // Iterate import descriptors
    offset = import_offset
    WHILE TRUE:
        descriptor = cast::<ImportDescriptor>(&pe.data[offset..])

        // Zero descriptor marks end
        IF descriptor.name == 0:
            BREAK

        // Read DLL name
        name_offset = rva_to_offset(pe, descriptor.name)?
        dll_name = read_null_terminated_string(&pe.data[name_offset..])

        // Read imported functions
        thunk_rva = IF descriptor.original_first_thunk != 0:
            descriptor.original_first_thunk
        ELSE:
            descriptor.first_thunk

        thunk_offset = rva_to_offset(pe, thunk_rva)?
        functions = parse_thunks(pe, thunk_offset)

        imports.push(Import {
            dll_name,
            functions
        })

        offset += size_of::<ImportDescriptor>()

    RETURN imports

// Compute imphash (import hash)
FUNCTION compute_imphash(imports: &[Import]) -> String:
    // Build import string: dll.func,dll.func,...
    parts = Vec::new()

    FOR import IN imports:
        dll = import.dll_name
            .strip_suffix(".dll").unwrap_or(&import.dll_name)
            .to_lowercase()

        FOR func IN import.functions:
            // Remove ordinal prefix if present
            func_name = IF func.starts_with("ord"):
                func.clone()
            ELSE:
                func.to_lowercase()

            parts.push(format!("{}.{}", dll, func_name))

    concat = parts.join(",")

    // MD5 hash
    RETURN md5_hex(&concat)
```

### PE Module API

```pseudocode
STRUCT PeModule:
    // All fields are lazy-loaded
    parsed: Option<PeParser>
    imports_cache: Option<Vec<Import>>
    exports_cache: Option<Vec<Export>>
    sections_cache: Option<Vec<Section>>
    imphash_cache: Option<String>
    rich_header_cache: Option<RichHeader>

IMPL RYaraModule FOR PeModule:
    CONST NAME: &str = "pe"

    FUNCTION declarations() -> Vec<Declaration>:
        RETURN vec![
            // Constants
            Declaration::integer("MACHINE_I386", 0x14c),
            Declaration::integer("MACHINE_AMD64", 0x8664),
            Declaration::integer("MACHINE_ARM", 0x1c0),

            Declaration::integer("SUBSYSTEM_NATIVE", 1),
            Declaration::integer("SUBSYSTEM_WINDOWS_GUI", 2),
            Declaration::integer("SUBSYSTEM_WINDOWS_CUI", 3),

            // Characteristics flags
            Declaration::integer("RELOCS_STRIPPED", 0x0001),
            Declaration::integer("EXECUTABLE_IMAGE", 0x0002),
            Declaration::integer("DLL", 0x2000),

            // Section characteristics
            Declaration::integer("SECTION_CNT_CODE", 0x00000020),
            Declaration::integer("SECTION_MEM_EXECUTE", 0x20000000),
            Declaration::integer("SECTION_MEM_READ", 0x40000000),
            Declaration::integer("SECTION_MEM_WRITE", 0x80000000),

            // Fields
            Declaration::field("machine", Type::Integer),
            Declaration::field("subsystem", Type::Integer),
            Declaration::field("characteristics", Type::Integer),
            Declaration::field("entry_point", Type::Integer),
            Declaration::field("image_base", Type::Integer),
            Declaration::field("number_of_sections", Type::Integer),
            Declaration::field("timestamp", Type::Integer),
            Declaration::field("dll_name", Type::String),

            // Arrays
            Declaration::array("sections", Type::Struct("Section")),
            Declaration::array("imports", Type::Struct("Import")),
            Declaration::array("exports", Type::Struct("Export")),
            Declaration::array("resources", Type::Struct("Resource")),

            // Functions
            Declaration::function("is_pe", vec![], Type::Boolean),
            Declaration::function("is_dll", vec![], Type::Boolean),
            Declaration::function("is_32bit", vec![], Type::Boolean),
            Declaration::function("is_64bit", vec![], Type::Boolean),
            Declaration::function("imphash", vec![], Type::String),
            Declaration::function("section_index", vec![Type::String], Type::Integer),
            Declaration::function("exports", vec![Type::String], Type::Boolean),
            Declaration::function("imports", vec![Type::String, Type::String], Type::Boolean),
            Declaration::function("rich_signature.toolid", vec![Type::Integer], Type::Integer),
        ]

    FUNCTION get_field(&mut self, field: &str) -> Value:
        // Ensure parsed
        self.ensure_parsed()

        MATCH field:
            "machine" => Value::Integer(self.parsed?.coff_header?.machine as i64),
            "subsystem" => Value::Integer(self.get_subsystem() as i64),
            "characteristics" => Value::Integer(self.parsed?.coff_header?.characteristics as i64),
            "entry_point" => Value::Integer(self.get_entry_point() as i64),
            "image_base" => Value::Integer(self.get_image_base() as i64),
            "number_of_sections" => Value::Integer(self.parsed?.sections.len() as i64),
            "timestamp" => Value::Integer(self.parsed?.coff_header?.time_date_stamp as i64),

            "sections" => {
                self.ensure_sections_parsed()
                Value::Array(self.sections_cache.clone())
            }

            "imports" => {
                self.ensure_imports_parsed()
                Value::Array(self.imports_cache.clone())
            }

            _ => Value::Undefined

    FUNCTION call(&mut self, name: &str, args: &[Value]) -> Value:
        MATCH name:
            "is_pe" => Value::Boolean(self.parsed.is_some()),
            "is_dll" => {
                chars = self.parsed?.coff_header?.characteristics
                Value::Boolean((chars & 0x2000) != 0)
            }
            "is_32bit" => Value::Boolean(!self.parsed?.is_64bit),
            "is_64bit" => Value::Boolean(self.parsed?.is_64bit),

            "imphash" => {
                IF self.imphash_cache.is_none():
                    self.ensure_imports_parsed()
                    self.imphash_cache = Some(compute_imphash(&self.imports_cache?))
                Value::String(self.imphash_cache.clone()?)
            }

            "section_index" => {
                name = args[0].as_string()?
                FOR (i, section) IN self.parsed?.sections.iter().enumerate():
                    section_name = read_section_name(section)
                    IF section_name == name:
                        RETURN Value::Integer(i as i64)
                Value::Undefined
            }

            "exports" => {
                export_name = args[0].as_string()?
                self.ensure_exports_parsed()
                FOR export IN &self.exports_cache?:
                    IF export.name == export_name:
                        RETURN Value::Boolean(true)
                Value::Boolean(false)
            }

            "imports" => {
                dll_name = args[0].as_string()?
                func_name = args[1].as_string()?
                self.ensure_imports_parsed()
                FOR import IN &self.imports_cache?:
                    IF import.dll_name.eq_ignore_ascii_case(&dll_name):
                        FOR func IN &import.functions:
                            IF func.eq_ignore_ascii_case(&func_name):
                                RETURN Value::Boolean(true)
                Value::Boolean(false)
            }

            _ => Value::Undefined
```

---

## ELF Module Implementation

```pseudocode
// ELF file format structures (Linux/Unix)

STRUCT ElfIdent:
    magic: [u8; 4]         // "\x7fELF"
    class: u8              // 1 = 32-bit, 2 = 64-bit
    endian: u8             // 1 = little, 2 = big
    version: u8
    osabi: u8
    abiversion: u8
    padding: [u8; 7]

STRUCT ElfHeader32:
    ident: ElfIdent
    type_: u16             // ET_EXEC, ET_DYN, etc.
    machine: u16           // EM_386, EM_X86_64, etc.
    version: u32
    entry: u32
    phoff: u32             // Program header offset
    shoff: u32             // Section header offset
    flags: u32
    ehsize: u16
    phentsize: u16
    phnum: u16
    shentsize: u16
    shnum: u16
    shstrndx: u16

STRUCT ElfHeader64:
    // Same as 32-bit with 64-bit addresses
    entry: u64
    phoff: u64
    shoff: u64
    // ...

STRUCT ElfSection32:
    name: u32              // Offset in string table
    type_: u32
    flags: u32
    addr: u32
    offset: u32
    size: u32
    link: u32
    info: u32
    addralign: u32
    entsize: u32

STRUCT ElfSymbol32:
    name: u32
    value: u32
    size: u32
    info: u8               // Type and binding
    other: u8
    shndx: u16

STRUCT ElfModule:
    parsed: Option<ElfParser>
    symbols_cache: Option<Vec<Symbol>>
    sections_cache: Option<Vec<Section>>
    telfhash_cache: Option<String>

IMPL RYaraModule FOR ElfModule:
    FUNCTION get_field(&mut self, field: &str) -> Value:
        MATCH field:
            "type" => Value::Integer(self.parsed?.header.type_ as i64),
            "machine" => Value::Integer(self.parsed?.header.machine as i64),
            "entry_point" => Value::Integer(self.parsed?.header.entry as i64),
            "number_of_sections" => Value::Integer(self.parsed?.sections.len() as i64),
            "number_of_segments" => Value::Integer(self.parsed?.segments.len() as i64),

            "symtab" => {
                self.ensure_symbols_parsed()
                Value::Array(self.symbols_cache.clone())
            }

            "dynsym" => {
                self.ensure_dynsym_parsed()
                Value::Array(self.dynsym_cache.clone())
            }

            _ => Value::Undefined

    FUNCTION call(&mut self, name: &str, args: &[Value]) -> Value:
        MATCH name:
            "telfhash" => {
                // Trend Micro ELF hash for similarity
                IF self.telfhash_cache.is_none():
                    self.telfhash_cache = Some(compute_telfhash(self.parsed?))
                Value::String(self.telfhash_cache.clone()?)
            }

            "import_md5" => {
                // MD5 of imported symbols
                Value::String(compute_import_md5(self.parsed?))
            }

            _ => Value::Undefined

// Telfhash implementation (TLSH-based ELF similarity hash)
FUNCTION compute_telfhash(elf: &ElfParser) -> String:
    // Extract symbols from .dynsym
    symbols = get_dynamic_symbols(elf)

    // Sort by name
    symbols.sort_by(|a, b| a.name.cmp(&b.name))

    // Concatenate symbol names
    symbol_string = symbols
        .iter()
        .map(|s| s.name.as_str())
        .collect::<Vec<_>>()
        .join(",")

    // Compute TLSH
    RETURN tlsh_hash(&symbol_string)
```

---

## Hash Module Implementation

```pseudocode
STRUCT HashModule:
    data: Option<Bytes>
    filesize: usize

IMPL RYaraModule FOR HashModule:
    CONST NAME: &str = "hash"

    FUNCTION declarations() -> Vec<Declaration>:
        RETURN vec![
            Declaration::function("md5", vec![Type::Integer, Type::Integer], Type::String),
            Declaration::function("sha1", vec![Type::Integer, Type::Integer], Type::String),
            Declaration::function("sha256", vec![Type::Integer, Type::Integer], Type::String),
            Declaration::function("sha512", vec![Type::Integer, Type::Integer], Type::String),
            Declaration::function("checksum32", vec![Type::Integer, Type::Integer], Type::Integer),
            Declaration::function("crc32", vec![Type::Integer, Type::Integer], Type::Integer),
        ]

    FUNCTION call(&mut self, name: &str, args: &[Value]) -> Value:
        offset = args[0].as_integer()? as usize
        length = args[1].as_integer()? as usize

        // Bounds check
        IF offset + length > self.data?.len():
            RETURN Value::Undefined

        slice = &self.data?[offset..offset + length]

        MATCH name:
            "md5" => {
                hash = md5::compute(slice)
                Value::String(hex::encode(hash))
            }

            "sha1" => {
                hash = sha1::Sha1::digest(slice)
                Value::String(hex::encode(hash))
            }

            "sha256" => {
                hash = sha2::Sha256::digest(slice)
                Value::String(hex::encode(hash))
            }

            "sha512" => {
                hash = sha2::Sha512::digest(slice)
                Value::String(hex::encode(hash))
            }

            "checksum32" => {
                sum: u32 = 0
                FOR byte IN slice:
                    sum = sum.wrapping_add(*byte as u32)
                Value::Integer(sum as i64)
            }

            "crc32" => {
                hash = crc32fast::hash(slice)
                Value::Integer(hash as i64)
            }

            _ => Value::Undefined

// SIMD-accelerated hashing for large files
FUNCTION sha256_simd(data: &[u8]) -> [u8; 32]:
    // Use SHA-NI instructions on supported CPUs
    IF cpu_supports_sha_ni():
        RETURN sha256_sha_ni(data)

    // Fall back to software implementation
    RETURN sha256_software(data)

FUNCTION sha256_sha_ni(data: &[u8]) -> [u8; 32]:
    // Intel SHA-NI implementation
    // Process 64 bytes at a time using hardware acceleration

    state = SHA256_INIT_STATE

    FOR chunk IN data.chunks(64):
        // Load message into XMM registers
        msg0 = _mm_loadu_si128(chunk[0..16])
        msg1 = _mm_loadu_si128(chunk[16..32])
        msg2 = _mm_loadu_si128(chunk[32..48])
        msg3 = _mm_loadu_si128(chunk[48..64])

        // 64 rounds of SHA-256 using SHA-NI
        // _mm_sha256rnds2_epu32, _mm_sha256msg1_epu32, etc.
        state = sha256_compress_ni(state, msg0, msg1, msg2, msg3)

    RETURN finalize(state)
```

---

## Math Module Implementation

```pseudocode
STRUCT MathModule:
    data: Option<Bytes>

IMPL RYaraModule FOR MathModule:
    CONST NAME: &str = "math"

    FUNCTION declarations() -> Vec<Declaration>:
        RETURN vec![
            Declaration::function("entropy", vec![Type::Integer, Type::Integer], Type::Float),
            Declaration::function("deviation", vec![Type::Integer, Type::Integer, Type::Float], Type::Float),
            Declaration::function("mean", vec![Type::Integer, Type::Integer], Type::Float),
            Declaration::function("serial_correlation", vec![Type::Integer, Type::Integer], Type::Float),
            Declaration::function("monte_carlo_pi", vec![Type::Integer, Type::Integer], Type::Float),
            Declaration::function("in_range", vec![Type::Float, Type::Float, Type::Float], Type::Boolean),
            Declaration::function("count", vec![Type::Integer, Type::Integer, Type::Integer], Type::Integer),
            Declaration::function("percentage", vec![Type::Integer, Type::Integer, Type::Integer], Type::Float),
            Declaration::function("mode", vec![Type::Integer, Type::Integer], Type::Integer),
            Declaration::function("to_number", vec![Type::Boolean], Type::Integer),
            Declaration::function("abs", vec![Type::Integer], Type::Integer),
            Declaration::function("min", vec![Type::Integer, Type::Integer], Type::Integer),
            Declaration::function("max", vec![Type::Integer, Type::Integer], Type::Integer),
        ]

    FUNCTION call(&mut self, name: &str, args: &[Value]) -> Value:
        MATCH name:
            "entropy" => {
                offset = args[0].as_integer()? as usize
                length = args[1].as_integer()? as usize
                slice = self.get_slice(offset, length)?
                Value::Float(calculate_entropy(slice))
            }

            "mean" => {
                offset = args[0].as_integer()? as usize
                length = args[1].as_integer()? as usize
                slice = self.get_slice(offset, length)?
                sum: f64 = slice.iter().map(|&b| b as f64).sum()
                Value::Float(sum / length as f64)
            }

            "deviation" => {
                offset = args[0].as_integer()? as usize
                length = args[1].as_integer()? as usize
                expected_mean = args[2].as_float()?
                slice = self.get_slice(offset, length)?
                Value::Float(calculate_deviation(slice, expected_mean))
            }

            "serial_correlation" => {
                offset = args[0].as_integer()? as usize
                length = args[1].as_integer()? as usize
                slice = self.get_slice(offset, length)?
                Value::Float(calculate_serial_correlation(slice))
            }

            "count" => {
                byte = args[0].as_integer()? as u8
                offset = args[1].as_integer()? as usize
                length = args[2].as_integer()? as usize
                slice = self.get_slice(offset, length)?
                count = slice.iter().filter(|&&b| b == byte).count()
                Value::Integer(count as i64)
            }

            "mode" => {
                offset = args[0].as_integer()? as usize
                length = args[1].as_integer()? as usize
                slice = self.get_slice(offset, length)?
                Value::Integer(calculate_mode(slice) as i64)
            }

            _ => Value::Undefined

// SIMD-accelerated entropy calculation
FUNCTION calculate_entropy(data: &[u8]) -> f64:
    IF data.is_empty():
        RETURN 0.0

    // Count byte frequencies using SIMD
    frequencies = count_bytes_simd(data)

    // Calculate entropy: -Σ p(x) * log2(p(x))
    length = data.len() as f64
    entropy = 0.0

    FOR count IN frequencies:
        IF count > 0:
            probability = count as f64 / length
            entropy -= probability * probability.log2()

    RETURN entropy

FUNCTION count_bytes_simd(data: &[u8]) -> [u64; 256]:
    counts = [0u64; 256]

    // Process 32 bytes at a time with histogram
    // Use SIMD to parallelize counting

    FOR chunk IN data.chunks(32):
        // Vectorized histogram update
        FOR byte IN chunk:
            counts[*byte as usize] += 1

    RETURN counts

FUNCTION calculate_deviation(data: &[u8], expected: f64) -> f64:
    IF data.is_empty():
        RETURN 0.0

    sum_sq_diff = 0.0
    FOR byte IN data:
        diff = *byte as f64 - expected
        sum_sq_diff += diff * diff

    RETURN (sum_sq_diff / data.len() as f64).sqrt()

FUNCTION calculate_serial_correlation(data: &[u8]) -> f64:
    IF data.len() < 2:
        RETURN 0.0

    n = data.len() as f64

    // Calculate mean
    sum: f64 = data.iter().map(|&b| b as f64).sum()
    mean = sum / n

    // Calculate correlation coefficient
    numerator = 0.0
    denominator = 0.0

    FOR i IN 0..data.len() - 1:
        x = data[i] as f64 - mean
        y = data[i + 1] as f64 - mean
        numerator += x * y
        denominator += x * x

    IF denominator == 0.0:
        RETURN 0.0

    RETURN numerator / denominator
```

---

## Dotnet Module Implementation

```pseudocode
// .NET PE/CLI structures

STRUCT CliHeader:
    cb: u32
    major_runtime_version: u16
    minor_runtime_version: u16
    meta_data: DataDirectory
    flags: u32
    entry_point_token: u32
    resources: DataDirectory
    strong_name_signature: DataDirectory
    code_manager_table: DataDirectory
    vtable_fixups: DataDirectory
    export_address_table_jumps: DataDirectory
    managed_native_header: DataDirectory

STRUCT MetadataHeader:
    signature: u32         // 0x424A5342 = "BSJB"
    major_version: u16
    minor_version: u16
    reserved: u32
    version_length: u32
    version: String
    flags: u16
    streams: u16

STRUCT StreamHeader:
    offset: u32
    size: u32
    name: String           // #~, #Strings, #US, #Blob, #GUID

STRUCT DotnetModule:
    pe: PeParser
    cli_header: Option<CliHeader>
    metadata: Option<MetadataParser>
    types_cache: Option<Vec<TypeDef>>
    resources_cache: Option<Vec<Resource>>

IMPL RYaraModule FOR DotnetModule:
    CONST NAME: &str = "dotnet"

    FUNCTION declarations() -> Vec<Declaration>:
        RETURN vec![
            Declaration::field("version", Type::String),
            Declaration::field("module_name", Type::String),
            Declaration::field("number_of_streams", Type::Integer),
            Declaration::field("number_of_guids", Type::Integer),
            Declaration::field("number_of_resources", Type::Integer),
            Declaration::field("number_of_generic_parameters", Type::Integer),
            Declaration::field("number_of_classes", Type::Integer),
            Declaration::field("number_of_assembly_refs", Type::Integer),
            Declaration::field("number_of_modulerefs", Type::Integer),
            Declaration::field("number_of_user_strings", Type::Integer),
            Declaration::field("typelib", Type::String),

            Declaration::array("streams", Type::Struct("Stream")),
            Declaration::array("guids", Type::String),
            Declaration::array("resources", Type::Struct("Resource")),
            Declaration::array("classes", Type::Struct("Class")),
            Declaration::array("assembly_refs", Type::Struct("AssemblyRef")),
            Declaration::array("user_strings", Type::String),

            Declaration::function("is_dotnet", vec![], Type::Boolean),
            Declaration::function("assembly", Type::Struct("Assembly")),
        ]

    FUNCTION get_field(&mut self, field: &str) -> Value:
        MATCH field:
            "version" => {
                Value::String(self.metadata?.version.clone())
            }

            "module_name" => {
                Value::String(self.get_module_name())
            }

            "number_of_classes" => {
                self.ensure_types_parsed()
                Value::Integer(self.types_cache?.len() as i64)
            }

            "classes" => {
                self.ensure_types_parsed()
                Value::Array(self.types_cache.clone())
            }

            _ => Value::Undefined

// Parse .NET metadata tables
FUNCTION parse_metadata(pe: &PeParser) -> Result<MetadataParser>:
    // Get CLI header from PE data directory
    cli_dir = pe.get_data_directory(14)  // COM_DESCRIPTOR
    IF cli_dir.virtual_address == 0:
        RETURN Err(NotDotnet)

    cli_offset = rva_to_offset(pe, cli_dir.virtual_address)?
    cli_header = cast::<CliHeader>(&pe.data[cli_offset..])

    // Parse metadata
    meta_offset = rva_to_offset(pe, cli_header.meta_data.virtual_address)?
    meta_header = parse_metadata_header(&pe.data[meta_offset..])?

    // Parse streams
    streams = parse_streams(&pe.data[meta_offset..], meta_header)

    // Parse #~ stream (metadata tables)
    tables_stream = streams.get("#~")?
    tables = parse_metadata_tables(tables_stream)

    RETURN Ok(MetadataParser {
        header: meta_header,
        streams,
        tables
    })

// Extract class definitions
FUNCTION get_type_definitions(metadata: &MetadataParser) -> Vec<TypeDef>:
    typedef_table = metadata.tables.get(TableId::TypeDef)?
    types = Vec::new()

    FOR row IN typedef_table:
        type_name = metadata.get_string(row.name)
        namespace = metadata.get_string(row.namespace)

        // Get methods for this type
        methods = get_methods_for_type(metadata, row)

        types.push(TypeDef {
            name: type_name,
            namespace,
            visibility: get_visibility(row.flags),
            is_abstract: (row.flags & 0x80) != 0,
            is_sealed: (row.flags & 0x100) != 0,
            is_interface: (row.flags & 0x20) != 0,
            methods,
        })

    RETURN types
```

---

## Module Registration and Loading

```pseudocode
// R-YARA module registry

STRUCT ModuleRegistry:
    modules: HashMap<String, Box<dyn RYaraModule>>

IMPL ModuleRegistry:
    FUNCTION new() -> Self:
        registry = ModuleRegistry { modules: HashMap::new() }

        // Register built-in modules
        registry.register(Box::new(PeModule::new()))
        registry.register(Box::new(ElfModule::new()))
        registry.register(Box::new(DotnetModule::new()))
        registry.register(Box::new(HashModule::new()))
        registry.register(Box::new(MathModule::new()))
        registry.register(Box::new(TimeModule::new()))
        registry.register(Box::new(ConsoleModule::new()))

        RETURN registry

    FUNCTION register(&mut self, module: Box<dyn RYaraModule>):
        self.modules.insert(module.name().to_string(), module)

    FUNCTION load(&mut self, name: &str, data: &[u8]) -> Result<()>:
        module = self.modules.get_mut(name)?
        module.initialize(data)

    FUNCTION get(&self, name: &str) -> Option<&dyn RYaraModule>:
        self.modules.get(name).map(|m| m.as_ref())

// Parallel module initialization
FUNCTION initialize_modules_parallel(
    registry: &mut ModuleRegistry,
    data: &[u8]
) -> HashMap<String, ModuleData>:
    // Determine applicable modules
    applicable = registry.modules
        .par_iter()
        .filter(|(_, m)| m.can_handle(data))
        .collect::<Vec<_>>()

    // Initialize in parallel
    results = applicable
        .par_iter()
        .map(|(name, module)| {
            (name.clone(), module.initialize(data))
        })
        .collect()

    RETURN results
```

---

## Usage Example: YARA Rule with Modules

```yara
import "pe"
import "hash"
import "math"
import "dotnet"

rule Suspicious_Packed_Executable {
    meta:
        description = "Detects suspicious packed executable"
        author = "R-YARA"

    strings:
        $mz = { 4D 5A }
        $upx = "UPX!"

    condition:
        // PE checks
        pe.is_pe() and
        pe.number_of_sections >= 3 and
        pe.entry_point > pe.sections[0].virtual_address and

        // High entropy indicates packing
        math.entropy(0, filesize) > 7.0 and

        // Import hash matching known packers
        pe.imphash() == "d3b06d2e6c7c1a2c2b3d4e5f6a7b8c9d" or

        // .NET specific checks
        (dotnet.is_dotnet() and
         dotnet.number_of_resources > 10) or

        // Hash of specific section
        hash.sha256(pe.sections[0].raw_data_offset,
                    pe.sections[0].raw_data_size)
            == "abcd1234..." or

        // String patterns
        $mz at 0 and $upx
}
```

---

## Performance Comparison

```
Module Operation           | YARA (C)  | YARA-X    | R-YARA (Goal)
---------------------------|-----------|-----------|---------------
PE header parse            | 0.5ms     | 0.3ms     | 0.1ms (lazy)
Import table parse         | 2.0ms     | 1.5ms     | 0.3ms (on-demand)
Imphash compute            | 1.0ms     | 0.8ms     | 0.2ms (cached+SIMD)
ELF symbol parse           | 1.5ms     | 1.0ms     | 0.3ms (zero-copy)
SHA256 (1MB file)          | 5.0ms     | 4.0ms     | 1.5ms (SHA-NI)
Entropy (1MB file)         | 8.0ms     | 6.0ms     | 2.0ms (SIMD count)
.NET metadata parse        | 10.0ms    | 8.0ms     | 3.0ms (lazy)
```

Key optimizations:
1. **Lazy parsing**: Only parse what's needed
2. **Zero-copy**: Reference data instead of copying
3. **SIMD acceleration**: For hashing and counting
4. **Caching**: Computed values are cached
5. **Parallel loading**: Multiple modules load simultaneously
