//! DEX Module
//!
//! Provides Android DEX (Dalvik Executable) file analysis compatible with YARA's dex module.
//!
//! # YARA Compatibility
//!
//! This module is compatible with YARA's built-in dex module:
//!
//! ```yara
//! import "dex"
//!
//! rule DexExample {
//!     condition:
//!         dex.header.magic == "dex\n" and
//!         dex.number_of_classes > 10
//! }
//! ```

use smol_str::SmolStr;

// ============================================================================
// DEX Constants
// ============================================================================

/// DEX Magic bytes
pub const DEX_MAGIC: &[u8] = b"dex\n";

/// Standard DEX versions
pub mod version {
    pub const DEX_035: &str = "035";
    pub const DEX_036: &str = "036";
    pub const DEX_037: &str = "037";
    pub const DEX_038: &str = "038";
    pub const DEX_039: &str = "039";
}

/// Access flags for classes, methods, and fields
pub mod access_flags {
    pub const ACC_PUBLIC: u32 = 0x0001;
    pub const ACC_PRIVATE: u32 = 0x0002;
    pub const ACC_PROTECTED: u32 = 0x0004;
    pub const ACC_STATIC: u32 = 0x0008;
    pub const ACC_FINAL: u32 = 0x0010;
    pub const ACC_SYNCHRONIZED: u32 = 0x0020;
    pub const ACC_VOLATILE: u32 = 0x0040;
    pub const ACC_BRIDGE: u32 = 0x0040;
    pub const ACC_TRANSIENT: u32 = 0x0080;
    pub const ACC_VARARGS: u32 = 0x0080;
    pub const ACC_NATIVE: u32 = 0x0100;
    pub const ACC_INTERFACE: u32 = 0x0200;
    pub const ACC_ABSTRACT: u32 = 0x0400;
    pub const ACC_STRICT: u32 = 0x0800;
    pub const ACC_SYNTHETIC: u32 = 0x1000;
    pub const ACC_ANNOTATION: u32 = 0x2000;
    pub const ACC_ENUM: u32 = 0x4000;
    pub const ACC_CONSTRUCTOR: u32 = 0x10000;
    pub const ACC_DECLARED_SYNCHRONIZED: u32 = 0x20000;
}

// ============================================================================
// Data Structures
// ============================================================================

/// DEX header information
#[derive(Debug, Clone)]
pub struct DexHeader {
    pub magic: [u8; 8],
    pub checksum: u32,
    pub signature: [u8; 20],
    pub file_size: u32,
    pub header_size: u32,
    pub endian_tag: u32,
    pub link_size: u32,
    pub link_offset: u32,
    pub map_offset: u32,
    pub string_ids_size: u32,
    pub string_ids_offset: u32,
    pub type_ids_size: u32,
    pub type_ids_offset: u32,
    pub proto_ids_size: u32,
    pub proto_ids_offset: u32,
    pub field_ids_size: u32,
    pub field_ids_offset: u32,
    pub method_ids_size: u32,
    pub method_ids_offset: u32,
    pub class_defs_size: u32,
    pub class_defs_offset: u32,
    pub data_size: u32,
    pub data_offset: u32,
}

impl Default for DexHeader {
    fn default() -> Self {
        Self {
            magic: [0; 8],
            checksum: 0,
            signature: [0; 20],
            file_size: 0,
            header_size: 0,
            endian_tag: 0,
            link_size: 0,
            link_offset: 0,
            map_offset: 0,
            string_ids_size: 0,
            string_ids_offset: 0,
            type_ids_size: 0,
            type_ids_offset: 0,
            proto_ids_size: 0,
            proto_ids_offset: 0,
            field_ids_size: 0,
            field_ids_offset: 0,
            method_ids_size: 0,
            method_ids_offset: 0,
            class_defs_size: 0,
            class_defs_offset: 0,
            data_size: 0,
            data_offset: 0,
        }
    }
}

/// String entry in DEX file
#[derive(Debug, Clone)]
pub struct DexString {
    pub offset: u32,
    pub value: SmolStr,
}

/// Type entry in DEX file
#[derive(Debug, Clone)]
pub struct DexType {
    pub descriptor_idx: u32,
    pub descriptor: SmolStr,
}

/// Class definition
#[derive(Debug, Clone)]
pub struct DexClass {
    pub class_name: SmolStr,
    pub access_flags: u32,
    pub superclass: Option<SmolStr>,
    pub interfaces: Vec<SmolStr>,
    pub source_file: Option<SmolStr>,
    pub methods: Vec<DexMethod>,
    pub fields: Vec<DexField>,
}

/// Method definition
#[derive(Debug, Clone)]
pub struct DexMethod {
    pub name: SmolStr,
    pub class_name: SmolStr,
    pub prototype: SmolStr,
    pub access_flags: u32,
}

/// Field definition
#[derive(Debug, Clone)]
pub struct DexField {
    pub name: SmolStr,
    pub class_name: SmolStr,
    pub type_name: SmolStr,
    pub access_flags: u32,
}

/// Parsed DEX file information
#[derive(Debug, Clone)]
pub struct DexInfo {
    pub is_dex: bool,
    pub version: SmolStr,
    pub header: DexHeader,
    pub strings: Vec<DexString>,
    pub types: Vec<DexType>,
    pub classes: Vec<DexClass>,
}

impl Default for DexInfo {
    fn default() -> Self {
        Self {
            is_dex: false,
            version: SmolStr::new(""),
            header: DexHeader::default(),
            strings: Vec::new(),
            types: Vec::new(),
            classes: Vec::new(),
        }
    }
}

impl DexInfo {
    /// Parse a DEX file from bytes
    ///
    /// This performs header-level parsing to extract basic DEX information.
    /// For full class/method parsing, the dex crate can be used directly.
    pub fn parse(data: &[u8]) -> Self {
        // Check magic first
        if !is_dex(data) {
            return Self::default();
        }

        Self {
            is_dex: true,
            version: Self::extract_version(data),
            header: Self::extract_header(data),
            strings: Self::extract_strings(data),
            types: Vec::new(),
            classes: Vec::new(),
        }
    }

    fn extract_strings(data: &[u8]) -> Vec<DexString> {
        let mut strings = Vec::new();

        if data.len() < 112 {
            return strings;
        }

        let string_ids_size =
            u32::from_le_bytes([data[56], data[57], data[58], data[59]]) as usize;
        let string_ids_offset =
            u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;

        // Each string ID is 4 bytes (offset to string_data_item)
        for i in 0..string_ids_size.min(1000) {
            // Limit to 1000 strings
            let id_offset = string_ids_offset + i * 4;
            if id_offset + 4 > data.len() {
                break;
            }

            let string_data_offset = u32::from_le_bytes([
                data[id_offset],
                data[id_offset + 1],
                data[id_offset + 2],
                data[id_offset + 3],
            ]) as usize;

            if let Some(s) = Self::read_string_at(data, string_data_offset) {
                strings.push(DexString {
                    offset: string_data_offset as u32,
                    value: SmolStr::new(&s),
                });
            }
        }

        strings
    }

    fn read_string_at(data: &[u8], offset: usize) -> Option<String> {
        if offset >= data.len() {
            return None;
        }

        // String data item: uleb128 size, then mutf8 data
        let (size, bytes_read) = Self::read_uleb128(data, offset)?;
        let string_start = offset + bytes_read;
        let string_end = string_start + size as usize;

        if string_end > data.len() {
            return None;
        }

        // Try to read as UTF-8 (simplified MUTF-8 handling)
        String::from_utf8(data[string_start..string_end].to_vec()).ok()
    }

    fn read_uleb128(data: &[u8], offset: usize) -> Option<(u32, usize)> {
        let mut result: u32 = 0;
        let mut shift = 0;
        let mut pos = offset;

        loop {
            if pos >= data.len() {
                return None;
            }

            let byte = data[pos];
            pos += 1;

            result |= ((byte & 0x7F) as u32) << shift;

            if byte & 0x80 == 0 {
                break;
            }

            shift += 7;
            if shift >= 35 {
                return None; // Overflow protection
            }
        }

        Some((result, pos - offset))
    }

    fn extract_version(data: &[u8]) -> SmolStr {
        if data.len() >= 8 {
            // Version is at bytes 4-7 (3 digits + null)
            let version_bytes = &data[4..7];
            if let Ok(version) = std::str::from_utf8(version_bytes) {
                return SmolStr::new(version);
            }
        }
        SmolStr::new("")
    }

    fn extract_header(data: &[u8]) -> DexHeader {
        if data.len() < 112 {
            return DexHeader::default();
        }

        let mut header = DexHeader::default();

        // Magic
        header.magic.copy_from_slice(&data[0..8]);

        // Checksum (little-endian u32 at offset 8)
        header.checksum = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);

        // SHA-1 signature (20 bytes at offset 12)
        header.signature.copy_from_slice(&data[12..32]);

        // File size
        header.file_size = u32::from_le_bytes([data[32], data[33], data[34], data[35]]);

        // Header size
        header.header_size = u32::from_le_bytes([data[36], data[37], data[38], data[39]]);

        // Endian tag
        header.endian_tag = u32::from_le_bytes([data[40], data[41], data[42], data[43]]);

        // Link size and offset
        header.link_size = u32::from_le_bytes([data[44], data[45], data[46], data[47]]);
        header.link_offset = u32::from_le_bytes([data[48], data[49], data[50], data[51]]);

        // Map offset
        header.map_offset = u32::from_le_bytes([data[52], data[53], data[54], data[55]]);

        // String IDs
        header.string_ids_size = u32::from_le_bytes([data[56], data[57], data[58], data[59]]);
        header.string_ids_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]);

        // Type IDs
        header.type_ids_size = u32::from_le_bytes([data[64], data[65], data[66], data[67]]);
        header.type_ids_offset = u32::from_le_bytes([data[68], data[69], data[70], data[71]]);

        // Proto IDs
        header.proto_ids_size = u32::from_le_bytes([data[72], data[73], data[74], data[75]]);
        header.proto_ids_offset = u32::from_le_bytes([data[76], data[77], data[78], data[79]]);

        // Field IDs
        header.field_ids_size = u32::from_le_bytes([data[80], data[81], data[82], data[83]]);
        header.field_ids_offset = u32::from_le_bytes([data[84], data[85], data[86], data[87]]);

        // Method IDs
        header.method_ids_size = u32::from_le_bytes([data[88], data[89], data[90], data[91]]);
        header.method_ids_offset = u32::from_le_bytes([data[92], data[93], data[94], data[95]]);

        // Class definitions
        header.class_defs_size = u32::from_le_bytes([data[96], data[97], data[98], data[99]]);
        header.class_defs_offset =
            u32::from_le_bytes([data[100], data[101], data[102], data[103]]);

        // Data section
        header.data_size = u32::from_le_bytes([data[104], data[105], data[106], data[107]]);
        header.data_offset = u32::from_le_bytes([data[108], data[109], data[110], data[111]]);

        header
    }

    /// Check if this is a valid DEX file
    pub fn is_dex(&self) -> bool {
        self.is_dex
    }

    /// Get the DEX version string
    pub fn version(&self) -> &str {
        self.version.as_str()
    }

    /// Get the number of strings
    pub fn number_of_strings(&self) -> usize {
        self.strings.len()
    }

    /// Get the number of classes
    pub fn number_of_classes(&self) -> usize {
        self.classes.len()
    }

    /// Get the total number of methods across all classes
    pub fn number_of_methods(&self) -> usize {
        self.classes.iter().map(|c| c.methods.len()).sum()
    }

    /// Get the total number of fields across all classes
    pub fn number_of_fields(&self) -> usize {
        self.classes.iter().map(|c| c.fields.len()).sum()
    }

    /// Check if a class exists by name
    pub fn has_class(&self, name: &str) -> bool {
        self.classes.iter().any(|c| c.class_name.contains(name))
    }

    /// Check if a method exists by name (in any class)
    pub fn has_method(&self, name: &str) -> bool {
        self.classes
            .iter()
            .any(|c| c.methods.iter().any(|m| m.name.as_str() == name))
    }

    /// Check if a string exists
    pub fn has_string(&self, value: &str) -> bool {
        self.strings.iter().any(|s| s.value.contains(value))
    }

    /// Get class by name
    pub fn get_class(&self, name: &str) -> Option<&DexClass> {
        self.classes.iter().find(|c| c.class_name.contains(name))
    }

    /// Get all class names
    pub fn class_names(&self) -> Vec<&str> {
        self.classes.iter().map(|c| c.class_name.as_str()).collect()
    }
}

// ============================================================================
// Convenience Functions
// ============================================================================

/// Parse a DEX file and return basic info
pub fn parse(data: &[u8]) -> DexInfo {
    DexInfo::parse(data)
}

/// Check if data is a valid DEX file
pub fn is_dex(data: &[u8]) -> bool {
    if data.len() < 8 {
        return false;
    }
    // Check magic: "dex\n"
    &data[0..4] == DEX_MAGIC
}

/// Get the DEX version string
pub fn dex_version(data: &[u8]) -> Option<String> {
    if data.len() < 8 || !is_dex(data) {
        return None;
    }
    std::str::from_utf8(&data[4..7]).ok().map(|s| s.to_string())
}

/// Get the number of strings in the DEX file
pub fn number_of_strings(data: &[u8]) -> u32 {
    if data.len() < 60 {
        return 0;
    }
    u32::from_le_bytes([data[56], data[57], data[58], data[59]])
}

/// Get the number of classes in the DEX file
pub fn number_of_classes(data: &[u8]) -> u32 {
    if data.len() < 100 {
        return 0;
    }
    u32::from_le_bytes([data[96], data[97], data[98], data[99]])
}

/// Get the file size from the header
pub fn file_size(data: &[u8]) -> u32 {
    if data.len() < 36 {
        return 0;
    }
    u32::from_le_bytes([data[32], data[33], data[34], data[35]])
}

/// Get the checksum from the header
pub fn checksum(data: &[u8]) -> u32 {
    if data.len() < 12 {
        return 0;
    }
    u32::from_le_bytes([data[8], data[9], data[10], data[11]])
}

/// Get the SHA-1 signature as a hex string
pub fn signature_hex(data: &[u8]) -> String {
    if data.len() < 32 {
        return String::new();
    }
    hex::encode(&data[12..32])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(DEX_MAGIC, b"dex\n");
        assert_eq!(access_flags::ACC_PUBLIC, 0x0001);
        assert_eq!(access_flags::ACC_STATIC, 0x0008);
        assert_eq!(access_flags::ACC_FINAL, 0x0010);
        assert_eq!(access_flags::ACC_NATIVE, 0x0100);
        assert_eq!(access_flags::ACC_INTERFACE, 0x0200);
    }

    #[test]
    fn test_is_dex() {
        // Valid DEX magic
        let valid = b"dex\n035\0rest of file...";
        assert!(is_dex(valid));

        // Invalid magic
        let invalid = b"not a dex file";
        assert!(!is_dex(invalid));

        // Too short
        let short = b"dex";
        assert!(!is_dex(short));

        // Empty
        assert!(!is_dex(&[]));
    }

    #[test]
    fn test_dex_version() {
        let data035 = b"dex\n035\0";
        assert_eq!(dex_version(data035), Some("035".to_string()));

        let data039 = b"dex\n039\0";
        assert_eq!(dex_version(data039), Some("039".to_string()));

        let invalid = b"not dex";
        assert_eq!(dex_version(invalid), None);
    }

    #[test]
    fn test_default_header() {
        let header = DexHeader::default();
        assert_eq!(header.file_size, 0);
        assert_eq!(header.checksum, 0);
        assert_eq!(header.class_defs_size, 0);
    }

    #[test]
    fn test_default_info() {
        let info = DexInfo::default();
        assert!(!info.is_dex);
        assert!(info.version.is_empty());
        assert!(info.classes.is_empty());
        assert!(info.strings.is_empty());
    }

    #[test]
    fn test_invalid_data() {
        let data = b"not a dex file at all";
        let info = DexInfo::parse(data);
        assert!(!info.is_dex());
    }

    #[test]
    fn test_access_flags() {
        // Test combining flags
        let public_static_final =
            access_flags::ACC_PUBLIC | access_flags::ACC_STATIC | access_flags::ACC_FINAL;
        assert_eq!(public_static_final, 0x0019);

        // Test checking flags
        assert!(public_static_final & access_flags::ACC_PUBLIC != 0);
        assert!(public_static_final & access_flags::ACC_STATIC != 0);
        assert!(public_static_final & access_flags::ACC_FINAL != 0);
        assert!(public_static_final & access_flags::ACC_NATIVE == 0);
    }

    #[test]
    fn test_dex_class_struct() {
        let class = DexClass {
            class_name: SmolStr::new("Lcom/example/Test;"),
            access_flags: access_flags::ACC_PUBLIC,
            superclass: Some(SmolStr::new("Ljava/lang/Object;")),
            interfaces: vec![SmolStr::new("Ljava/io/Serializable;")],
            source_file: Some(SmolStr::new("Test.java")),
            methods: vec![DexMethod {
                name: SmolStr::new("onCreate"),
                class_name: SmolStr::new("Lcom/example/Test;"),
                prototype: SmolStr::new("VL"),
                access_flags: access_flags::ACC_PUBLIC,
            }],
            fields: vec![DexField {
                name: SmolStr::new("mValue"),
                class_name: SmolStr::new("Lcom/example/Test;"),
                type_name: SmolStr::new("I"),
                access_flags: access_flags::ACC_PRIVATE,
            }],
        };

        assert_eq!(class.class_name.as_str(), "Lcom/example/Test;");
        assert!(class.class_name.contains("example"));
        assert_eq!(class.methods.len(), 1);
        assert_eq!(class.fields.len(), 1);
        assert_eq!(class.methods[0].name.as_str(), "onCreate");
    }

    #[test]
    fn test_dex_method_struct() {
        let method = DexMethod {
            name: SmolStr::new("main"),
            class_name: SmolStr::new("Lcom/example/Main;"),
            prototype: SmolStr::new("V[L"),
            access_flags: access_flags::ACC_PUBLIC | access_flags::ACC_STATIC,
        };

        assert_eq!(method.name.as_str(), "main");
        assert!(method.access_flags & access_flags::ACC_PUBLIC != 0);
        assert!(method.access_flags & access_flags::ACC_STATIC != 0);
    }

    #[test]
    fn test_dex_field_struct() {
        let field = DexField {
            name: SmolStr::new("TAG"),
            class_name: SmolStr::new("Lcom/example/Main;"),
            type_name: SmolStr::new("Ljava/lang/String;"),
            access_flags: access_flags::ACC_PRIVATE
                | access_flags::ACC_STATIC
                | access_flags::ACC_FINAL,
        };

        assert_eq!(field.name.as_str(), "TAG");
        assert!(field.access_flags & access_flags::ACC_FINAL != 0);
    }

    #[test]
    fn test_header_extraction() {
        // Minimal DEX header (112 bytes minimum)
        let mut header_data = vec![0u8; 112];

        // Magic
        header_data[0..4].copy_from_slice(DEX_MAGIC);
        // Version "035\0"
        header_data[4..8].copy_from_slice(b"035\0");

        // Checksum at offset 8
        header_data[8..12].copy_from_slice(&0x12345678u32.to_le_bytes());

        // File size at offset 32
        header_data[32..36].copy_from_slice(&112u32.to_le_bytes());

        // Header size at offset 36 (always 0x70 = 112)
        header_data[36..40].copy_from_slice(&112u32.to_le_bytes());

        // Endian tag at offset 40 (0x12345678 for little-endian)
        header_data[40..44].copy_from_slice(&0x12345678u32.to_le_bytes());

        // String IDs at offset 56
        header_data[56..60].copy_from_slice(&100u32.to_le_bytes());

        // Class defs at offset 96
        header_data[96..100].copy_from_slice(&10u32.to_le_bytes());

        let header = DexInfo::extract_header(&header_data);

        assert_eq!(header.checksum, 0x12345678);
        assert_eq!(header.file_size, 112);
        assert_eq!(header.header_size, 112);
        assert_eq!(header.string_ids_size, 100);
        assert_eq!(header.class_defs_size, 10);
    }

    #[test]
    fn test_convenience_functions() {
        // Minimal header data for testing convenience functions
        let mut data = vec![0u8; 112];
        data[0..8].copy_from_slice(b"dex\n035\0");
        data[8..12].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        data[32..36].copy_from_slice(&0x1000u32.to_le_bytes());
        data[56..60].copy_from_slice(&50u32.to_le_bytes());
        data[96..100].copy_from_slice(&5u32.to_le_bytes());

        assert!(is_dex(&data));
        assert_eq!(checksum(&data), 0xDEADBEEF);
        assert_eq!(file_size(&data), 0x1000);
        assert_eq!(number_of_strings(&data), 50);
        assert_eq!(number_of_classes(&data), 5);
    }

    #[test]
    fn test_signature_hex() {
        let mut data = vec![0u8; 32];
        data[0..4].copy_from_slice(DEX_MAGIC);
        // SHA-1 signature at offset 12-32 (20 bytes)
        for i in 12..32 {
            data[i] = (i - 12) as u8;
        }

        let sig = signature_hex(&data);
        assert_eq!(sig.len(), 40); // 20 bytes = 40 hex chars
        assert_eq!(&sig[0..4], "0001"); // First two bytes: 00, 01
    }
}
