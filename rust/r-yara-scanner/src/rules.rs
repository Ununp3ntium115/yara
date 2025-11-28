//! Compiled rules management

use crate::error::{ScanError, ScanResult};
use r_yara_compiler::{CompiledRules, Compiler};
use r_yara_parser::parse;
use std::fs;
use std::path::Path;

/// Load and compile YARA rules from a file
///
/// # Arguments
///
/// * `path` - Path to the YARA rules file
///
/// # Example
///
/// ```no_run
/// use r_yara_scanner::load_rules_from_file;
///
/// let rules = load_rules_from_file("rules/malware.yar")?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn load_rules_from_file<P: AsRef<Path>>(path: P) -> ScanResult<CompiledRules> {
    let path = path.as_ref();

    if !path.exists() {
        return Err(ScanError::FileNotFound(path.display().to_string()));
    }

    let source = fs::read_to_string(path)
        .map_err(|e| ScanError::InvalidRuleFile(format!("{}: {}", path.display(), e)))?;

    load_rules_from_string(&source)
}

/// Load and compile YARA rules from a string
///
/// # Arguments
///
/// * `source` - YARA rules source code
///
/// # Example
///
/// ```
/// use r_yara_scanner::load_rules_from_string;
///
/// let source = r#"
///     rule test {
///         strings:
///             $a = "malware"
///         condition:
///             $a
///     }
/// "#;
///
/// let rules = load_rules_from_string(source)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn load_rules_from_string(source: &str) -> ScanResult<CompiledRules> {
    compile_rules(source)
}

/// Compile YARA rules from source code
///
/// # Arguments
///
/// * `source` - YARA rules source code
///
/// # Returns
///
/// Compiled rules ready for scanning
pub fn compile_rules(source: &str) -> ScanResult<CompiledRules> {
    // Parse the source
    let ast = parse(source)?;

    // Compile to bytecode
    let mut compiler = Compiler::new();
    let compiled = compiler.compile(&ast)?;

    Ok(compiled)
}

/// Load rules from multiple files
///
/// # Arguments
///
/// * `paths` - Iterator of paths to YARA rule files
///
/// # Example
///
/// ```no_run
/// use r_yara_scanner::load_rules_from_files;
///
/// let paths = vec!["rules/malware.yar", "rules/packer.yar"];
/// let rules = load_rules_from_files(paths.iter())?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn load_rules_from_files<'a, I, P>(paths: I) -> ScanResult<CompiledRules>
where
    I: IntoIterator<Item = &'a P>,
    P: AsRef<Path> + 'a,
{
    let mut combined_source = String::new();

    for path in paths {
        let path = path.as_ref();

        if !path.exists() {
            return Err(ScanError::FileNotFound(path.display().to_string()));
        }

        let source = fs::read_to_string(path)
            .map_err(|e| ScanError::InvalidRuleFile(format!("{}: {}", path.display(), e)))?;

        combined_source.push_str(&source);
        combined_source.push('\n');
    }

    load_rules_from_string(&combined_source)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compile_simple_rule() {
        let source = r#"
            rule test_rule {
                condition:
                    true
            }
        "#;

        let result = compile_rules(source);
        assert!(result.is_ok());

        let rules = result.unwrap();
        assert_eq!(rules.rules.len(), 1);
        assert_eq!(rules.rules[0].name.as_str(), "test_rule");
    }

    #[test]
    fn test_compile_rule_with_strings() {
        let source = r#"
            rule test_strings {
                strings:
                    $a = "test"
                    $b = "hello"
                condition:
                    any of them
            }
        "#;

        let result = compile_rules(source);
        assert!(result.is_ok());

        let rules = result.unwrap();
        assert_eq!(rules.patterns.len(), 2);
    }

    #[test]
    fn test_compile_multiple_rules() {
        let source = r#"
            rule rule1 {
                condition: true
            }

            rule rule2 {
                strings:
                    $a = "test"
                condition:
                    $a
            }
        "#;

        let result = compile_rules(source);
        assert!(result.is_ok());

        let rules = result.unwrap();
        assert_eq!(rules.rules.len(), 2);
    }

    #[test]
    fn test_compile_with_imports() {
        let source = r#"
            import "pe"
            import "hash"

            rule test {
                condition:
                    true
            }
        "#;

        let result = compile_rules(source);
        assert!(result.is_ok());

        let rules = result.unwrap();
        assert_eq!(rules.imports.len(), 2);
    }

    #[test]
    fn test_compile_invalid_syntax() {
        let source = r#"
            rule invalid {
                condition:
                    this is not valid
            }
        "#;

        let result = compile_rules(source);
        assert!(result.is_err());
    }
}
