//! Build script for r-yara-parser
//!
//! Runs LALRPOP to generate the parser from the grammar file.

fn main() {
    lalrpop::process_root().unwrap();
}
