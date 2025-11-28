# R-YARA Documentation

Welcome to the R-YARA documentation! R-YARA is a Rust-based reimplementation of the YARA pattern matching system, designed for high-performance malware detection and analysis.

## Documentation Structure

This documentation is organized into the following sections:

### 1. [Getting Started Guide](GETTING_STARTED.md)
Quick start guide to get you up and running with R-YARA:
- Installation instructions
- Basic usage examples
- Your first scan
- Writing YARA rules

### 2. [Architecture Guide](ARCHITECTURE.md)
Deep dive into R-YARA's system architecture:
- Component diagram and overview
- Data flow from rules to scan results
- Crate dependencies and structure
- Module system design

### 3. [API Reference](API_REFERENCE.md)
Complete API documentation for developers:
- Scanner API
- Rule compilation
- Module functions (pe, elf, hash, math, etc.)
- Error handling

### 4. [CLI Guide](CLI_GUIDE.md)
Command-line interface reference:
- `r-yara scan` - Scan files and directories
- `r-yara compile` - Compile rules
- `r-yara check` - Validate rules
- Options and flags

### 5. [Module Reference](MODULES.md)
Comprehensive module documentation:
- PE module (Windows executables)
- ELF module (Linux executables)
- Mach-O module (macOS executables)
- DEX module (Android executables)
- Hash module (cryptographic hashing)
- Math module (entropy, statistics)

### 6. [PYRO Integration Guide](PYRO_INTEGRATION.md)
Integration with PYRO Platform:
- Architecture with PYRO
- API endpoints and gateway
- WebSocket streaming
- Worker configuration

## Quick Links

### For Beginners
Start with the [Getting Started Guide](GETTING_STARTED.md) to learn the basics.

### For Developers
Check the [API Reference](API_REFERENCE.md) for integration into your applications.

### For Security Researchers
See the [Module Reference](MODULES.md) for detailed information on analyzing executable files.

### For DevOps/Platform Engineers
Review the [PYRO Integration Guide](PYRO_INTEGRATION.md) for deployment and scaling.

## About R-YARA

R-YARA is a modern, high-performance implementation of YARA written in Rust. It maintains compatibility with standard YARA rules while providing:

- **Performance**: Rust's zero-cost abstractions and memory safety
- **Modularity**: Clean separation of concerns with multiple crates
- **Integration**: REST API, CLI, and library interfaces
- **Platform Support**: Native PYRO Platform integration
- **Extensibility**: Plugin-based module system

## Version

This documentation is for R-YARA version 0.1.0.

## License

R-YARA is licensed under the Apache 2.0 License.

## Contributing

For information about contributing to R-YARA, please see the main repository README.

## Support

- GitHub Issues: Report bugs and request features
- Documentation: This guide and inline code documentation
- Examples: See the `examples/` directory in the repository

## Related Documentation

- [YARA Official Documentation](https://yara.readthedocs.io/)
- [Rust Documentation](https://doc.rust-lang.org/)
- [PYRO Platform Documentation](https://pyro-platform.io/)
