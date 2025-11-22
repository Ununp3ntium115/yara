#!/usr/bin/env python3
"""
YARA System Scanner
Scans files on the system using YARA rules from the Yara-Rules repository
"""

import yara
import os
import sys
import argparse
from pathlib import Path
from datetime import datetime
import json

# Import rule transcoder for Cryptex support
try:
    from tools.rule_loader import CryptexRuleLoader
    CRYPTEX_AVAILABLE = True
except ImportError:
    CRYPTEX_AVAILABLE = False
    CryptexRuleLoader = None

class YaraScanner:
    def __init__(self, rules_path, output_file=None, use_cryptex=False, auto_transcode=True):
        """Initialize the YARA scanner with compiled rules"""
        self.rules_path = rules_path
        self.output_file = output_file
        self.use_cryptex = use_cryptex and CRYPTEX_AVAILABLE
        self.auto_transcode = auto_transcode
        self.matches = []
        self.scanned_files = 0
        self.matched_files = 0
        self.rule_loader = None

        print(f"[*] Loading YARA rules from: {rules_path}")
        try:
            if self.use_cryptex:
                self.rule_loader = CryptexRuleLoader(auto_transcode=auto_transcode)
                self.rules = self.rule_loader.load_rule_file(Path(rules_path), use_cryptex=True)
                print(f"[+] YARA rules loaded with Cryptex transcoding!")
            else:
                self.rules = yara.compile(filepath=rules_path)
                print(f"[+] YARA rules loaded successfully!")
        except Exception as e:
            print(f"[!] Error loading YARA rules: {e}")
            sys.exit(1)

    def scan_file(self, filepath):
        """Scan a single file with YARA rules"""
        try:
            matches = self.rules.match(filepath)
            self.scanned_files += 1

            if matches:
                self.matched_files += 1
                match_info = {
                    'file': str(filepath),
                    'timestamp': datetime.now().isoformat(),
                    'matches': []
                }

                print(f"\n[!] MATCH FOUND: {filepath}")
                for match in matches:
                    print(f"    Rule: {match.rule}")
                    print(f"    Tags: {', '.join(match.tags) if match.tags else 'None'}")

                    match_info['matches'].append({
                        'rule': match.rule,
                        'tags': list(match.tags),
                        'meta': dict(match.meta) if match.meta else {}
                    })

                self.matches.append(match_info)
                return True
            return False
        except Exception as e:
            # Skip files that can't be read
            return False

    def scan_directory(self, directory, recursive=True, extensions=None):
        """Scan all files in a directory"""
        directory = Path(directory)

        if not directory.exists():
            print(f"[!] Directory does not exist: {directory}")
            return

        print(f"\n[*] Scanning directory: {directory}")
        print(f"[*] Recursive: {recursive}")

        pattern = "**/*" if recursive else "*"

        for filepath in directory.glob(pattern):
            if filepath.is_file():
                # Filter by extension if specified
                if extensions:
                    if filepath.suffix.lower() not in extensions:
                        continue

                # Skip very large files (> 100MB)
                try:
                    if filepath.stat().st_size > 100 * 1024 * 1024:
                        continue
                except:
                    continue

                self.scan_file(filepath)

                # Progress indicator
                if self.scanned_files % 100 == 0:
                    print(f"[*] Progress: {self.scanned_files} files scanned, {self.matched_files} matches found")

    def save_results(self):
        """Save scan results to file"""
        if self.output_file:
            try:
                with open(self.output_file, 'w') as f:
                    json.dump({
                        'scan_time': datetime.now().isoformat(),
                        'total_scanned': self.scanned_files,
                        'total_matches': self.matched_files,
                        'matches': self.matches
                    }, f, indent=2)
                print(f"\n[+] Results saved to: {self.output_file}")
            except Exception as e:
                print(f"[!] Error saving results: {e}")

    def print_summary(self):
        """Print scan summary"""
        print("\n" + "="*60)
        print("SCAN SUMMARY")
        print("="*60)
        print(f"Total files scanned: {self.scanned_files}")
        print(f"Total matches found: {self.matched_files}")
        print(f"Files with matches: {len(self.matches)}")
        print("="*60)


def main():
    parser = argparse.ArgumentParser(
        description='YARA System Scanner using Yara-Rules repository',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Scan a specific directory
  python yara_scanner.py -d C:\\Users\\username\\Downloads

  # Scan with specific rule category
  python yara_scanner.py -d C:\\temp -r yara-rules/malware_index.yar

  # Scan with output file
  python yara_scanner.py -d C:\\temp -o scan_results.json

  # Scan only specific file types
  python yara_scanner.py -d C:\\temp -e .exe .dll .pdf
        '''
    )

    parser.add_argument(
        '-r', '--rules',
        default='yara-rules/index.yar',
        help='Path to YARA rules file (default: yara-rules/index.yar)'
    )

    parser.add_argument(
        '-d', '--directory',
        required=True,
        help='Directory to scan'
    )

    parser.add_argument(
        '--no-recursive',
        action='store_true',
        help='Do not scan subdirectories'
    )

    parser.add_argument(
        '-e', '--extensions',
        nargs='+',
        help='File extensions to scan (e.g., .exe .dll .pdf)'
    )

    parser.add_argument(
        '-o', '--output',
        help='Output file for results (JSON format)'
    )
    
    parser.add_argument(
        '--cryptex',
        action='store_true',
        help='Use Cryptex codename transcoding for rules'
    )
    
    parser.add_argument(
        '--no-transcode',
        action='store_true',
        help='Disable automatic transcoding (only if --cryptex is used)'
    )

    args = parser.parse_args()
    
    # Initialize scanner with optional Cryptex support
    scanner = YaraScanner(
        args.rules, 
        args.output,
        use_cryptex=args.cryptex,
        auto_transcode=not args.no_transcode
    )

    # Perform scan
    scanner.scan_directory(
        args.directory,
        recursive=not args.no_recursive,
        extensions=args.extensions
    )

    # Print summary
    scanner.print_summary()

    # Save results if output file specified
    if args.output:
        scanner.save_results()
    
    # Cleanup if using Cryptex loader
    if hasattr(scanner, 'rule_loader') and scanner.rule_loader:
        scanner.rule_loader.cleanup()


if __name__ == '__main__':
    main()
