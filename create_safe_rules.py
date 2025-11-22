#!/usr/bin/env python3
"""
Create a safe YARA rules index without cuckoo module dependencies
"""

import os
import re
from pathlib import Path

def check_rule_file(filepath):
    """Check if a rule file has cuckoo module dependencies"""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            # Check for cuckoo module usage
            if re.search(r'cuckoo\.', content, re.IGNORECASE):
                return False, "Contains cuckoo module reference"
            return True, "OK"
    except Exception as e:
        return False, f"Error reading file: {e}"

def create_safe_index():
    """Create a safe index file without problematic rules"""
    base_path = Path("yara-rules")
    output_file = Path("yara-rules/safe_malware_index.yar")

    # Read original index
    original_index = base_path / "malware_index.yar"

    if not original_index.exists():
        print(f"[!] Original index not found: {original_index}")
        return

    safe_rules = []
    skipped_rules = []

    print("[*] Analyzing malware rules...")

    with open(original_index, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()

            # Check if it's an include statement
            if line.startswith('include'):
                # Extract the file path
                match = re.search(r'include\s+"([^"]+)"', line)
                if match:
                    rule_file = match.group(1)
                    full_path = base_path / rule_file

                    if full_path.exists():
                        is_safe, reason = check_rule_file(full_path)

                        if is_safe:
                            safe_rules.append(line)
                            print(f"[+] SAFE: {rule_file}")
                        else:
                            skipped_rules.append((rule_file, reason))
                            print(f"[-] SKIP: {rule_file} - {reason}")
                    else:
                        print(f"[!] NOT FOUND: {full_path}")
            elif line and not line.startswith('/*') and not line.startswith('*'):
                safe_rules.append(line)

    # Write safe index
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("/*\n")
        f.write("Safe Malware Rules Index\n")
        f.write("Rules without cuckoo module dependencies\n")
        f.write("Generated automatically\n")
        f.write("*/\n\n")

        for rule in safe_rules:
            f.write(rule + '\n')

    print(f"\n[+] Created safe index: {output_file}")
    print(f"[+] Included rules: {len(safe_rules)}")
    print(f"[!] Skipped rules: {len(skipped_rules)}")

    if skipped_rules:
        print("\nSkipped rules:")
        for rule, reason in skipped_rules:
            print(f"  - {rule}: {reason}")

if __name__ == '__main__':
    create_safe_index()
