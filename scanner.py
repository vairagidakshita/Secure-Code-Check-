import os
import re
from datetime import datetime

# ==========================================
# 1. DEFINE DETAILED SECURITY RULES (REGEX)
# ==========================================
SECURITY_RULES = {
    "Hardcoded API Key / Secret": {
        "pattern": r'(?i)(api_key|secret|password|passwd|auth_token|credentials)\s*=\s*["\'][a-zA-Z0-9_\-]{8,}["\']',
        "severity": "High",
        "description": "Potential hardcoded credential or secret found. If leaked, attackers can gain unauthorized access."
    },
    "Command Injection Risk": {
        "pattern": r'(os\.system|subprocess\.Popen|subprocess\.run)\s*\(',
        "severity": "High",
        "description": "Direct OS command execution detected. Highly vulnerable to Command Injection if user input is not sanitized."
    },
    "Arbitrary Code Execution Risk": {
        "pattern": r'\b(eval|exec)\s*\(',
        "severity": "High",
        "description": "Use of eval() or exec() detected. Dynamically executing strings as code is extremely dangerous."
    },
    "Weak Cryptographic Hash": {
        "pattern": r'\b(hashlib\.md5|hashlib\.sha1|md5|sha1)\s*\(',
        "severity": "Medium",
        "description": "MD5 or SHA-1 hashing algorithm detected. These are mathematically broken and vulnerable to collision attacks."
    },
    "Insecure Temporary File Creation": {
        "pattern": r'tempfile\.mktemp\s*\(',
        "severity": "Low",
        "description": "mktemp() is deprecated and vulnerable to file-system race conditions."
    }
}

SUPPORTED_EXTENSIONS = {'.py', '.js', '.txt', '.conf', '.env'}

def scan_file(file_path):
    """Scans individual files line by line against the regex pattern rules."""
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                clean_line = line.strip()
                if clean_line.startswith('#') or clean_line.startswith('//'):
                    continue
                
                for rule_name, rule_meta in SECURITY_RULES.items():
                    if re.search(rule_meta["pattern"], clean_line):
                        findings.append({
                            "file": file_path,
                            "line_number": line_num,
                            "code_snippet": clean_line[:100],
                            "issue": rule_name,
                            "severity": rule_meta["severity"],
                            "description": rule_meta["description"]
                        })
    except Exception as e:
        print(f"[-] Error reading file: {e}")
    return findings

def run_scanner(target_directory):
    """Orchestrates file retrieval and mapping."""
    print(f"[*] Starting Security Scan on directory: {target_directory}")
    all_findings = []
    
    for root, _, files in os.walk(target_directory):
        for file in files:
            if os.path.splitext(file)[1] in SUPPORTED_EXTENSIONS:
                full_path = os.path.join(root, file)
                if "scanner.py" in full_path:
                    continue
                
                file_findings = scan_file(full_path)
                if file_findings:
                    all_findings.extend(file_findings)
                    print(f"[!] Identified vulnerabilities in: {full_path}")
    
    generate_markdown_report(all_findings, target_directory)

def generate_markdown_report(findings, target_dir):
    """Builds a clean markdown audit log file."""
    report_filename = "security_report.md"
    
    high_count = sum(1 for f in findings if f["severity"] == "High")
    med_count = sum(1 for f in findings if f["severity"] == "Medium")
    low_count = sum(1 for f in findings if f["severity"] == "Low")
    
    with open(report_filename, 'w', encoding='utf-8') as rf:
        rf.write("# Static Application Security Testing (SAST) Report\n")
        rf.write(f"Target Directory: {target_dir}\n\n")
        
        rf.write("## Executive Summary\n")
        rf.write(f"Total Vulnerabilities Found: {len(findings)}\n")
        rf.write(f"High Severity: {high_count}\n")
        rf.write(f"Medium Severity: {med_count}\n")
        rf.write(f"Low Severity: {low_count}\n\n")
        
        rf.write("--\n\n")
        
        rf.write("## Detailed Vulnerability Findings\n")
        if len(findings) == 0:
            rf.write("No vulnerabilities detected.\n")
        else:
            for idx, finding in enumerate(findings, 1):
                rf.write(f"### Issue {idx}: {finding['issue']}\n")
                rf.write(f"* **Location:** {finding['file']} (Line {finding['line_number']})\n")
                rf.write(f"* **Severity:** {finding['severity']}\n")
                rf.write(f"* **Description:** {finding['description']}\n")
                rf.write(f"* **Code Snippet:** {finding['code_snippet']}\n") 
                
    print(f"\n[+] Scan complete. Report generated as: {report_filename}")

if __name__ == "__main__":
    target_folder = input("Enter full path to scan (or type '.' for current folder): ").strip()
    if os.path.exists(target_folder):
        run_scanner(target_folder)
    else:
        print("[-] Error: Path does not exist.")