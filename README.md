# Secure-Code-Check-

A lightweight, high-performance **Static Application Security Testing (SAST)** command-line utility built entirely in Python. This tool automates the process of auditing source code files to discover hardcoded secrets (API keys, credentials) and high-risk security logic flaws before code is pushed to production.

---

## Key Features-
Zero Dependencies: Relies completely on native Python standard libraries (`os`, `re`, `datetime`). No external packages or installation overhead required.
Secret Detection Engine: Scans string variables and assignments using high-entropy pattern matching to intercept exposed passwords, auth tokens, and cryptographic keys.
Logic-Flaw Mapping: Identifies dangerous code functions capable of introducing critical vulnerabilities like Command Injection or dynamic script execution.
Automated Forensic Reporting: Aggregates multi-file findings and instantly generates a structured, human-readable executive audit report (security_report.md).

---

##  Core Vulnerability Mapping Matrix:

The analyzer dynamically evaluates source files against the following built-in security rule definitions:

formate: | Threat Category | Target Signatures / Keywords | Assessed Severity | Operational Risk Description |

| **Hardcoded Secret** | `api_key`, `secret`, `password`, `auth_token` |  **High** | Exposed credentials can be leveraged by malicious actors if code repositories are compromised or publicly leaked. |

| **Command Injection**| `os.system()`, `subprocess.Popen()`, `subprocess.run()` |  **High** | Direct invocation of system shells allows arbitrary OS command execution if user input reaches these functions unsanitized. |

| **Arbitrary Code Execution** | `eval()`, `exec()` |  **High** | Parsing untrusted input strings straight into the active runtime environment bypasses application boundaries entirely. |

| **Weak Cryptography** | `hashlib.md5()`, `hashlib.sha1()` |  **Medium** | Cryptographically broken hashing algorithms are highly susceptible to collision attacks and rapid brute-forcing. |

| **Insecure Temp Files**| `tempfile.mktemp()` |  **Low** | Deprecated file generation methods prone to local symlink racing conditions on the file system layer. |

---

##  Supported Technology Stack:

The scanner scans any flat-text asset but is pre-configured to look directly inside files matching the following extensions:
* **Languages:** Python (`.py`), JavaScript (`.js`)
* **Environment & Configs:** Configuration text (`.txt`), Configuration files (`.conf`), Environment stores (`.env`)

---

##  Installation & Quick Start

### 1. Clone the Workspace
Drop the main script into the workspace directory where your target application code resides.

### 2. Execute the Scanner
Launch your native terminal interface and run the script utilizing your system's Python 3 interpreter:

--bash
python scanner.py
#after run this you get this output:

Enter full path to scan (or type '.' for current folder): 

##enter the path of the code that you want to check

expected output: a .md file is genrated in your folder:

#in .md file you will  get all information about your code Vulnerabilities:

**Example**:
# Static Application Security Testing (SAST) Report
Target Directory: C:\Users\Dakshita Vairagi\OneDrive\Desktop\MY_Projects\test_code

## Executive Summary
Total Vulnerabilities Found: 3
High Severity: 2
Medium Severity: 1
Low Severity: 0

---

## Detailed Vulnerability Findings
### Issue 1: Hardcoded API Key / Secret
* **Location:** C:\Users\Dakshita Vairagi\OneDrive\Desktop\MY_Projects\test_code\vulnerable_script.py (Line 2)
* **Severity:** High
* **Description:** Potential hardcoded credential or secret found. If leaked, attackers can gain unauthorized access.
* **Code Snippet:** api_key = "AIzaSyD-fake-key-value-12345"
### Issue 2: Command Injection Risk
* **Location:** C:\Users\Dakshita Vairagi\OneDrive\Desktop\MY_Projects\test_code\vulnerable_script.py (Line 7)
* **Severity:** High
* **Description:** Direct OS command execution detected. Highly vulnerable to Command Injection if user input is not sanitized.
* **Code Snippet:** os.system("ping " + user_input)
### Issue 3: Weak Cryptographic Hash
* **Location:** C:\Users\Dakshita Vairagi\OneDrive\Desktop\MY_Projects\test_code\vulnerable_script.py (Line 11)
* **Severity:** Medium
* **Description:** MD5 or SHA-1 hashing algorithm detected. These are mathematically broken and vulnerable to collision attacks.
* **Code Snippet:** hashed_data = hashlib.md5(b"password123")
 )
