# Opengrep and snyk analysis (Go & Python)

This repository contains tools, documentation, and benchmark reports comparing **Snyk Code** (SARIF) against **OpenGrep** (`--config auto` vs. explicit `-f` rule packs) on the Damn Vulnerable Web Application ([DVWA](https://github.com/digininja/DVWA)).

---

## 1. Executive Summary: Snyk vs. OpenGrep Parity Overview

Running OpenGrep with explicit `-f` rule packs closes the gap with Snyk Code significantly compared to default `--config auto`:

* **Snyk Code Total Application Findings**: **105**
* **OpenGrep `--config auto` Findings**: **66**
  * Correlated with Snyk: **27 findings** (25.7% Snyk coverage)
* **OpenGrep `-f` Rule Packs Findings**: **108**
  * Correlated with Snyk: **47 findings** (44.8% Snyk coverage)
  * **Incremental Snyk Parity with `-f`**: **+20 additional Snyk findings caught** (+74.1% increase in correlated issues)
* **Uncorrelated Snyk Findings**: **58 findings** (areas where Snyk catches patterns not present in default OpenGrep packs)

```
Tri-Scanner Finding Comparison:
  Snyk Code      [105 findings]  ████████████████████████
  OpenGrep Auto  [ 66 findings]  ███████████████          (27 Snyk matches)
  OpenGrep -f    [108 findings]  █████████████████████████ (47 Snyk matches: +20 newly common)
```

---

## 2. Categories Newly Common in Snyk and OpenGrep Reports (+20 Findings)

When transitioning from `--config auto` to explicit `-f` rule packs, OpenGrep newly detected **20 vulnerabilities** that Snyk also flags. These findings were previously invisible under `--config auto`:

| Category / Snyk Rule | CWEs | Newly Matched Count | Primary Files / Vulnerability | Technical Reason for Parity |
| :--- | :---: | :---: | :--- | :--- |
| **Insecure Cryptography & Broken Password Hashing** (`php/InsecureHash`) | **CWE-916**, **CWE-328** | **18** | `login.php:27`<br>`dvwaPage.inc.php:651`<br>`vulnerabilities/brute/source/high.php:16`<br>`vulnerabilities/captcha/source/high.php:27`<br>`vulnerabilities/csrf/source/high.php:39`<br>`vulnerabilities/weak_id/source/high.php:10` | Snyk flags broken `md5()` hashing used for authentication and session management. `--config auto` excluded `weak-crypto.yaml` because it is tagged `confidence: LOW` and `subcategory: [audit]`. Passing `-f .../php` forced OpenGrep to load this rule, catching all 18 password hashing vulnerabilities. |
| **Hardcoded Credentials & Plaintext Secrets** (`php/HardcodedCredential/test`) | **CWE-798**, **CWE-259** | **2** | `vulnerabilities/sqli/test.php:4`<br>`vulnerabilities/csrf/help/help.php:54` | Snyk detected committed database passwords and API tokens in test/help files. `--config auto` only scans detected language ASTs, skipping regex secret patterns. Passing `-f .../generic` activated GitLeaks secret rules (`hashicorp-tf-password`, `generic-api-key`), achieving parity. |
| **Total Newly Correlated** | | **20** | | **Snyk coverage increased from 25.7% (27) to 44.8% (47)** |

---

## 3. Categories of Snyk Findings NOT Present in the OpenGrep Report (58 Findings)

Snyk Code identified **58 findings** that OpenGrep (even with `-f` rule packs) did not detect. Below is the detailed architectural breakdown of these gaps:

| Category / Snyk Rule | CWEs | Unmatched Count | Example Locations in DVWA | Why OpenGrep Missed It |
| :--- | :---: | :---: | :--- | :--- |
| **1. Information Exposure & Exception Server Leaks** (`php/ServerLeak`) | **CWE-200**, **CWE-209** | **23** | `login.php:40`<br>`vulnerabilities/sqli/source/low.php:11, 36`<br>`vulnerabilities/sqli/source/medium.php:12, 32, 55`<br>`vulnerabilities/brute/source/high.php:20`<br>`vulnerabilities/xss_s/source/high.php:19` | Snyk flags database error strings (`mysqli_error($GLOBALS["___mysqli_ston"])`) and exception messages (`$e->getMessage()`) printed directly to HTTP responses. OpenGrep lacks a sink pattern matching `mysqli_error()` or exception output reflection. |
| **2. Insecure Cookie Configuration (Missing `HttpOnly` / `Secure`)** | **CWE-1004**, **CWE-614** | **13** | `vulnerabilities/bac/source/low.php:94`<br>`vulnerabilities/sqli_blind/cookie-input.php:12`<br>`vulnerabilities/weak_id/source/low.php:11`<br>`dvwa/js/dvwaPage.js:44` | Snyk audits `setcookie()` and `session_set_cookie_params()` when boolean flags `$httponly` or `$secure` are missing or set to `false`. OpenGrep's default web rules do not inspect PHP cookie parameter lists. |
| *• WebCookieHttpOnlyDisabledByDefault* | `CWE-1004` | *4* | `vulnerabilities/bac/source/low.php:94` | Default cookie set without `HttpOnly`. |
| *• WebCookieSecureDisabledByDefault* | `CWE-614` | *4* | `vulnerabilities/sqli_blind/cookie-input.php:12` | Default cookie set without `Secure`. |
| *• WebCookieHttpOnlyDisabledExplicitly* | `CWE-1004` | *2* | `login.php:57` | Explicit `false` passed for `HttpOnly`. |
| *• WebCookieSecureDisabledExplicitly* | `CWE-614` | *2* | `login.php:57` | Explicit `false` passed for `Secure`. |
| *• WebCookieSecureDisabledByDefault (JS)* | `CWE-614` | *1* | `dvwa/js/dvwaPage.js:44` | Client-side cookie set without `Secure`. |
| **3. Complex Multi-Step & SQLite SQL Injection** (`php/Sqli`) | **CWE-89** | **5** | `vulnerabilities/sqli/source/medium.php:40`<br>`vulnerabilities/sqli_blind/source/medium.php:45`<br>`vulnerabilities/sqli_blind/source/high.php:40` | Snyk detects SQL injection on SQLite drivers (`sqlite3_query()`, `sqlite_query()`) and complex multi-parameter POST inputs. OpenGrep covers procedural `mysqli_query` but lacks taint sources for SQLite APIs. |
| **4. Multi-Hop Sanitization Bypass XSS** (`php/XSS`) | **CWE-79** | **6** | `vulnerabilities/xss_r/source/medium.php:7`<br>`vulnerabilities/xss_r/source/high.php:7`<br>`vulnerabilities/xss_s/source/medium.php:12` | Snyk's inter-procedural taint engine traces input through ineffective regex stripping (`preg_replace('/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', '', $_GET['name'])`). OpenGrep's intra-file engine treats `preg_replace` as a sanitizer barrier unless custom bypass rules are loaded. |
| **5. Hardcoded Non-Cryptographic Secrets** (`php/HardcodedNonCryptoSecret`) | **CWE-547** | **5** | `vulnerabilities/sqli/source/low.php:18`<br>`vulnerabilities/sqli_blind/source/low.php:18`<br>`config/config.inc.php:20` | Snyk uses semantic heuristics to flag sensitive variable assignments (e.g. `$_DVWA['db_password'] = 'p@ssword'`). OpenGrep secret rules look for high-entropy tokens rather than variable names. |
| **6. Open Redirect** (`php/OR`) | **CWE-601** | **4** | `vulnerabilities/open_redirect/source/low.php:4`<br>`vulnerabilities/open_redirect/source/medium.php:11`<br>`vulnerabilities/open_redirect/source/high.php:5`<br>`vulnerabilities/open_redirect/source/impossible.php:12` | Snyk flags unvalidated redirects via `header("Location: " . $_GET['redirect'])`. OpenGrep's default PHP ruleset does not contain an open redirect sink rule for `header("Location: ...")`. |
| **7. Insecure Symmetric Cipher Mode** (`php/InsecureECB`) | **CWE-327** | **1** | `vulnerabilities/cryptography/source/ecb_attack.php:40` | Snyk flags Electronic Codebook (ECB) cipher mode (`MCRYPT_RIJNDAEL_128` with ECB mode). OpenGrep crypto rules only check for weak hashing (`md5`, `sha1`), not block cipher modes. |
| **8. Insecure Hash in Arithmetic Loop** (`php/InsecureHash`) | **CWE-916** | **1** | `vulnerabilities/cryptography/source/ecb_attack.php:92` | 1 remaining hash call wrapped in nested custom loops. |
| **TOTAL UNMATCHED SNYK FINDINGS** | | **58** | | **Identifies clear targets for custom OpenGrep parity rules** |

---

## 4. Architecture of the Go Program (`main.go`)

The Go program (`main.go`) provides automated cross-scanner correlation between SARIF (Snyk) and JSON (OpenGrep) schemas without relying on matching rule names.

### Key Capabilities

1. **Portable Relative Path Resolution (`resolveFilePath`)**:
   * Contains **no hardcoded local machine paths**.
   * Accepts relative CLI arguments (`-snyk`, `-opengrep`, `-auto`).
   * Automatically searches candidate directories (`.`, `reports/`, `../DVWA/`, `../../DVWA/`) if flags are omitted.
2. **Scanner Self-Scan Filtering**:
   * Automatically ignores `snyk-report.json` and `opengrep-*.json` during parsing so reports are never polluted by scanner self-scans.
3. **Workspace Path Normalization (`normalizePath`)**:
   * Standardizes slashes and strips varying workspace roots (e.g. `/DVWA/`, `DVWA/`, `./`) so Snyk URIs match OpenGrep paths.
4. **CWE Extraction & Semantic Taxonomy Matching (`matchCWEFamily`)**:
   * Snyk and OpenGrep use different rule IDs for the same vulnerability.
   * `main.go` parses numeric CWEs from SARIF `rule.properties` and OpenGrep `metadata.cwe`.
   * Maps related CWEs into 11 semantic security families:
     * **SQL Injection**: `CWE-89, 564, 943`
     * **Cross-Site Scripting (XSS)**: `CWE-79, 80, 83`
     * **Command / Code Injection**: `CWE-78, 77, 88, 94`
     * **Path Traversal / SSRF**: `CWE-22, 23, 36, 73, 918`
     * **Hardcoded Secrets / Credentials**: `CWE-798, 259, 321`
     * **Weak Cryptography / Hashing**: `CWE-327, 328, 330, 326, 916`
     * **Insecure Cookie / Session**: `CWE-614, 1004, 384`
     * **Information Exposure**: `CWE-200, 209, 215, 547`
     * **Type Juggling / Loose Comparison**: `CWE-697, 1025`
     * **Permissive CORS / Headers**: `CWE-346, 942`
     * **CSRF**: `CWE-352`
5. **Two-Pass Multi-Dimensional Matching Engine (`compareFindings`)**:
   * **Line Tolerance Window**: Configurable tolerance (default $\pm 2$ lines) and span overlap (`StartLine <= EndLine`).
   * **Confidence Ranking**:
     * **`HIGH`**: Same file, lines within tolerance, matching exact CWE or CWE taxonomy family.
     * **`MEDIUM`**: Exact line match fallback when one tool lacks CWE metadata.
     * **`LOW`**: Location-only proximity match.

---

## 5. How to Run the Go Program

### Compilation & Prerequisites
Ensure Go 1.18+ is installed:
```bash
go version
```

### Running with Default Relative Paths
When reports (`snyk-report.json`, `opengrep-dvwa-only-flags.json`, `opengrep-dvwa-auto.json`) are present in the current folder or `../DVWA`:

```bash
# 1. Tri-Report Executive Summary (compares Snyk against both OpenGrep modes):
go run main.go

# 2. Compare OpenGrep -f Flags directly against OpenGrep --config auto:
go run main.go -target opengrep

# 3. Compare Snyk vs OpenGrep -f Flags only:
go run main.go -target flags

# 4. Compare Snyk vs OpenGrep --config auto only:
go run main.go -target auto
```

### Running with Custom Relative Paths & Flags
```bash
go run main.go \
  -snyk snyk-report.json \
  -opengrep opengrep-dvwa-only-flags.json \
  -auto opengrep-dvwa-auto.json \
  -target both \
  -tolerance 2 \
  -mode smart \
  -verbose
```

### Sample Output: Tri-Report Executive Summary
```text
================================================================
        SECURITY SCANNER REPORT COMPARISON TOOL (GO)           
================================================================
Snyk SARIF Report       : snyk-report.json
OpenGrep (-f flags)     : opengrep-dvwa-only-flags.json
OpenGrep (--config auto): opengrep-dvwa-auto.json
Comparison Target       : both
Line Tolerance Window   : ±2 lines
Matching Mode           : smart

================================================================
         TRI-REPORT EXECUTIVE COMPARISON SUMMARY               
================================================================
Total Snyk Code Findings               : 105
Total OpenGrep Auto Findings           : 66
Total OpenGrep (-f Flags) Findings     : 108
----------------------------------------------------------------
Snyk Findings Correlated by Auto       : 27 / 105 (25.7%)
Snyk Findings Correlated by -f Flags   : 47 / 105 (44.8%)
Incremental Coverage with -f Flags     : +20 Snyk issues caught
================================================================
```
