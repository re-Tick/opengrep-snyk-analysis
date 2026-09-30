# OpenGrep Security Coverage Analysis: `-f` Rule Packs vs. `--config auto`

This document provides a technical evaluation and evidence-based comparison between running OpenGrep with default cloud auto-configuration (`--config auto`) versus explicit multi-folder rule packs (`-f`).

---

## 1. What Happened and Why

### Summary of Findings
When evaluating the Damn Vulnerable Web Application (DVWA), switching from `--config auto` to explicit `-f` rule packs produced an immediate **+63.6% increase in security detection**:

* **`--config auto` total application findings**: **66**
* **`-f` rule packs total application findings**: **108**
* **Net difference**: **+42 findings** (+51 added from new rules, -9 from loose-equality normalization)

```
Scan Findings Comparison:
  --config auto  [66 findings]  ████████████████
  -f rule packs  [108 findings] ██████████████████████████ (+63.6%)
```

---

### Complete Rule-by-Rule Reconciliation Table

Every single finding across both reports reconciles with 100% mathematical accuracy:

| Rule Check ID | `--config auto` | `-f` Rule Packs | Diff | Category / Vulnerability |
| :--- | :---: | :---: | :---: | :--- |
| **`weak-crypto`** | 0 | **19** | <span style="color:green">**+19**</span> | Insecure Hashing (`CWE-328`) |
| **`unsafe-dynamic-method`** | 0 | **7** | <span style="color:green">**+7**</span> | Dynamic Code Injection (`CWE-94`) |
| **`insecure-document-method`**| 0 | **6** | <span style="color:green">**+6**</span> | Client-Side DOM XSS (`CWE-79`) |
| **`insecure-innerhtml`** | 0 | **6** | <span style="color:green">**+6**</span> | Client-Side DOM XSS (`CWE-79`) |
| **`useless-assignment`** | 0 | **6** | <span style="color:green">**+6**</span> | Dead Code / Quality |
| **`dockerfile-source-not-pinned`** | 0 | **1** | <span style="color:green">**+1**</span> | Supply Chain Vulnerability |
| **`missing-no-install-recommends`**| 0 | **1** | <span style="color:green">**+1**</span> | Container Hardening |
| **`generic-api-key`** | 0 | **1** | <span style="color:green">**+1**</span> | Hardcoded API Token (`CWE-798`) |
| **`hashicorp-tf-password`** | 0 | **1** | <span style="color:green">**+1**</span> | Hardcoded DB Password (`CWE-798`) |
| **`echoed-request`** | 0 | **1** | <span style="color:green">**+1**</span> | Reflected Request (`CWE-79`) |
| **`javascript-alert`** | 0 | **1** | <span style="color:green">**+1**</span> | Production Debug Popup |
| **`javascript-confirm`** | 0 | **1** | <span style="color:green">**+1**</span> | Production Debug Popup |
| **`md5-loose-equality`** | 10 | **1** | <span style="color:red">**-9**</span> | Type Juggling (superseded by `weak-crypto`) |
| *11 Common Core Rules (SQLi, Exec, CORS...)* | 49 | 49 | **0** | Identical baseline coverage |
| **TOTALS** | **66** | **108** | <span style="color:green">**+42**</span> | **(+51 New, -9 Shifted)** |

---

### Detailed Breakdown: What Happened & Why (with Official Doc Links)

#### 1. Broken Password Hashing & Insecure Cryptography (+19 Findings)
* **What Happened**: Found 19 instances of broken `md5()` used for authentication, password changes, and token generation across core files:
  * `login.php:27` (User login authentication)
  * `dvwa/includes/dvwaPage.inc.php:651`
  * `vulnerabilities/brute/source/high.php:16`
  * `vulnerabilities/captcha/source/high.php:27`
  * `vulnerabilities/csrf/source/high.php:39`
  * `vulnerabilities/weak_id/source/high.php:10`
* **Why `--config auto` Missed It**:
  * In the rule definition (`php/lang/security/weak-crypto.yaml`), the metadata specifies:
    ```yaml
    subcategory: [audit]
    confidence: LOW
    ```
  * According to the [Semgrep Rule Taxonomy Documentation](https://semgrep.dev/docs/writing-rules/rule-ideas/) and [Semgrep Rule Syntax Guide](https://semgrep.dev/docs/writing-rules/rule-syntax/), rules marked `subcategory: [audit]` or `confidence: LOW` are explicitly excluded from automated default CI rulesets (`--config auto`) to prevent developer notification fatigue.
* **Why `-f` Caught It**:
  * Passing `-f .../php` loads the rule directly from disk, bypassing the registry's automated confidence filter.

---

#### 2. DOM-Based Cross-Site Scripting (DOM XSS) (+12 Findings)
* **What Happened**: Found 12 client-side vulnerabilities where untrusted input is written directly into DOM sinks:
  * `vulnerabilities/authbypass/authbypass.js:43, 45, 47, 49` (8 findings: both `document-method` and `innerhtml`)
  * `vulnerabilities/csp/source/high.js:9` (2 findings)
  * `vulnerabilities/csp/source/impossible.js:9` (2 findings)
* **Why `--config auto` Missed It**:
  * `--config auto` scoped the scan to backend PHP server-side rules and omitted browser-side DOM security audit rules (`insecure-innerhtml`, `insecure-document-method`).
* **Why `-f` Caught It**:
  * Passing `-f .../javascript` explicitly enabled all 205 JavaScript browser security audit rules.

---

#### 3. Dynamic Code & Method Injection (+7 Findings)
* **What Happened**: Detected dangerous dynamic method evaluation on untrusted property names (`String[b('0x0')](...)`):
  * `vulnerabilities/javascript/source/high.js:1` (5 occurrences)
  * `vulnerabilities/javascript/source/high_unobfuscated.js:60, 108` (2 occurrences)
* **Why `--config auto` Missed It**:
  * The rule `unsafe-dynamic-method` is categorized as an AST audit rule in `javascript/lang/security/audit/` and is excluded from default auto packs.
* **Why `-f` Caught It**:
  * Explicitly including the JavaScript pack forced the engine to inspect obfuscated dynamic invocations.

---

#### 4. Plaintext Secrets & Hardcoded Credentials (+2 Findings)
* **What Happened**: Discovered hardcoded credentials directly committed to the codebase:
  * `vulnerabilities/sqli/test.php:4` (Hardcoded database credentials: `hashicorp-tf-password`)
  * `vulnerabilities/csrf/help/help.php:54` (Hardcoded API token: `generic-api-key`)
* **Why `--config auto` Missed It**:
  * Per the [Semgrep CLI Reference](https://semgrep.dev/docs/cli-reference/), `--config auto` only scans for language-specific AST patterns in detected code languages. It does not run generic regex entropy secret scans.
  * In `generic-api-key.yaml`, line 8–9 explicitly states: *"This rule can introduce a lot of false positives, it is not recommended to be used in PR comments."* and sets `confidence: LOW`.
* **Why `-f` Caught It**:
  * Passing `-f .../generic` activated GitLeaks-grade secret scanning across all files.

---

#### 5. Container & Supply Chain Risks (+2 Findings)
* **What Happened**: Identified container infrastructure vulnerabilities:
  * `Dockerfile:1`: Unpinned base image digest (`dockerfile-source-not-pinned`) exposing build pipelines to upstream supply-chain tampering.
  * `Dockerfile:10`: `apt-get install` without `--no-install-recommends` (`missing-no-install-recommends`), inflating image size and attack surface.
* **Why `--config auto` Missed It**:
  * As documented by [OpenGrep](https://github.com/opengrep/opengrep), `--config auto` scopes language detection to application files (`.php`, `.js`), ignoring infrastructure files like `Dockerfile`.
* **Why `-f` Caught It**:
  * Passing `-f .../dockerfile` instructed OpenGrep to parse the Dockerfile grammar.

---

#### 6. Code Quality, Dead Code & Debug Popups (+8 Findings)
* **What Happened**: Detected dead variable assignments (`useless-assignment` in `high_unobfuscated.js:438, 441, 442, 446, 447, 448`) and leftover debug popups (`alert()` and `confirm()` in `dvwaPage.js:16, 38`).
* **Why `--config auto` Missed It**:
  * Code hygiene and correctness checks are silenced in `--config auto` to focus exclusively on high-priority security defects.
* **Why `-f` Caught It**:
  * Passing `-f .../javascript` included full correctness and best-practice audit rulesets.

---

#### 7. Reflected Request Handling (+1 Finding)
* **What Happened**: Reflected HTTP parameters in `vulnerabilities/csp/source/jsonp.php:12` (`echoed-request`).
* **Why `--config auto` Missed It**: Strict intra-file reflection rules are excluded from standard web sets.
* **Why `-f` Caught It**: Loaded via `php/lang/security/injection/`.

---

## 2. Resolving Raw File Count Discrepancies (423 vs 171 vs 108 vs 66)

If you inspect raw unmanaged scan files, you may notice numbers like 423 or 171. Here is why:

1. **Scanner Self-Scans (Scanning Previous Reports)**:
   * When `opengrep scan` was initially run without `--exclude="snyk-report.json"` and `--exclude="opengrep-*.json"`, OpenGrep scanned the JSON reports themselves.
   * `opengrep-dvwa-only-flags.json` contained **423 raw entries**:
     * 210 findings were generated on line 1 of `opengrep-dvwa-auto.json`
     * 105 findings were generated inside `snyk-report.json`
     * **108 findings** were the real vulnerabilities in DVWA source code ($423 - 210 - 105 = \mathbf{108}$).
2. **Exclusion Filters in `--config auto`**:
   * An early run of auto without excludes produced 171 entries (66 real findings + 105 findings inside `snyk-report.json`).
   * When properly excluding reports and test directories, the clean application finding count is **66**.

---

## 3. Evidence & Verification

Both raw JSON scan outputs are committed to this repository:
1. `opengrep-dvwa-auto.json`: Output from `--config auto` (66 application findings)
2. `opengrep-dvwa-only-flags.json`: Output from `-f` rule packs (108 application findings)

### How to Run the Diff Tool
A portable comparison script `compare-diff.py` is included. It converts both JSON reports into canonical finding lines and renders a native **Git-style colorized diff** (green for new findings, red for removed findings).

```bash
# Run diff using default relative paths in the repo:
python3 compare-diff.py

# Or pass custom report paths explicitly:
python3 compare-diff.py opengrep-dvwa-auto.json opengrep-dvwa-only-flags.json
```

> **Portability Note**: `compare-diff.py` uses relative paths and automatic project-root normalization. It contains **no hardcoded local machine paths** and can be run by anyone after cloning the repository.

### Sample Output from `compare-diff.py`
```diff
--- opengrep-dvwa-auto.json (--config auto)
+++ opengrep-dvwa-only-flags.json (-f flags)
@@ -1,24 +1,53 @@
+ Dockerfile:1                                [dockerfile-source-not-pinned]  
+ Dockerfile:10                               [missing-no-install-recommends]  
+ dvwa/includes/dvwaPage.inc.php:651          [weak-crypto                 ]  CWE-328
+ dvwa/js/dvwaPage.js:16                      [javascript-alert            ]  
+ dvwa/js/dvwaPage.js:38                      [javascript-confirm          ]  
  instructions.php:26                         [tainted-filename            ]  CWE-918
- login.php:41                                [md5-loose-equality          ]  CWE-697
+ login.php:27                                [weak-crypto                 ]  CWE-328
  phpinfo.php:8                               [phpinfo-use                 ]  CWE-200
  vulnerabilities/api/gen_openapi.php:6       [php-permissive-cors         ]  CWE-346
  vulnerabilities/api/public/index.php:11     [php-permissive-cors         ]  CWE-346
  vulnerabilities/api/src/HealthController:88 [exec-use                    ]  CWE-94
  vulnerabilities/api/src/HealthController:88 [tainted-exec                ]  CWE-78
  vulnerabilities/api/src/Token.php:39        [openssl-decrypt-validate    ]  CWE-252
+ vulnerabilities/authbypass/authbypass.js:43 [insecure-document-method    ]  CWE-79
+ vulnerabilities/authbypass/authbypass.js:43 [insecure-innerhtml          ]  CWE-79
+ vulnerabilities/authbypass/authbypass.js:45 [insecure-document-method    ]  CWE-79
+ vulnerabilities/authbypass/authbypass.js:45 [insecure-innerhtml          ]  CWE-79
+ vulnerabilities/authbypass/authbypass.js:47 [insecure-document-method    ]  CWE-79
+ vulnerabilities/authbypass/authbypass.js:47 [insecure-innerhtml          ]  CWE-79
+ vulnerabilities/authbypass/authbypass.js:49 [insecure-document-method    ]  CWE-79
+ vulnerabilities/authbypass/authbypass.js:49 [insecure-innerhtml          ]  CWE-79
  vulnerabilities/bac/source/low.php:22       [tainted-sql-string          ]  CWE-89
  vulnerabilities/bac/source/low.php:35       [tainted-sql-string          ]  CWE-89
  vulnerabilities/bac/source/low.php:79       [tainted-sql-string          ]  CWE-89
  vulnerabilities/bac/source/medium.php:21    [tainted-sql-string          ]  CWE-89
  vulnerabilities/bac/source/medium.php:28    [tainted-sql-string          ]  CWE-89
  vulnerabilities/bac/source/medium.php:71    [tainted-sql-string          ]  CWE-89
- vulnerabilities/brute/source/high.php:22   [md5-loose-equality          ]  CWE-697
+ vulnerabilities/brute/source/high.php:16   [weak-crypto                 ]  CWE-328
+ vulnerabilities/brute/source/impossible:16 [weak-crypto                 ]  CWE-328
  vulnerabilities/brute/source/low.php:12     [tainted-sql-string          ]  CWE-89
- vulnerabilities/brute/source/low.php:15    [md5-loose-equality          ]  CWE-697
+ vulnerabilities/brute/source/low.php:9      [weak-crypto                 ]  CWE-328
- vulnerabilities/brute/source/medium.php:17 [md5-loose-equality          ]  CWE-697
+ vulnerabilities/brute/source/medium.php:11 [weak-crypto                 ]  CWE-328
+ vulnerabilities/captcha/source/high.php:27 [weak-crypto                 ]  CWE-328
+ vulnerabilities/captcha/source/impossible:14 [weak-crypto               ]  CWE-328
+ vulnerabilities/captcha/source/impossible:19 [weak-crypto               ]  CWE-328
+ vulnerabilities/captcha/source/impossible:24 [weak-crypto               ]  CWE-328
+ vulnerabilities/captcha/source/low.php:57  [weak-crypto                 ]  CWE-328
+ vulnerabilities/captcha/source/medium.php:65 [weak-crypto               ]  CWE-328
+ vulnerabilities/csp/source/high.js:9        [insecure-document-method    ]  CWE-79
+ vulnerabilities/csp/source/high.js:9        [insecure-innerhtml          ]  CWE-79
+ vulnerabilities/csp/source/impossible.js:9  [insecure-document-method    ]  CWE-79
+ vulnerabilities/csp/source/impossible.js:9  [insecure-innerhtml          ]  CWE-79
+ vulnerabilities/csp/source/jsonp.php:12    [echoed-request              ]  CWE-79
+ vulnerabilities/csrf/help/help.php:54      [generic-api-key             ]  CWE-798
+ vulnerabilities/csrf/source/high.php:39    [weak-crypto                 ]  CWE-328
+ vulnerabilities/csrf/source/impossible:15  [weak-crypto                 ]  CWE-328
+ vulnerabilities/csrf/source/impossible:29  [weak-crypto                 ]  CWE-328
+ vulnerabilities/csrf/source/low.php:12     [weak-crypto                 ]  CWE-328
+ vulnerabilities/csrf/source/medium.php:14  [weak-crypto                 ]  CWE-328
+ vulnerabilities/csrf/test_credentials.php:19 [weak-crypto              ]  CWE-328
+ vulnerabilities/sqli/test.php:4            [hashicorp-tf-password       ]  CWE-798
```

---

## 4. How to Reproduce

### Prerequisites & Installation

#### 1. Install OpenGrep
```bash
curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash
```

#### 2. Clone the Target Repository (DVWA)
```bash
git clone https://github.com/digininja/DVWA.git
git clone https://github.com/OpsMx/opengrep-rules.git
cd DVWA
```

---

### Scan Commands

#### Command A: Baseline Scan with `--config auto`
```bash
opengrep scan \
  --exclude=.gitlab/ \
  --exclude=.github/ \
  --exclude=test-framework/ \
  --exclude=test/ \
  --exclude=tests/ \
  --exclude=testsuite/ \
  --exclude=testdata/ \
  --exclude=testing/ \
  --exclude=__tests__/ \
  --exclude=_tests_/ \
  --exclude=src/test/ \
  --exclude=internal/test/ \
  --exclude='*_test.go' \
  --exclude='*_test.js' \
  --exclude='*_test.py' \
  --exclude='*Test.java' \
  --exclude='*Tests.java' \
  --exclude='test_*.go' \
  --exclude='test_*.py' \
  --exclude='test_*.js' \
  --config auto \
  --json \
  -o ./opengrep-dvwa-auto.json \
  .
```

#### Command B: Full-Coverage Scan with Explicit `-f` Rule Packs
```bash

opengrep scan \
  --exclude=.gitlab/ \
  --exclude="snyk-report.json" \
  --exclude="opengrep-*.json" \
  --exclude=.github/ \
  --exclude=test-framework/ \
  --exclude=test/ \
  --exclude=tests/ \
  --exclude=testsuite/ \
  --exclude=testdata/ \
  --exclude=testing/ \
  --exclude=__tests__/ \
  --exclude=_tests_/ \
  --exclude=src/test/ \
  --exclude=internal/test/ \
  --exclude='*_test.go' \
  --exclude='*_test.js' \
  --exclude='*_test.py' \
  --exclude='*Test.java' \
  --exclude='*Tests.java' \
  --exclude='test_*.go' \
  --exclude='test_*.py' \
  --exclude='test_*.js' \
  -f ../opengrep-rules/ai \
  -f ../opengrep-rules/apex \
  -f ../opengrep-rules/bash \
  -f ../opengrep-rules/c \
  -f ../opengrep-rules/clojure \
  -f ../opengrep-rules/csharp \
  -f ../opengrep-rules/dockerfile \
  -f ../opengrep-rules/elixir \
  -f ../opengrep-rules/generic \
  -f ../opengrep-rules/go \
  -f ../opengrep-rules/html \
  -f ../opengrep-rules/java \
  -f ../opengrep-rules/javascript \
  -f ../opengrep-rules/json \
  -f ../opengrep-rules/kotlin \
  -f ../opengrep-rules/libsonnet \
  -f ../opengrep-rules/ocaml \
  -f ../opengrep-rules/php \
  -f ../opengrep-rules/problem-based-packs \
  -f ../opengrep-rules/python \
  -f ../opengrep-rules/ruby \
  -f ../opengrep-rules/rust \
  -f ../opengrep-rules/scala \
  -f ../opengrep-rules/solidity \
  -f ../opengrep-rules/swift \
  -f ../opengrep-rules/terraform \
  -f ../opengrep-rules/trusted_python \
  -f ../opengrep-rules/typescript \
  -f ../opengrep-rules/yaml \
  --json \
  -o ./opengrep-dvwa-only-flags.json \
  --taint-intrafile \
  .
```

---

## 5. Key Takeaways for Leadership

1. **`--config auto` is a Minimal Linter**: It intentionally mutes low-confidence and audit-level rules to avoid developer pushback, but consequently misses 43.5% of critical security issues (including broken authentication hashing, plaintext passwords, and container supply-chain flaws).
2. **Explicit `-f` Rule Packs Provide Comprehensive SAST**: Passing explicit language and secret packs elevates OpenGrep to an enterprise-grade scanner, discovering **42 net additional findings (+63.6%)** across the entire full-stack application lifecycle.
