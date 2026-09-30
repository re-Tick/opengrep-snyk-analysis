#!/usr/bin/env python3
import json
import subprocess
import sys
import os

def norm(path):
    path = path.replace("\\", "/")
    # Normalize common project root patterns or relative paths
    for marker in ["/DVWA/", "DVWA/"]:
        if marker in path:
            return path.split(marker)[-1]
    # If it is an absolute path, retain relative to last directory
    parts = path.strip("/").split("/")
    if len(parts) > 2 and parts[0] in ["home", "Users", "var", "tmp"]:
        return "/".join(parts[-2:])
    return path.lstrip("./")

def extract_findings_list(report_path):
    if not os.path.exists(report_path):
        print(f"Error: report file not found at '{report_path}'", file=sys.stderr)
        print("Usage: python3 compare-diff.py [path/to/auto.json] [path/to/flags.json]", file=sys.stderr)
        sys.exit(1)
        
    with open(report_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Exclude scanner self-scans (snyk-report.json and opengrep-*.json)
    results = [r for r in data.get("results", []) 
               if not any(x in r.get("path", "") for x in ["snyk-report", "opengrep-"])]

    lines = []
    for r in results:
        fpath = norm(r.get("path", ""))
        line = r.get("start", {}).get("line", 0)
        rule = r.get("check_id", "").split(".")[-1]
        cwe = r.get("extra", {}).get("metadata", {}).get("cwe", [])
        cwe_str = cwe[0].split(":")[0] if cwe else ""
        lines.append(f"{fpath}:{line:<4d}  [{rule:<28s}]  {cwe_str}")

    return sorted(list(set(lines)))

def find_default_file(filename):
    # Check current working directory, script directory, and common subfolders
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        filename,
        os.path.join(".", filename),
        os.path.join(".", "reports", filename),
        os.path.join(script_dir, filename),
        os.path.join(script_dir, "reports", filename),
        os.path.join(script_dir, "..", "DVWA", filename),
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return filename

def main():
    default_auto = find_default_file("opengrep-dvwa-auto.json")
    default_flags = find_default_file("opengrep-dvwa-only-flags.json")

    auto_file = sys.argv[1] if len(sys.argv) > 1 else default_auto
    flags_file = sys.argv[2] if len(sys.argv) > 2 else default_flags

    auto_lines = extract_findings_list(auto_file)
    flags_lines = extract_findings_list(flags_file)

    tmp_auto = "/tmp/auto_findings.txt"
    tmp_flags = "/tmp/flags_findings.txt"

    with open(tmp_auto, "w", encoding="utf-8") as f:
        f.write("\n".join(auto_lines) + "\n")

    with open(tmp_flags, "w", encoding="utf-8") as f:
        f.write("\n".join(flags_lines) + "\n")

    label_auto = f"{os.path.basename(auto_file)} (--config auto)"
    label_flags = f"{os.path.basename(flags_file)} (-f flags)"

    # Run git diff with color support
    cmd = [
        "git", "diff", "--no-index",
        "--color=always",
        f"--src-prefix=a/{label_auto}/",
        f"--dst-prefix=b/{label_flags}/",
        tmp_auto, tmp_flags
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.stdout:
        print(result.stdout)
    else:
        cmd_plain = ["diff", "-u", tmp_auto, tmp_flags]
        res_plain = subprocess.run(cmd_plain, capture_output=True, text=True)
        print(res_plain.stdout)

if __name__ == "__main__":
    main()
