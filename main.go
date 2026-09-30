package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// CWE Family groupings for cross-scanner semantic equivalence
var cweFamilies = [][]int{
	{89, 564, 943},            // SQL Injection
	{79, 80, 83},              // Cross-Site Scripting (XSS)
	{78, 77, 88, 94},          // Command / Code Injection
	{22, 23, 36, 73, 918},     // Path Traversal / File Inclusion / SSRF
	{798, 259, 321},           // Hardcoded Secrets / Credentials
	{327, 328, 330, 326, 916}, // Weak Cryptography / Hash
	{614, 1004, 384},          // Insecure Cookie / Session
	{200, 209, 215, 547},      // Sensitive Information Exposure
	{697, 1025},               // Incorrect Comparison / Type Juggling
	{346, 942},                // Permissive CORS / Header misconfiguration
	{352},                     // Cross-Site Request Forgery (CSRF)
}

var cweRegex = regexp.MustCompile(`(?i)CWE-(\d+)`)

// UnifiedFinding represents a normalized finding from either tool
type UnifiedFinding struct {
	ID        int
	Tool      string
	File      string
	StartLine int
	EndLine   int
	StartCol  int
	EndCol    int
	RuleID    string
	CWEs      []int
	Message   string
	Severity  string
}

// SARIF Schema Structs (used by Snyk)
type SarifReport struct {
	Runs []SarifRun `json:"runs"`
}

type SarifRun struct {
	Tool struct {
		Driver struct {
			Rules []SarifRule `json:"rules"`
		} `json:"driver"`
	} `json:"tool"`
	Results []SarifResult `json:"results"`
}

type SarifRule struct {
	ID         string          `json:"id"`
	Properties json.RawMessage `json:"properties"`
}

type SarifResult struct {
	RuleID    string `json:"ruleId"`
	RuleIndex int    `json:"ruleIndex"`
	Level     string `json:"level"`
	Message   struct {
		Text string `json:"text"`
	} `json:"message"`
	Locations []struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
			Region struct {
				StartLine   int `json:"startLine"`
				EndLine     int `json:"endLine"`
				StartColumn int `json:"startColumn"`
				EndColumn   int `json:"endColumn"`
			} `json:"region"`
		} `json:"physicalLocation"`
	} `json:"locations"`
}

// OpenGrep Schema Structs
type OpenGrepReport struct {
	Results []OpenGrepResult `json:"results"`
}

type OpenGrepResult struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   struct {
		Line int `json:"line"`
		Col  int `json:"col"`
	} `json:"start"`
	End struct {
		Line int `json:"line"`
		Col  int `json:"col"`
	} `json:"end"`
	Extra struct {
		Message  string          `json:"message"`
		Severity string          `json:"severity"`
		Metadata json.RawMessage `json:"metadata"`
	} `json:"extra"`
}

// MatchResult stores a pair of matching findings with the confidence level
type MatchResult struct {
	Snyk     UnifiedFinding
	OpenGrep UnifiedFinding
	Level    string // HIGH, MEDIUM, LOW
	Reason   string
}

// resolveFilePath searches for a file using relative paths and common directory fallbacks
func resolveFilePath(given string, defaultCandidates ...string) (string, error) {
	candidates := []string{}
	if strings.TrimSpace(given) != "" {
		candidates = append(candidates, given)
	}
	candidates = append(candidates, defaultCandidates...)

	searchDirs := []string{
		".",
		"reports",
		"../DVWA",
		"../../DVWA",
		"../compare-opengrep-snyk",
		"../compare-opengrep-reports",
	}

	for _, cand := range candidates {
		if _, err := os.Stat(cand); err == nil {
			return cand, nil
		}
		for _, dir := range searchDirs {
			p := filepath.Join(dir, cand)
			if _, err := os.Stat(p); err == nil {
				return p, nil
			}
		}
	}
	return "", fmt.Errorf("file not found: %s (searched candidates: %v across %v)", given, candidates, searchDirs)
}

func main() {
	snykPathFlag := flag.String("snyk", "snyk-report.json", "Relative or absolute path to Snyk SARIF JSON report")
	ogFlagsPathFlag := flag.String("opengrep", "opengrep-dvwa-only-flags.json", "Relative or absolute path to OpenGrep -f flags JSON report")
	ogAutoPathFlag := flag.String("auto", "opengrep-dvwa-auto.json", "Relative or absolute path to OpenGrep --config auto JSON report")
	target := flag.String("target", "both", "Comparison target: 'flags' (Snyk vs OpenGrep -f), 'auto' (Snyk vs OpenGrep auto), 'both' (compare both OpenGreps against Snyk), 'opengrep' (OpenGrep flags vs auto)")
	lineTolerance := flag.Int("tolerance", 2, "Line number window tolerance (+/- lines)")
	mode := flag.String("mode", "smart", "Matching mode: 'smart' (CWE + exact line fallback), 'cwe' (strict CWE match), 'location' (file + line only)")
	verbose := flag.Bool("verbose", false, "Show verbose matched pairs details")
	flag.Parse()

	// Resolve relative paths
	snykPath, snykErr := resolveFilePath(*snykPathFlag, "snyk-report.json")
	ogFlagsPath, flagsErr := resolveFilePath(*ogFlagsPathFlag, "opengrep-dvwa-only-flags.json", "opengrep-dvwa-only-flags-multi-files.json")
	ogAutoPath, autoErr := resolveFilePath(*ogAutoPathFlag, "opengrep-dvwa-auto.json", "opengrep-dvwa-auto-multi-file.json")

	fmt.Println("================================================================")
	fmt.Println("        SECURITY SCANNER REPORT COMPARISON TOOL (GO)           ")
	fmt.Println("================================================================")
	if snykErr == nil {
		fmt.Printf("Snyk SARIF Report       : %s\n", snykPath)
	}
	if flagsErr == nil {
		fmt.Printf("OpenGrep (-f flags)     : %s\n", ogFlagsPath)
	}
	if autoErr == nil {
		fmt.Printf("OpenGrep (--config auto): %s\n", ogAutoPath)
	}
	fmt.Printf("Comparison Target       : %s\n", *target)
	fmt.Printf("Line Tolerance Window   : ±%d lines\n", *lineTolerance)
	fmt.Printf("Matching Mode           : %s\n\n", *mode)

	// Mode 1: OpenGrep Flags vs Auto direct comparison
	if *target == "opengrep" {
		if flagsErr != nil || autoErr != nil {
			fmt.Fprintf(os.Stderr, "Error: need both OpenGrep reports for 'opengrep' comparison mode\n")
			os.Exit(1)
		}
		runOpenGrepComparison(ogFlagsPath, ogAutoPath)
		return
	}

	// Validate Snyk report
	if snykErr != nil {
		fmt.Fprintf(os.Stderr, "Error locating Snyk report: %v\n", snykErr)
		os.Exit(1)
	}
	snykFindings, err := loadSnykFindings(snykPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading Snyk report: %v\n", err)
		os.Exit(1)
	}

	// Execute comparison based on target
	if *target == "auto" {
		if autoErr != nil {
			fmt.Fprintf(os.Stderr, "Error locating OpenGrep auto report: %v\n", autoErr)
			os.Exit(1)
		}
		ogAuto, err := loadOpenGrepFindings(ogAutoPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading OpenGrep auto report: %v\n", err)
			os.Exit(1)
		}
		runSnykVsOpenGrep("OpenGrep (--config auto)", snykFindings, ogAuto, *lineTolerance, *mode, *verbose)
		return
	}

	if *target == "flags" {
		if flagsErr != nil {
			fmt.Fprintf(os.Stderr, "Error locating OpenGrep flags report: %v\n", flagsErr)
			os.Exit(1)
		}
		ogFlags, err := loadOpenGrepFindings(ogFlagsPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading OpenGrep flags report: %v\n", err)
			os.Exit(1)
		}
		runSnykVsOpenGrep("OpenGrep (-f rule packs)", snykFindings, ogFlags, *lineTolerance, *mode, *verbose)
		return
	}

	// Default: "both" — Compare Snyk against Auto, then against Flags, and show summary
	if flagsErr == nil && autoErr == nil {
		ogAuto, err := loadOpenGrepFindings(ogAutoPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading OpenGrep auto report: %v\n", err)
			os.Exit(1)
		}
		ogFlags, err := loadOpenGrepFindings(ogFlagsPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading OpenGrep flags report: %v\n", err)
			os.Exit(1)
		}

		matchesAuto, _, _ := compareFindings(snykFindings, ogAuto, *lineTolerance, *mode)
		matchesFlags, _, _ := compareFindings(snykFindings, ogFlags, *lineTolerance, *mode)

		fmt.Println("================================================================")
		fmt.Println("         TRI-REPORT EXECUTIVE COMPARISON SUMMARY               ")
		fmt.Println("================================================================")
		fmt.Printf("Total Snyk Code Findings               : %d\n", len(snykFindings))
		fmt.Printf("Total OpenGrep Auto Findings           : %d\n", len(ogAuto))
		fmt.Printf("Total OpenGrep (-f Flags) Findings     : %d\n", len(ogFlags))
		fmt.Println("----------------------------------------------------------------")
		fmt.Printf("Snyk Findings Correlated by Auto       : %d / %d (%.1f%%)\n",
			len(matchesAuto), len(snykFindings), float64(len(matchesAuto))/float64(len(snykFindings))*100)
		fmt.Printf("Snyk Findings Correlated by -f Flags   : %d / %d (%.1f%%)\n",
			len(matchesFlags), len(snykFindings), float64(len(matchesFlags))/float64(len(snykFindings))*100)
		fmt.Printf("Incremental Coverage with -f Flags     : +%d Snyk issues caught\n",
			len(matchesFlags)-len(matchesAuto))
		fmt.Println("================================================================\n")

		// Detailed print of Snyk vs OpenGrep -f
		runSnykVsOpenGrep("OpenGrep (-f rule packs)", snykFindings, ogFlags, *lineTolerance, *mode, *verbose)
		return
	}

	// Fallback to flags
	if flagsErr == nil {
		ogFlags, _ := loadOpenGrepFindings(ogFlagsPath)
		runSnykVsOpenGrep("OpenGrep (-f rule packs)", snykFindings, ogFlags, *lineTolerance, *mode, *verbose)
	}
}

// runSnykVsOpenGrep executes the correlation between Snyk and a specific OpenGrep report
func runSnykVsOpenGrep(ogLabel string, snykFindings, ogFindings []UnifiedFinding, lineTol int, mode string, verbose bool) {
	fmt.Printf("Loaded %d findings from Snyk Code\n", len(snykFindings))
	fmt.Printf("Loaded %d findings from %s\n\n", len(ogFindings), ogLabel)

	matches, uncommonSnyk, uncommonOG := compareFindings(snykFindings, ogFindings, lineTol, mode)

	fmt.Println("================================================================")
	fmt.Printf("          SUMMARY STATISTICS: Snyk vs %s\n", ogLabel)
	fmt.Println("================================================================")
	fmt.Printf("Total Snyk findings        : %d\n", len(snykFindings))
	fmt.Printf("Total %s findings: %d\n", ogLabel, len(ogFindings))
	fmt.Printf("Matched Snyk findings      : %d (%.1f%% of Snyk)\n",
		len(snykFindings)-len(uncommonSnyk),
		float64(len(snykFindings)-len(uncommonSnyk))/float64(len(snykFindings))*100)
	fmt.Printf("Matched OpenGrep findings  : %d (%.1f%% of %s)\n",
		len(ogFindings)-len(uncommonOG),
		float64(len(ogFindings)-len(uncommonOG))/float64(len(ogFindings))*100, ogLabel)
	fmt.Printf("Total Correlated Match Pairs: %d\n", len(matches))
	fmt.Printf("Uncommon Snyk findings     : %d\n", len(uncommonSnyk))
	fmt.Printf("Uncommon OpenGrep findings : %d\n\n", len(uncommonOG))

	// Matched Findings
	fmt.Println("================================================================")
	fmt.Printf("COMMON / MATCHED FINDINGS (%d pairs)\n", len(matches))
	fmt.Println("================================================================")
	for i, m := range matches {
		fmt.Printf("[%3d] [%-6s] %s (Snyk L%d / OG L%d)\n",
			i+1, m.Level, m.Snyk.File, m.Snyk.StartLine, m.OpenGrep.StartLine)
		fmt.Printf("      Snyk     : %s (CWEs: %v)\n", m.Snyk.RuleID, formatCWEs(m.Snyk.CWEs))
		fmt.Printf("      OpenGrep : %s (CWEs: %v)\n", m.OpenGrep.RuleID, formatCWEs(m.OpenGrep.CWEs))
		fmt.Printf("      Match    : %s\n", m.Reason)
		if verbose {
			fmt.Printf("      Snyk Msg : %s\n", truncate(m.Snyk.Message, 80))
			fmt.Printf("      OG Msg   : %s\n", truncate(m.OpenGrep.Message, 80))
		}
		fmt.Println()
	}

	// Uncommon Snyk Findings
	fmt.Println("================================================================")
	fmt.Printf("UNCOMMON SNYK FINDINGS (%d findings)\n", len(uncommonSnyk))
	fmt.Println("================================================================")
	for i, f := range uncommonSnyk {
		fmt.Printf("[%3d] %s:%d\t%-35s\tCWEs: %v\n",
			i+1, f.File, f.StartLine, f.RuleID, formatCWEs(f.CWEs))
	}
	fmt.Println()

	// Uncommon OpenGrep Findings
	fmt.Println("================================================================")
	fmt.Printf("UNCOMMON %s FINDINGS (%d findings)\n", strings.ToUpper(ogLabel), len(uncommonOG))
	fmt.Println("================================================================")
	for i, f := range uncommonOG {
		fmt.Printf("[%3d] %s:%d\t%-35s\tCWEs: %v\n",
			i+1, f.File, f.StartLine, f.RuleID, formatCWEs(f.CWEs))
	}
}

// runOpenGrepComparison directly compares OpenGrep Flags vs OpenGrep Auto
func runOpenGrepComparison(flagsPath, autoPath string) {
	flagsFindings, err := loadOpenGrepFindings(flagsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading flags report: %v\n", err)
		return
	}
	autoFindings, err := loadOpenGrepFindings(autoPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading auto report: %v\n", err)
		return
	}

	// Canonical rule key: File:Line:Col:CanonicalRule
	keyCol := func(f UnifiedFinding) string {
		rule := f.RuleID
		if idx := strings.LastIndex(rule, "."); idx >= 0 {
			rule = rule[idx+1:]
		}
		return fmt.Sprintf("%s:%d:%d:%s", f.File, f.StartLine, f.StartCol, rule)
	}

	flagsMap := make(map[string]UnifiedFinding)
	for _, f := range flagsFindings {
		flagsMap[keyCol(f)] = f
	}

	autoMap := make(map[string]UnifiedFinding)
	for _, f := range autoFindings {
		autoMap[keyCol(f)] = f
	}

	var commonCount int
	var flagsOnly []UnifiedFinding
	var autoOnly []UnifiedFinding

	for k, f := range flagsMap {
		if _, ok := autoMap[k]; ok {
			commonCount++
		} else {
			flagsOnly = append(flagsOnly, f)
		}
	}
	for k, f := range autoMap {
		if _, ok := flagsMap[k]; !ok {
			autoOnly = append(autoOnly, f)
		}
	}

	fmt.Println("================================================================")
	fmt.Println("   OPENGREP DIRECT COMPARISON: -f Rule Packs vs --config auto   ")
	fmt.Println("================================================================")
	fmt.Printf("Total Findings in -f Rule Packs report    : %d\n", len(flagsFindings))
	fmt.Printf("Total Findings in --config auto report    : %d\n", len(autoFindings))
	fmt.Printf("Common Findings (Identical rule & location): %d\n", commonCount)
	fmt.Printf("Unique Findings in -f Rule Packs (+New)   : %d\n", len(flagsOnly))
	fmt.Printf("Unique Findings in --config auto (-Shifted): %d\n", len(autoOnly))
	fmt.Printf("Net Coverage Increase                     : +%d findings (+%.1f%%)\n",
		len(flagsFindings)-len(autoFindings),
		float64(len(flagsFindings)-len(autoFindings))/float64(len(autoFindings))*100)
	fmt.Println("================================================================")
}

// loadOpenGrepFindings parses an OpenGrep JSON file and filters self-scans
func loadOpenGrepFindings(path string) ([]UnifiedFinding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var report OpenGrepReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, err
	}

	findings := make([]UnifiedFinding, 0, len(report.Results))
	for i, r := range report.Results {
		// Filter scanner self-scans on previous reports
		if strings.Contains(r.Path, "snyk-report") || strings.Contains(r.Path, "opengrep-") {
			continue
		}
		cwes := extractCWEsFromRaw(r.Extra.Metadata)
		findings = append(findings, UnifiedFinding{
			ID:        i,
			Tool:      "OpenGrep",
			File:      normalizePath(r.Path),
			StartLine: r.Start.Line,
			EndLine:   r.End.Line,
			StartCol:  r.Start.Col,
			EndCol:    r.End.Col,
			RuleID:    r.CheckID,
			CWEs:      cwes,
			Message:   r.Extra.Message,
		})
	}
	return findings, nil
}

// loadSnykFindings parses a Snyk SARIF JSON file
func loadSnykFindings(path string) ([]UnifiedFinding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var report SarifReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, err
	}

	if len(report.Runs) == 0 {
		return nil, fmt.Errorf("no runs found in SARIF report")
	}

	run := report.Runs[0]
	rulesMap := make(map[string][]int)

	// Map rules to their CWEs
	for _, rule := range run.Tool.Driver.Rules {
		cwes := extractCWEsFromRaw(rule.Properties)
		rulesMap[rule.ID] = cwes
	}

	findings := make([]UnifiedFinding, 0, len(run.Results))
	for i, res := range run.Results {
		if len(res.Locations) == 0 {
			continue
		}
		loc := res.Locations[0].PhysicalLocation
		uri := loc.ArtifactLocation.URI
		reg := loc.Region

		endLine := reg.EndLine
		if endLine == 0 {
			endLine = reg.StartLine
		}

		cwes := rulesMap[res.RuleID]

		findings = append(findings, UnifiedFinding{
			ID:        i,
			Tool:      "Snyk",
			File:      normalizePath(uri),
			StartLine: reg.StartLine,
			EndLine:   endLine,
			StartCol:  reg.StartColumn,
			EndCol:    reg.EndColumn,
			RuleID:    res.RuleID,
			CWEs:      cwes,
			Message:   res.Message.Text,
			Severity:  res.Level,
		})
	}
	return findings, nil
}

// normalizePath standardizes relative path separators and removes workspace prefixes
func normalizePath(path string) string {
	path = filepath.ToSlash(path)

	// Common prefix cleanups (e.g., repository roots)
	if idx := strings.Index(path, "/DVWA/"); idx >= 0 {
		path = path[idx+len("/DVWA/"):]
	} else if strings.HasPrefix(path, "DVWA/") {
		path = strings.TrimPrefix(path, "DVWA/")
	}

	path = strings.TrimPrefix(path, "./")
	path = strings.TrimPrefix(path, "/")
	return path
}

// extractCWEsFromRaw extracts CWE IDs (integers) from arbitrary JSON bytes
func extractCWEsFromRaw(raw json.RawMessage) []int {
	if len(raw) == 0 {
		return nil
	}
	matches := cweRegex.FindAllStringSubmatch(string(raw), -1)
	if len(matches) == 0 {
		return nil
	}

	seen := make(map[int]bool)
	var cwes []int
	for _, m := range matches {
		if len(m) > 1 {
			if id, err := strconv.Atoi(m[1]); err == nil && !seen[id] {
				cwes = append(cwes, id)
				seen[id] = true
			}
		}
	}
	sort.Ints(cwes)
	return cwes
}

// evaluateMatch determines if a Snyk finding and OpenGrep finding represent the same issue
func evaluateMatch(snyk, og UnifiedFinding, lineTol int, mode string) (matched bool, level string, reason string) {
	// 1. File path must match
	if snyk.File != og.File {
		return false, "", ""
	}

	// 2. Line distance check
	lineDiff := int(math.Abs(float64(snyk.StartLine - og.StartLine)))
	linesOverlap := (snyk.StartLine <= og.EndLine && og.StartLine <= snyk.EndLine)
	withinTolerance := lineDiff <= lineTol || linesOverlap

	if !withinTolerance {
		return false, "", ""
	}

	// Location-only mode
	if mode == "location" {
		return true, "LOW", fmt.Sprintf("Line distance %d (Tolerance ±%d)", lineDiff, lineTol)
	}

	// 3. Taxonomy match: Exact CWE overlap
	commonCWEs := intersect(snyk.CWEs, og.CWEs)
	if len(commonCWEs) > 0 {
		return true, "HIGH", fmt.Sprintf("Shared CWE: %v (Line diff %d)", formatCWEs(commonCWEs), lineDiff)
	}

	// 4. Taxonomy match: CWE Family / Category overlap
	if sharedFamily := matchCWEFamily(snyk.CWEs, og.CWEs); sharedFamily != "" {
		return true, "HIGH", fmt.Sprintf("CWE Family match: %s (Line diff %d)", sharedFamily, lineDiff)
	}

	// If mode is strictly CWE, reject non-CWE matches
	if mode == "cwe" {
		return false, "", ""
	}

	// 5. Smart Fallback: If either scanner lacks CWE metadata, allow exact line match
	if lineDiff == 0 && (len(snyk.CWEs) == 0 || len(og.CWEs) == 0) {
		return true, "MEDIUM", fmt.Sprintf("Exact line match (L%d), missing CWE metadata in one tool", snyk.StartLine)
	}

	return false, "", ""
}

// compareFindings performs cross-tool correlation
func compareFindings(snykFindings, ogFindings []UnifiedFinding, lineTol int, mode string) ([]MatchResult, []UnifiedFinding, []UnifiedFinding) {
	matchedSnykIdx := make(map[int]bool)
	matchedOGIdx := make(map[int]bool)
	var matches []MatchResult

	// Two-pass matching: Pass 1 favors HIGH confidence matches first
	passes := []string{"HIGH", "MEDIUM", "LOW"}

	for _, targetLevel := range passes {
		for i, sf := range snykFindings {
			if matchedSnykIdx[i] && targetLevel != "HIGH" {
				continue
			}

			for j, of := range ogFindings {
				if matchedOGIdx[j] && targetLevel != "HIGH" {
					continue
				}

				matched, level, reason := evaluateMatch(sf, of, lineTol, mode)
				if matched && level == targetLevel {
					matchedSnykIdx[i] = true
					matchedOGIdx[j] = true
					matches = append(matches, MatchResult{
						Snyk:     sf,
						OpenGrep: of,
						Level:    level,
						Reason:   reason,
					})
					break
				}
			}
		}
	}

	// Collect uncommon findings
	var uncommonSnyk []UnifiedFinding
	for i, sf := range snykFindings {
		if !matchedSnykIdx[i] {
			uncommonSnyk = append(uncommonSnyk, sf)
		}
	}

	var uncommonOG []UnifiedFinding
	for j, of := range ogFindings {
		if !matchedOGIdx[j] {
			uncommonOG = append(uncommonOG, of)
		}
	}

	// Sort results for consistent output
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Snyk.File != matches[j].Snyk.File {
			return matches[i].Snyk.File < matches[j].Snyk.File
		}
		return matches[i].Snyk.StartLine < matches[j].Snyk.StartLine
	})

	sort.Slice(uncommonSnyk, func(i, j int) bool {
		if uncommonSnyk[i].File != uncommonSnyk[j].File {
			return uncommonSnyk[i].File < uncommonSnyk[j].File
		}
		return uncommonSnyk[i].StartLine < uncommonSnyk[j].StartLine
	})

	sort.Slice(uncommonOG, func(i, j int) bool {
		if uncommonOG[i].File != uncommonOG[j].File {
			return uncommonOG[i].File < uncommonOG[j].File
		}
		return uncommonOG[i].StartLine < uncommonOG[j].StartLine
	})

	return matches, uncommonSnyk, uncommonOG
}

// Helpers
func intersect(a, b []int) []int {
	m := make(map[int]bool)
	for _, x := range a {
		m[x] = true
	}
	var res []int
	for _, x := range b {
		if m[x] {
			res = append(res, x)
		}
	}
	return res
}

func matchCWEFamily(cwes1, cwes2 []int) string {
	for _, family := range cweFamilies {
		has1, has2 := false, false
		for _, c1 := range cwes1 {
			for _, f := range family {
				if c1 == f {
					has1 = true
					break
				}
			}
		}
		for _, c2 := range cwes2 {
			for _, f := range family {
				if c2 == f {
					has2 = true
					break
				}
			}
		}
		if has1 && has2 {
			return fmt.Sprintf("Family group %v", family)
		}
	}
	return ""
}

func formatCWEs(cwes []int) string {
	if len(cwes) == 0 {
		return "None"
	}
	var list []string
	for _, c := range cwes {
		list = append(list, fmt.Sprintf("CWE-%d", c))
	}
	return strings.Join(list, ", ")
}

func truncate(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > maxLen {
		return s[:maxLen-3] + "..."
	}
	return s
}
