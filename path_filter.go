package gosec

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/securego/gosec/v2/issue"
)

const (
	// ExcludeRulesSourceCLI marks path exclusion rules provided via the --exclude-rules flag.
	ExcludeRulesSourceCLI = "cli"
	// ExcludeRulesSourceConfig marks path exclusion rules provided through the configuration file.
	ExcludeRulesSourceConfig = "config"
	// excludeRulesSourceDefault is used when the origin of a rule cannot be determined.
	excludeRulesSourceDefault = "unknown"
)

// PathExcludeRule defines rules to exclude for specific file paths
type PathExcludeRule struct {
	Path   string   `json:"path"`             // Regex pattern for matching file paths
	Rules  []string `json:"rules"`            // Rule IDs to exclude. Use "*" to exclude all rules
	Source string   `json:"source,omitempty"` // Origin of the rule (cli or config)
}

// compiledPathRule is a pre-compiled version of PathExcludeRule for efficient matching
type compiledPathRule struct {
	pathRegex  *regexp.Regexp
	ruleSet    map[string]bool // Set of rule IDs to exclude
	excludeAll bool            // True if "*" was specified in rules
	source     string          // Origin of the rule (cli or config)
	original   PathExcludeRule // Keep original for error messages
}

// PathSuppression describes a single path-based exclusion that matched an issue.
type PathSuppression struct {
	RuleID string // Suppressed rule ID, or "*" when every rule is excluded for the path
	Path   string // Configured path regex responsible for the suppression
	Source string // Origin of the exclusion rule (cli or config)
}

// PathExclusionFilter handles filtering of issues based on path and rule combinations
type PathExclusionFilter struct {
	rules []compiledPathRule
}

// NewPathExclusionFilter creates a new filter from the provided exclusion rules.
// Returns an error if any path regex is invalid.
func NewPathExclusionFilter(rules []PathExcludeRule) (*PathExclusionFilter, error) {
	if len(rules) == 0 {
		return &PathExclusionFilter{rules: nil}, nil
	}

	compiled := make([]compiledPathRule, 0, len(rules))

	for i, rule := range rules {
		if rule.Path == "" {
			return nil, fmt.Errorf("exclude-rules[%d]: path cannot be empty", i)
		}

		regex, err := regexp.Compile(rule.Path)
		if err != nil {
			return nil, fmt.Errorf("exclude-rules[%d]: invalid path regex %q: %w", i, rule.Path, err)
		}

		ruleSet := make(map[string]bool)
		excludeAll := false

		for _, ruleID := range rule.Rules {
			ruleID = strings.TrimSpace(ruleID)
			if ruleID == "*" {
				excludeAll = true
			} else if ruleID != "" {
				ruleSet[ruleID] = true
			}
		}

		compiled = append(compiled, compiledPathRule{
			pathRegex:  regex,
			ruleSet:    ruleSet,
			excludeAll: excludeAll,
			source:     exclusionSource(rule.Source),
			original:   rule,
		})
	}

	return &PathExclusionFilter{rules: compiled}, nil
}

// exclusionSource normalizes the provenance of an exclusion rule, falling back
// to a stable value when the source was not recorded.
func exclusionSource(source string) string {
	if strings.TrimSpace(source) == "" {
		return excludeRulesSourceDefault
	}
	return source
}

// ShouldExclude returns true if the given issue should be excluded based on
// its file path and rule ID
func (f *PathExclusionFilter) ShouldExclude(filePath, ruleID string) bool {
	return len(f.MatchingSuppressions(filePath, ruleID)) > 0
}

// MatchingSuppressions returns every path exclusion rule that applies to the
// given file path and rule ID, in configuration order. Overlapping rules each
// produce their own entry so audits can trace every rule that suppressed a
// finding. A wildcard ("*") rule is reported with RuleID set to "*".
func (f *PathExclusionFilter) MatchingSuppressions(filePath, ruleID string) []PathSuppression {
	if f == nil || len(f.rules) == 0 {
		return nil
	}

	// Normalize path separators for consistent matching
	normalizedPath := strings.ReplaceAll(filePath, "\\", "/")

	var matches []PathSuppression
	for _, rule := range f.rules {
		if rule.pathRegex.MatchString(normalizedPath) {
			if rule.excludeAll {
				matches = append(matches, PathSuppression{
					RuleID: aliasOfAllRules,
					Path:   rule.original.Path,
					Source: rule.source,
				})
				continue
			}
			if rule.ruleSet[ruleID] {
				matches = append(matches, PathSuppression{
					RuleID: ruleID,
					Path:   rule.original.Path,
					Source: rule.source,
				})
			}
		}
	}

	return matches
}

// FilterIssues applies path-based exclusions to a slice of issues.
// Returns the filtered issues and the count of excluded issues.
func (f *PathExclusionFilter) FilterIssues(issues []*issue.Issue) ([]*issue.Issue, int) {
	if f == nil || len(f.rules) == 0 || len(issues) == 0 {
		return issues, 0
	}

	filtered := make([]*issue.Issue, 0, len(issues))
	excluded := 0

	for _, iss := range issues {
		if len(f.MatchingSuppressions(iss.File, iss.RuleID)) > 0 {
			excluded++
			continue
		}
		filtered = append(filtered, iss)
	}

	return filtered, excluded
}

// SuppressIssues annotates issues matched by path exclusion rules with external
// suppressions instead of dropping them. Every overlapping rule is recorded
// separately, carrying the suppressed rule ID, the path regex and the rule
// source. Issues without a match are left untouched. It returns the number of
// suppressed issues.
func (f *PathExclusionFilter) SuppressIssues(issues []*issue.Issue) int {
	if f == nil || len(f.rules) == 0 || len(issues) == 0 {
		return 0
	}

	suppressed := 0
	for _, iss := range issues {
		matches := f.MatchingSuppressions(iss.File, iss.RuleID)
		if len(matches) == 0 {
			continue
		}
		for _, match := range matches {
			iss.Suppressions = append(iss.Suppressions, issue.SuppressionInfo{
				Kind:          "external",
				Justification: pathSuppressionJustification(match),
				Rule:          match.RuleID,
				Path:          match.Path,
				Source:        match.Source,
			})
		}
		suppressed++
	}

	return suppressed
}

// pathSuppressionJustification renders a stable, human-readable justification
// for a path-based external suppression.
func pathSuppressionJustification(match PathSuppression) string {
	return fmt.Sprintf("Suppressed by exclude-rules (source: %s, path: %s, rule: %s).",
		match.Source, match.Path, match.RuleID)
}

// ParseCLIExcludeRules parses the CLI format for exclude-rules.
// Format: "path:rule1,rule2;path2:rule3,rule4"
// Example: "cmd/.*:G204,G304;test/.*:G101"
func ParseCLIExcludeRules(input string) ([]PathExcludeRule, error) {
	if input == "" {
		return nil, nil
	}

	var rules []PathExcludeRule

	// Split by semicolon for multiple rules
	parts := strings.Split(input, ";")

	for i, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Split by colon to separate path and rules
		colonIdx := strings.LastIndex(part, ":")
		if colonIdx == -1 {
			return nil, fmt.Errorf("exclude-rules part %d: missing ':' separator in %q", i+1, part)
		}

		pathPattern := strings.TrimSpace(part[:colonIdx])
		rulesPart := strings.TrimSpace(part[colonIdx+1:])

		if pathPattern == "" {
			return nil, fmt.Errorf("exclude-rules part %d: path pattern cannot be empty", i+1)
		}

		if rulesPart == "" {
			return nil, fmt.Errorf("exclude-rules part %d: rules list cannot be empty", i+1)
		}

		// Split rules by comma
		ruleIDs := strings.Split(rulesPart, ",")
		cleanedRules := make([]string, 0, len(ruleIDs))
		for _, r := range ruleIDs {
			r = strings.TrimSpace(r)
			if r != "" {
				cleanedRules = append(cleanedRules, r)
			}
		}

		if len(cleanedRules) == 0 {
			return nil, fmt.Errorf("exclude-rules part %d: no valid rules specified", i+1)
		}

		rules = append(rules, PathExcludeRule{
			Path:   pathPattern,
			Rules:  cleanedRules,
			Source: ExcludeRulesSourceCLI,
		})
	}

	return rules, nil
}

// MergeExcludeRules combines exclude rules from multiple sources (config file + CLI).
// CLI rules take precedence and are processed first.
func MergeExcludeRules(configRules, cliRules []PathExcludeRule) []PathExcludeRule {
	if len(cliRules) == 0 {
		return configRules
	}
	if len(configRules) == 0 {
		return cliRules
	}

	// CLI rules first, then config rules
	merged := make([]PathExcludeRule, 0, len(cliRules)+len(configRules))
	merged = append(merged, cliRules...)
	merged = append(merged, configRules...)
	return merged
}

// String returns a human-readable representation of the filter
func (f *PathExclusionFilter) String() string {
	if f == nil || len(f.rules) == 0 {
		return "PathExclusionFilter{empty}"
	}

	var parts []string
	for _, rule := range f.rules {
		if rule.excludeAll {
			parts = append(parts, fmt.Sprintf("%s:*", rule.original.Path))
		} else {
			ruleIDs := make([]string, 0, len(rule.ruleSet))
			for id := range rule.ruleSet {
				ruleIDs = append(ruleIDs, id)
			}
			parts = append(parts, fmt.Sprintf("%s:[%s]", rule.original.Path, strings.Join(ruleIDs, ",")))
		}
	}

	return fmt.Sprintf("PathExclusionFilter{%s}", strings.Join(parts, "; "))
}
