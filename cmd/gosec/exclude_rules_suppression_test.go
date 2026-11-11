package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
	jsonreport "github.com/securego/gosec/v2/report/json"
	"github.com/securego/gosec/v2/report/sarif"
	"github.com/securego/gosec/v2/rules"
)

const (
	excludedCredentialSource = `package main

import "fmt"

func main() {
	password := "f62e5bcda4fae4f82370da0c6f20697b8f8447ef"
	fmt.Println(password)
}
`

	nosecCredentialSource = `package main

import "fmt"

func main() {
	password := "f62e5bcda4fae4f82370da0c6f20697b8f8447ef" // #nosec G101 -- test fixture
	fmt.Println(password)
}
`

	openCredentialSource = `package main

import "fmt"

func main() {
	password := "f62e5bcda4fae4f82370da0c6f20697b8f8447ef"
	fmt.Println(password)
}
`
)

// newMixedExclusionFixture creates a small module with a path-suppressed
// finding, a #nosec-suppressed finding and an unsuppressed finding.
func newMixedExclusionFixture(t FullGinkgoTInterface) string {
	root := t.TempDir()
	Expect(os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/exclusionfixture\n\ngo 1.24\n"), 0o600)).To(Succeed())
	files := map[string]string{
		filepath.Join("cmd", "tool", "main.go"): excludedCredentialSource,
		filepath.Join("internal", "nosec.go"):   nosecCredentialSource,
		filepath.Join("pkg", "open.go"):         openCredentialSource,
	}
	for relativePath, content := range files {
		fullPath := filepath.Join(root, relativePath)
		Expect(os.MkdirAll(filepath.Dir(fullPath), 0o755)).To(Succeed())
		Expect(os.WriteFile(fullPath, []byte(content), 0o600)).To(Succeed())
	}
	return root
}

func runMixedFixtureAnalyzer(t FullGinkgoTInterface, root string, trackSuppressions bool, excludeRuleIDs ...string) ([]*issue.Issue, *gosec.Metrics) {
	config := gosec.NewConfig()
	logger := log.New(io.Discard, "", 0)
	analyzer := gosec.NewAnalyzer(config, false, false, trackSuppressions, 1, logger)

	var filters []rules.RuleFilter
	if len(excludeRuleIDs) > 0 {
		filters = append(filters, rules.NewRuleFilter(true, excludeRuleIDs...))
	}
	analyzer.LoadRules(rules.Generate(trackSuppressions, filters...).RulesInfo())

	packagePaths, err := gosec.PackagePaths(filepath.Join(root, "..."), nil)
	Expect(err).NotTo(HaveOccurred())
	Expect(packagePaths).To(HaveLen(3))
	Expect(analyzer.Process(nil, packagePaths...)).To(Succeed())
	issues, metrics, scanErrors := analyzer.Report()
	Expect(scanErrors).To(BeEmpty())
	return issues, metrics
}

func buildMixedPathFilter() *gosec.PathExclusionFilter {
	rulesList := []gosec.PathExcludeRule{
		{Path: "^.*/cmd/.*", Rules: []string{"G101"}, Source: gosec.ExcludeRulesSourceCLI},
		{Path: "^.*/cmd/.*", Rules: []string{"*"}, Source: gosec.ExcludeRulesSourceConfig},
	}
	filter, err := gosec.NewPathExclusionFilter(rulesList)
	Expect(err).NotTo(HaveOccurred())
	return filter
}

func issueByFile(issues []*issue.Issue, suffix string) *issue.Issue {
	for _, iss := range issues {
		if filepathMatch(iss.File, suffix) {
			return iss
		}
	}
	return nil
}

func filepathMatch(path, suffix string) bool {
	normalized := filepath.ToSlash(path)
	return len(normalized) >= len(suffix) && normalized[len(normalized)-len(suffix):] == suffix
}

var _ = Describe("path-based external suppressions", func() {
	var root string

	BeforeEach(func() {
		root = newMixedExclusionFixture(GinkgoT())
	})

	It("keeps path exclusions auditable when suppression tracking is enabled", func() {
		issues, _ := runMixedFixtureAnalyzer(GinkgoT(), root, true)
		Expect(issues).To(HaveLen(3))

		pathFilter := buildMixedPathFilter()
		suppressedCount := pathFilter.SuppressIssues(issues)
		Expect(suppressedCount).To(Equal(1))
		Expect(issues).To(HaveLen(3))

		pathIssue := issueByFile(issues, "cmd/tool/main.go")
		Expect(pathIssue).NotTo(BeNil())
		Expect(pathIssue.RuleID).To(Equal("G101"))
		Expect(pathIssue.Suppressions).To(HaveLen(2))

		// First rule: CLI specific G101 exclusion.
		Expect(pathIssue.Suppressions[0].Kind).To(Equal("external"))
		Expect(pathIssue.Suppressions[0].Rule).To(Equal("G101"))
		Expect(pathIssue.Suppressions[0].Path).To(Equal("^.*/cmd/.*"))
		Expect(pathIssue.Suppressions[0].Source).To(Equal(gosec.ExcludeRulesSourceCLI))

		// Second overlapping rule: config wildcard exclusion.
		Expect(pathIssue.Suppressions[1].Kind).To(Equal("external"))
		Expect(pathIssue.Suppressions[1].Rule).To(Equal("*"))
		Expect(pathIssue.Suppressions[1].Path).To(Equal("^.*/cmd/.*"))
		Expect(pathIssue.Suppressions[1].Source).To(Equal(gosec.ExcludeRulesSourceConfig))

		// #nosec semantics are unchanged and do not gain path suppressions.
		nosecIssue := issueByFile(issues, "internal/nosec.go")
		Expect(nosecIssue).NotTo(BeNil())
		Expect(nosecIssue.Suppressions).To(HaveLen(1))
		Expect(nosecIssue.Suppressions[0].Kind).To(Equal("inSource"))

		// Unmatched findings remain active findings.
		openIssue := issueByFile(issues, "pkg/open.go")
		Expect(openIssue).NotTo(BeNil())
		Expect(openIssue.Suppressions).To(BeEmpty())
	})

	It("still drops path exclusions from the report when tracking is disabled", func() {
		issues, _ := runMixedFixtureAnalyzer(GinkgoT(), root, false)
		// Without tracking the analyzer already drops the #nosec finding; the
		// path filter keeps its legacy job of removing path-excluded findings.
		Expect(issues).To(HaveLen(2))

		pathFilter := buildMixedPathFilter()
		filtered, excluded := pathFilter.FilterIssues(issues)
		Expect(excluded).To(Equal(1))
		Expect(filtered).To(HaveLen(1))
		Expect(issueByFile(filtered, "cmd/tool/main.go")).To(BeNil())
		Expect(issueByFile(filtered, "pkg/open.go")).NotTo(BeNil())
	})

	It("does not interfere with globally excluded rules", func() {
		issues, _ := runMixedFixtureAnalyzer(GinkgoT(), root, true, "G101")
		Expect(issues).To(HaveLen(3))

		for _, iss := range issues {
			Expect(iss.Suppressions).NotTo(BeEmpty())
			last := iss.Suppressions[len(iss.Suppressions)-1]
			Expect(last.Kind).To(Equal("external"))
			Expect(last.Justification).To(Equal("Globally suppressed."))
		}

		// The #nosec finding keeps its in-source suppression alongside the
		// global one; path exclusions must not alter that semantics.
		nosecIssue := issueByFile(issues, "internal/nosec.go")
		Expect(nosecIssue.Suppressions[0].Kind).To(Equal("inSource"))

		pathFilter := buildMixedPathFilter()
		Expect(pathFilter.SuppressIssues(issues)).To(Equal(1))

		pathIssue := issueByFile(issues, "cmd/tool/main.go")
		// Global external suppression plus the two overlapping path rules.
		Expect(pathIssue.Suppressions).To(HaveLen(3))
		Expect(pathIssue.Suppressions[1].Source).To(Equal(gosec.ExcludeRulesSourceCLI))
		Expect(pathIssue.Suppressions[2].Source).To(Equal(gosec.ExcludeRulesSourceConfig))

		Expect(computeExitCode(issues, map[string][]gosec.Error{}, false)).To(Equal(exitSuccess))
	})

	It("renders path suppressions in JSON and SARIF reports while the exit code stays successful", func() {
		issues, metrics := runMixedFixtureAnalyzer(GinkgoT(), root, true)
		pathFilter := buildMixedPathFilter()
		Expect(pathFilter.SuppressIssues(issues)).To(Equal(1))

		filtered, trueIssues := filterIssues(issues, issue.Low, issue.Low)
		metrics.NumFound = trueIssues
		// One unsuppressed finding remains, so the scan still fails by default.
		Expect(trueIssues).To(Equal(1))
		Expect(computeExitCode(filtered, map[string][]gosec.Error{}, false)).To(Equal(exitFailure))

		reportInfo := gosec.NewReportInfo(filtered, metrics, map[string][]gosec.Error{})

		jsonBuffer := new(bytes.Buffer)
		Expect(jsonreport.WriteReport(jsonBuffer, reportInfo)).To(Succeed())

		var jsonReport map[string]interface{}
		Expect(json.Unmarshal(jsonBuffer.Bytes(), &jsonReport)).To(Succeed())
		jsonIssues := jsonReport["Issues"].([]interface{})
		Expect(jsonIssues).To(HaveLen(3))

		var pathSuppression map[string]interface{}
		for _, rawIssue := range jsonIssues {
			reportedIssue := rawIssue.(map[string]interface{})
			if filepathMatch(reportedIssue["file"].(string), "cmd/tool/main.go") {
				suppressions := reportedIssue["suppressions"].([]interface{})
				Expect(suppressions).To(HaveLen(2))
				pathSuppression = suppressions[0].(map[string]interface{})
			}
		}
		Expect(pathSuppression).NotTo(BeNil())
		Expect(pathSuppression["kind"]).To(Equal("external"))
		Expect(pathSuppression["rule"]).To(Equal("G101"))
		Expect(pathSuppression["path"]).To(Equal("^.*/cmd/.*"))
		Expect(pathSuppression["source"]).To(Equal("cli"))

		sarifReport, err := sarif.GenerateReport([]string{root}, reportInfo)
		Expect(err).NotTo(HaveOccurred())

		var foundPathSuppression bool
		for _, result := range sarifReport.Runs[0].Results {
			for _, suppression := range result.Suppressions {
				if suppression.Properties == nil {
					continue
				}
				if (*suppression.Properties)["source"] == "cli" && (*suppression.Properties)["path"] == "^.*/cmd/.*" {
					foundPathSuppression = true
				}
			}
		}
		Expect(foundPathSuppression).To(BeTrue())

		// Once every finding is suppressed the scan must report success, even
		// when path exclusions are the reason it was suppressed.
		for _, iss := range filtered {
			iss.Suppressions = append(iss.Suppressions, issue.SuppressionInfo{Kind: "external", Justification: "test"})
		}
		Expect(computeExitCode(filtered, map[string][]gosec.Error{}, false)).To(Equal(exitSuccess))
	})
})
