package investigation

import (
	"reflect"
	"strings"
	"testing"

	"github.com/jijo-OO7/chainrisk-lens/internal/analysis"
	"github.com/jijo-OO7/chainrisk-lens/internal/graph"
	"github.com/jijo-OO7/chainrisk-lens/internal/sbom"
)

type testEdge struct {
	from string
	to   string
}

func TestFromAnalysis(t *testing.T) {
	result := analyzeFixture(t,
		[]string{"target", "service", "worker"},
		[]testEdge{{from: "target", to: "service"}, {from: "service", to: "worker"}, {from: "worker", to: "target"}},
		"target",
	)

	evidence, err := FromAnalysis(result)
	if err != nil {
		t.Fatalf("FromAnalysis() error = %v", err)
	}
	want := Evidence{
		Target:   Component{BOMRef: "target", Name: "target", Version: "1"},
		Impacts: []Impact{
			{BOMRef: "service", Name: "service", Version: "1", Depth: 1, Path: []string{"target", "service"}},
			{BOMRef: "worker", Name: "worker", Version: "1", Depth: 2, Path: []string{"target", "service", "worker"}},
		},
		MaxDepth: 2,
		Cycle:    true,
	}
	if !reflect.DeepEqual(evidence, want) {
		t.Fatalf("FromAnalysis() = %#v, want %#v", evidence, want)
	}
	if err := evidence.Validate(); err != nil {
		t.Errorf("Evidence.Validate() error = %v", err)
	}
}

func TestFromAnalysisCopiesEvidence(t *testing.T) {
	result := analyzeFixture(t,
		[]string{"target", "dependent"},
		[]testEdge{{from: "target", to: "dependent"}},
		"target",
	)

	evidence, err := FromAnalysis(result)
	if err != nil {
		t.Fatal(err)
	}
	evidence.Impacts[0].Path[0] = "changed"
	if evidence.Impacts[0].Path[0] == result.Target.BOMRef {
		t.Fatal("test mutation did not change copied evidence path")
	}

	path, exists := result.PathTo("dependent")
	if !exists || path[0].BOMRef != "target" {
		t.Fatalf("mutating evidence changed analysis path: %#v, %t", path, exists)
	}
}

func TestFromAnalysisEquivalentResults(t *testing.T) {
	components := []string{"target", "alpha", "beta", "leaf"}
	edges := []testEdge{
		{from: "target", to: "beta"},
		{from: "target", to: "alpha"},
		{from: "beta", to: "leaf"},
		{from: "alpha", to: "leaf"},
	}
	first := analyzeFixture(t, components, edges, "target")
	second := analyzeFixture(t, reverseComponents(components), reverseEdges(edges), "target")

	firstEvidence, err := FromAnalysis(first)
	if err != nil {
		t.Fatal(err)
	}
	secondEvidence, err := FromAnalysis(second)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(firstEvidence, secondEvidence) {
		t.Fatalf("equivalent analyses produced different evidence:\n%#v\n%#v", firstEvidence, secondEvidence)
	}
	if !reflect.DeepEqual(firstEvidence.Impacts[2].Path, []string{"target", "alpha", "leaf"}) {
		t.Errorf("canonical path = %v, want [target alpha leaf]", firstEvidence.Impacts[2].Path)
	}
}

func TestEvidenceValidateRejectsInvalidEvidence(t *testing.T) {
	valid := Evidence{
		Target:   Component{BOMRef: "target"},
		Impacts:  []Impact{{BOMRef: "dependent", Depth: 1, Path: []string{"target", "dependent"}}},
		MaxDepth: 1,
	}
	tests := []struct {
		name     string
		mutate   func(*Evidence)
		wantPart string
	}{
		{
			name:     "missing target BOMRef",
			mutate:   func(evidence *Evidence) { evidence.Target.BOMRef = "" },
			wantPart: "target BOM-REF is empty",
		},
		{
			name:     "missing impact BOMRef",
			mutate:   func(evidence *Evidence) { evidence.Impacts[0].BOMRef = "" },
			wantPart: "impact BOM-REF is empty",
		},
		{
			name:     "target included as impact",
			mutate:   func(evidence *Evidence) { evidence.Impacts[0].BOMRef = "target" },
			wantPart: "must not appear in impacts",
		},
		{
			name:     "empty path",
			mutate:   func(evidence *Evidence) { evidence.Impacts[0].Path = nil },
			wantPart: "empty path",
		},
		{
			name:     "path starts elsewhere",
			mutate:   func(evidence *Evidence) { evidence.Impacts[0].Path[0] = "other" },
			wantPart: "does not begin at the target",
		},
		{
			name:     "path ends elsewhere",
			mutate:   func(evidence *Evidence) { evidence.Impacts[0].Path[1] = "other" },
			wantPart: "does not end at the impact",
		},
		{
			name:     "invalid depth",
			mutate:   func(evidence *Evidence) { evidence.Impacts[0].Depth = 0 },
			wantPart: "invalid depth",
		},
		{
			name:     "path depth mismatch",
			mutate:   func(evidence *Evidence) { evidence.Impacts[0].Depth = 2 },
			wantPart: "does not match path length",
		},
		{
			name:     "max depth mismatch",
			mutate:   func(evidence *Evidence) { evidence.MaxDepth = 2 },
			wantPart: "does not match impacts max depth",
		},
		{
			name: "duplicate impact",
			mutate: func(evidence *Evidence) {
				evidence.Impacts = append(evidence.Impacts, evidence.Impacts[0])
			},
			wantPart: "duplicate impact BOM-REF",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evidence := cloneEvidence(valid)
			test.mutate(&evidence)
			if err := evidence.Validate(); err == nil || !strings.Contains(err.Error(), test.wantPart) {
				t.Fatalf("Validate() error = %v, want error containing %q", err, test.wantPart)
			}
		})
	}
}

func TestEvidenceValidateAllowsNoImpacts(t *testing.T) {
	evidence := Evidence{Target: Component{BOMRef: "target"}, Impacts: []Impact{}, MaxDepth: 0}
	if err := evidence.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestResultValidateRequiresTraceableFindings(t *testing.T) {
	evidence := Evidence{
		Target:   Component{BOMRef: "target"},
		Impacts:  []Impact{{BOMRef: "dependent", Depth: 1, Path: []string{"target", "dependent"}}},
		MaxDepth: 1,
	}
	valid := Result{Findings: []Finding{{
		Statement: "The dependent is potentially exposed through the supplied path.",
		Evidence:  []EvidenceRef{{BOMRefs: []string{"target", "dependent"}}},
	}}}
	if err := valid.Validate(evidence); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	tests := []struct {
		name     string
		result   Result
		wantPart string
	}{
		{
			name:     "missing evidence reference",
			result:   Result{Findings: []Finding{{Statement: "A claim."}}},
			wantPart: "no evidence references",
		},
		{
			name: "unknown BOMRef",
			result: Result{Findings: []Finding{{
				Statement: "A claim.", Evidence: []EvidenceRef{{BOMRefs: []string{"not-supplied"}}},
			}}},
			wantPart: "not present in supplied evidence",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.result.Validate(evidence); err == nil || !strings.Contains(err.Error(), test.wantPart) {
				t.Fatalf("Validate() error = %v, want error containing %q", err, test.wantPart)
			}
		})
	}
}

func analyzeFixture(t *testing.T, componentRefs []string, edges []testEdge, target string) analysis.Analysis {
	t.Helper()
	document := sbom.SBOM{
		Components: make([]sbom.Component, 0, len(componentRefs)),
	}
	for _, bomRef := range componentRefs {
		document.Components = append(document.Components, sbom.Component{
			BOMRef: bomRef, Name: bomRef, Version: "1",
		})
	}
	for _, edge := range edges {
		document.Dependencies = append(document.Dependencies, sbom.Dependency{
			Ref: edge.to, DependsOn: []string{edge.from},
		})
	}
	dependencyGraph, err := graph.New(document)
	if err != nil {
		t.Fatalf("graph.New() error = %v", err)
	}
	result, err := analysis.Analyze(dependencyGraph, target)
	if err != nil {
		t.Fatalf("analysis.Analyze() error = %v", err)
	}
	return result
}

func cloneEvidence(evidence Evidence) Evidence {
	clone := evidence
	clone.Impacts = make([]Impact, len(evidence.Impacts))
	for i, impact := range evidence.Impacts {
		clone.Impacts[i] = impact
		clone.Impacts[i].Path = append([]string(nil), impact.Path...)
	}
	return clone
}

func reverseComponents(values []string) []string {
	reversed := make([]string, len(values))
	for i, value := range values {
		reversed[len(values)-1-i] = value
	}
	return reversed
}

func reverseEdges(values []testEdge) []testEdge {
	reversed := make([]testEdge, len(values))
	for i, value := range values {
		reversed[len(values)-1-i] = value
	}
	return reversed
}

