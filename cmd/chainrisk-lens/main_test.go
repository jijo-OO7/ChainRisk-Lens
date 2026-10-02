package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jijo-OO7/chainrisk-lens/internal/analysis"
	"github.com/jijo-OO7/chainrisk-lens/internal/graph"
	"github.com/jijo-OO7/chainrisk-lens/internal/investigation"
	"github.com/jijo-OO7/chainrisk-lens/internal/sbom"
)

type fakeInvestigator struct {
	request  investigation.Request
	evidence investigation.Evidence
	result   investigation.Result
	err      error
	calls    int
}

func (investigator *fakeInvestigator) Investigate(_ context.Context, request investigation.Request, evidence investigation.Evidence) (investigation.Result, error) {
	investigator.calls++
	investigator.request = request
	investigator.evidence = evidence
	return investigator.result, investigator.err
}

func TestRunSuccessfulAnalysis(t *testing.T) {
	sbomPath := writeSBOM(t, sbom.SBOM{
		Components: []sbom.Component{
			{BOMRef: "library-ref", Name: "library", Version: "1.0.0"},
			{BOMRef: "service-ref", Name: "service", Version: "2.1.0"},
		},
		Dependencies: []sbom.Dependency{{Ref: "service-ref", DependsOn: []string{"library-ref"}}},
	})

	var output bytes.Buffer
	if err := run([]string{"analyze", sbomPath, "--target", "library-ref"}, &output); err != nil {
		t.Fatalf("run() error = %v", err)
	}

	for _, want := range []string{
		"Compromised Target",
		"Name: library",
		"Potentially affected dependents: 1",
		"Depth 1 - Direct Dependents",
		"service@2.1.0",
		"Path: library@1.0.0 -> service@2.1.0",
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("report does not contain %q:\n%s", want, output.String())
		}
	}
	if strings.Contains(output.String(), "Depth 0") {
		t.Errorf("report presents the target as an impact:\n%s", output.String())
	}
}

func TestRunExplicitHumanFormatMatchesDefault(t *testing.T) {
	sbomPath := writeSBOM(t, sbom.SBOM{
		Components: []sbom.Component{{BOMRef: "target", Name: "target", Version: "1"}},
	})

	var defaultOutput, explicitOutput bytes.Buffer
	if err := run([]string{"analyze", sbomPath, "--target", "target"}, &defaultOutput); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"analyze", sbomPath, "--target", "target", "--format", "human"}, &explicitOutput); err != nil {
		t.Fatal(err)
	}
	if defaultOutput.String() != explicitOutput.String() {
		t.Fatalf("explicit human output differs from default:\n--- default ---\n%s\n--- explicit ---\n%s", defaultOutput.String(), explicitOutput.String())
	}
}

func TestRunJSONFormat(t *testing.T) {
	sbomPath := writeSBOM(t, sbom.SBOM{
		Components: []sbom.Component{
			{BOMRef: "target-ref", Name: "library", Version: "1.0.0"},
			{BOMRef: "service-ref", Name: "service", Version: "2.1.0"},
			{BOMRef: "worker-ref", Name: "worker", Version: "3.0.0"},
		},
		Dependencies: []sbom.Dependency{
			{Ref: "service-ref", DependsOn: []string{"target-ref"}},
			{Ref: "worker-ref", DependsOn: []string{"service-ref"}},
		},
	})

	var separatedOutput, equalsOutput bytes.Buffer
	if err := run([]string{"analyze", sbomPath, "--target", "target-ref", "--format", "json"}, &separatedOutput); err != nil {
		t.Fatalf("run(--format json) error = %v", err)
	}
	if err := run([]string{"analyze", sbomPath, "--target", "target-ref", "--format=json"}, &equalsOutput); err != nil {
		t.Fatalf("run(--format=json) error = %v", err)
	}
	if separatedOutput.String() != equalsOutput.String() {
		t.Fatalf("equivalent JSON format arguments produced different output:\n%s\n%s", separatedOutput.String(), equalsOutput.String())
	}
	if strings.HasPrefix(separatedOutput.String(), "ChainRisk Lens") {
		t.Fatalf("JSON output contains a human-readable heading: %s", separatedOutput.String())
	}

	var report jsonReport
	if err := json.Unmarshal(separatedOutput.Bytes(), &report); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, separatedOutput.String())
	}
	if report.Target != (jsonComponent{BOMRef: "target-ref", Name: "library", Version: "1.0.0"}) {
		t.Errorf("target = %#v, want target component serialized separately", report.Target)
	}
	wantImpacts := []jsonImpact{
		{
			BOMRef: "service-ref", Name: "service", Version: "2.1.0", Depth: 1,
			Path: []string{"target-ref", "service-ref"},
		},
		{
			BOMRef: "worker-ref", Name: "worker", Version: "3.0.0", Depth: 2,
			Path: []string{"target-ref", "service-ref", "worker-ref"},
		},
	}
	if !reflect.DeepEqual(report.Impacts, wantImpacts) {
		t.Errorf("impacts = %#v, want %#v", report.Impacts, wantImpacts)
	}
	for _, impact := range report.Impacts {
		if impact.BOMRef == report.Target.BOMRef {
			t.Errorf("target %q appears in impacts", report.Target.BOMRef)
		}
	}
	if report.MaxDepth != 2 || report.Cycle {
		t.Errorf("maxDepth/cycle = %d/%t, want 2/false", report.MaxDepth, report.Cycle)
	}
}

func TestRunJSONIsolatedTargetAndCycle(t *testing.T) {
	tests := []struct {
		name        string
		document    sbom.SBOM
		target      string
		wantImpacts []jsonImpact
		wantMax     int
		wantCycle   bool
	}{
		{
			name: "isolated target",
			document: sbom.SBOM{
				Components: []sbom.Component{{BOMRef: "target", Name: "target", Version: "1"}},
			},
			target:      "target",
			wantImpacts: []jsonImpact{},
		},
		{
			name: "reachable cycle",
			document: sbom.SBOM{
				Components: []sbom.Component{
					{BOMRef: "target", Name: "target", Version: "1"},
					{BOMRef: "dependent", Name: "dependent", Version: "2"},
				},
				Dependencies: []sbom.Dependency{
					{Ref: "target", DependsOn: []string{"dependent"}},
					{Ref: "dependent", DependsOn: []string{"target"}},
				},
			},
			target: "target",
			wantImpacts: []jsonImpact{{
				BOMRef: "dependent", Name: "dependent", Version: "2", Depth: 1,
				Path: []string{"target", "dependent"},
			}},
			wantMax:   1,
			wantCycle: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sbomPath := writeSBOM(t, test.document)
			var output bytes.Buffer
			if err := run([]string{"analyze", sbomPath, "--target", test.target, "--format=json"}, &output); err != nil {
				t.Fatalf("run() error = %v", err)
			}

			var report jsonReport
			if err := json.Unmarshal(output.Bytes(), &report); err != nil {
				t.Fatalf("output is not valid JSON: %v", err)
			}
			if !reflect.DeepEqual(report.Impacts, test.wantImpacts) {
				t.Errorf("impacts = %#v, want %#v", report.Impacts, test.wantImpacts)
			}
			if report.MaxDepth != test.wantMax || report.Cycle != test.wantCycle {
				t.Errorf("maxDepth/cycle = %d/%t, want %d/%t", report.MaxDepth, report.Cycle, test.wantMax, test.wantCycle)
			}
		})
	}
}

func TestRunFormatArgumentErrors(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "unsupported format",
			args:    []string{"analyze", "unused.json", "--target", "target", "--format", "yaml"},
			wantErr: "unsupported output format",
		},
		{
			name:    "duplicate format",
			args:    []string{"analyze", "unused.json", "--target", "target", "--format", "json", "--format=human"},
			wantErr: "--format may only be specified once",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			err := run(test.args, &output)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("run() error = %v, want error containing %q", err, test.wantErr)
			}
			if output.Len() != 0 {
				t.Errorf("run() wrote output before failing: %q", output.String())
			}
		})
	}
}

func TestRunTargetNotFound(t *testing.T) {
	sbomPath := writeSBOM(t, sbom.SBOM{
		Components: []sbom.Component{{BOMRef: "present", Name: "present", Version: "1"}},
	})

	var output bytes.Buffer
	err := run([]string{"analyze", sbomPath, "--target", "missing"}, &output)
	if !errors.Is(err, analysis.ErrTargetNotFound) {
		t.Fatalf("run() error = %v, want ErrTargetNotFound", err)
	}
	if output.Len() != 0 {
		t.Fatalf("run() wrote output before failing: %q", output.String())
	}
}

func TestRunMalformedSBOM(t *testing.T) {
	sbomPath := filepath.Join(t.TempDir(), "malformed.json")
	if err := os.WriteFile(sbomPath, []byte(`{"components":`), 0o600); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	err := run([]string{"analyze", sbomPath, "--target", "target"}, &output)
	if err == nil || !strings.Contains(err.Error(), "parse SBOM") {
		t.Fatalf("run() error = %v, want malformed SBOM parse error", err)
	}
	if output.Len() != 0 {
		t.Fatalf("run() wrote output before failing: %q", output.String())
	}
}

func TestRunTargetWithoutDependents(t *testing.T) {
	sbomPath := writeSBOM(t, sbom.SBOM{
		Components: []sbom.Component{
			{BOMRef: "target-ref", Name: "target", Version: "1"},
			{BOMRef: "unrelated-ref", Name: "unrelated", Version: "2"},
		},
	})

	var output bytes.Buffer
	if err := run([]string{"analyze", sbomPath, "--target", "target-ref"}, &output); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	for _, want := range []string{
		"Potentially affected dependents: 0",
		"Maximum propagation depth: 0",
		"No downstream dependents found.",
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("report does not contain %q:\n%s", want, output.String())
		}
	}
	if strings.Contains(output.String(), "unrelated") || strings.Contains(output.String(), "Propagation") {
		t.Errorf("report includes data outside the target's downstream reach:\n%s", output.String())
	}
}

func TestRunDeterministicOutput(t *testing.T) {
	firstPath := writeSBOM(t, sbom.SBOM{
		Components: []sbom.Component{
			{BOMRef: "target", Name: "target", Version: "1"},
			{BOMRef: "b", Name: "b", Version: "1"},
			{BOMRef: "a", Name: "a", Version: "1"},
			{BOMRef: "leaf", Name: "leaf", Version: "1"},
		},
		Dependencies: []sbom.Dependency{
			{Ref: "b", DependsOn: []string{"target"}},
			{Ref: "a", DependsOn: []string{"target"}},
			{Ref: "leaf", DependsOn: []string{"b"}},
			{Ref: "leaf", DependsOn: []string{"a"}},
		},
	})
	secondPath := writeSBOM(t, sbom.SBOM{
		Components: []sbom.Component{
			{BOMRef: "leaf", Name: "leaf", Version: "1"},
			{BOMRef: "a", Name: "a", Version: "1"},
			{BOMRef: "b", Name: "b", Version: "1"},
			{BOMRef: "target", Name: "target", Version: "1"},
		},
		Dependencies: []sbom.Dependency{
			{Ref: "leaf", DependsOn: []string{"a"}},
			{Ref: "leaf", DependsOn: []string{"b"}},
			{Ref: "a", DependsOn: []string{"target"}},
			{Ref: "b", DependsOn: []string{"target"}},
		},
	})

	var firstOutput, secondOutput bytes.Buffer
	if err := run([]string{"analyze", firstPath, "--target", "target"}, &firstOutput); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"analyze", secondPath, "--target", "target"}, &secondOutput); err != nil {
		t.Fatal(err)
	}
	if firstOutput.String() != secondOutput.String() {
		t.Fatalf("equivalent SBOMs produced different output:\n--- first ---\n%s\n--- second ---\n%s", firstOutput.String(), secondOutput.String())
	}
	if !strings.Contains(firstOutput.String(), "Path: target@1 -> a@1 -> leaf@1") {
		t.Errorf("report did not use the canonical shortest path:\n%s", firstOutput.String())
	}

	var firstJSON, secondJSON bytes.Buffer
	if err := run([]string{"analyze", firstPath, "--target", "target", "--format=json"}, &firstJSON); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"analyze", secondPath, "--target", "target", "--format=json"}, &secondJSON); err != nil {
		t.Fatal(err)
	}
	if firstJSON.String() != secondJSON.String() {
		t.Fatalf("equivalent SBOMs produced different JSON output:\n--- first ---\n%s\n--- second ---\n%s", firstJSON.String(), secondJSON.String())
	}
}

func TestRunInvestigateSuccessfulPipelineAndOutput(t *testing.T) {
	const question = "  Explain the potential impact of this compromised dependency.  "
	const targetBOMRef = "library@2.3.4"
	sbomPath := fixtureSBOMPath(t)
	wantEvidence := evidenceFromFixture(t, targetBOMRef)
	wantResult := fakeInvestigationResult()
	fake := &fakeInvestigator{result: wantResult}
	factoryCalls := 0
	factory := func() (investigation.Investigator, error) {
		factoryCalls++
		return fake, nil
	}

	var output bytes.Buffer
	err := runWithInvestigatorFactory(context.Background(), []string{
		"investigate", sbomPath, "--target", targetBOMRef, "--question", question,
	}, &output, factory)
	if err != nil {
		t.Fatalf("investigate command error = %v", err)
	}
	if factoryCalls != 1 || fake.calls != 1 {
		t.Fatalf("factory/investigator calls = %d/%d, want 1/1", factoryCalls, fake.calls)
	}
	if fake.request.Question != question {
		t.Errorf("investigator question = %q, want unchanged %q", fake.request.Question, question)
	}
	if !reflect.DeepEqual(fake.evidence, wantEvidence) {
		t.Fatalf("investigator evidence = %#v, want FromAnalysis() evidence %#v", fake.evidence, wantEvidence)
	}
	if fake.evidence.Target.BOMRef != targetBOMRef || len(fake.evidence.Impacts) != 1 {
		t.Fatalf("target/impacts = %#v/%#v, want separate target and one dependent", fake.evidence.Target, fake.evidence.Impacts)
	}
	if impact := fake.evidence.Impacts[0]; impact.BOMRef == targetBOMRef || impact.Depth != 1 || !reflect.DeepEqual(impact.Path, []string{targetBOMRef, "app@1.0.0"}) {
		t.Errorf("impact = %#v, want app@1.0.0 at depth 1 with the canonical path", impact)
	}

	for _, want := range []string{
		"Question: " + question,
		"Compromised Target:\n  library@2.3.4 library@2.3.4",
		"Summary:\n  Potential propagation reaches the supplied app.",
		"1. The app is potentially affected through the supplied dependency path.",
		"Evidence: library@2.3.4, app@1.0.0",
		"- The supplied evidence does not establish whether the app is compromised.",
		"- Verify the app against trusted deployment records.",
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("investigation output does not contain %q:\n%s", want, output.String())
		}
	}
}

func TestRunInvestigateMissingTargetDoesNotCallInvestigator(t *testing.T) {
	fake := &fakeInvestigator{result: fakeInvestigationResult()}
	factoryCalls := 0
	var output bytes.Buffer
	err := runWithInvestigatorFactory(context.Background(), []string{
		"investigate", fixtureSBOMPath(t), "--target", "missing-ref", "--question", "Explain impact.",
	}, &output, func() (investigation.Investigator, error) {
		factoryCalls++
		return fake, nil
	})
	if !errors.Is(err, analysis.ErrTargetNotFound) {
		t.Fatalf("investigate command error = %v, want ErrTargetNotFound", err)
	}
	if factoryCalls != 0 || fake.calls != 0 {
		t.Errorf("factory/investigator calls = %d/%d, want 0/0", factoryCalls, fake.calls)
	}
	if output.Len() != 0 {
		t.Errorf("command wrote output on missing target: %q", output.String())
	}
}

func TestRunInvestigateMalformedSBOMDoesNotCallInvestigator(t *testing.T) {
	sbomPath := filepath.Join(t.TempDir(), "malformed.json")
	if err := os.WriteFile(sbomPath, []byte(`{"components":`), 0o600); err != nil {
		t.Fatal(err)
	}
	fake := &fakeInvestigator{result: fakeInvestigationResult()}
	factoryCalls := 0
	var output bytes.Buffer
	err := runWithInvestigatorFactory(context.Background(), []string{
		"investigate", sbomPath, "--target", "library@2.3.4", "--question", "Explain impact.",
	}, &output, func() (investigation.Investigator, error) {
		factoryCalls++
		return fake, nil
	})
	if err == nil || !strings.Contains(err.Error(), "parse SBOM") {
		t.Fatalf("investigate command error = %v, want malformed SBOM error", err)
	}
	if factoryCalls != 0 || fake.calls != 0 {
		t.Errorf("factory/investigator calls = %d/%d, want 0/0", factoryCalls, fake.calls)
	}
	if output.Len() != 0 {
		t.Errorf("command wrote output on malformed SBOM: %q", output.String())
	}
}

func TestRunInvestigateRejectsInvalidInvestigatorResult(t *testing.T) {
	fake := &fakeInvestigator{result: investigation.Result{
		Summary:     "Unsupported result",
		Findings:    []investigation.Finding{{Statement: "Unsupported claim", Evidence: []investigation.EvidenceRef{{BOMRefs: []string{"unknown-ref"}}}}},
		Uncertainty: []string{},
		NextSteps:   []string{},
	}}
	var output bytes.Buffer
	err := runWithInvestigatorFactory(context.Background(), []string{
		"investigate", fixtureSBOMPath(t), "--target", "library@2.3.4", "--question", "Explain impact.",
	}, &output, func() (investigation.Investigator, error) { return fake, nil })
	if err == nil || !strings.Contains(err.Error(), "not present in supplied evidence") {
		t.Fatalf("investigate command error = %v, want result validation error", err)
	}
	if fake.calls != 1 {
		t.Errorf("investigator calls = %d, want 1", fake.calls)
	}
	if output.Len() != 0 {
		t.Errorf("command printed invalid result: %q", output.String())
	}
}

func TestRunInvestigateReportsInvestigatorErrorToStderr(t *testing.T) {
	fake := &fakeInvestigator{err: errors.New("controlled investigator failure")}
	var stdout, stderr bytes.Buffer
	err := execute(context.Background(), []string{
		"investigate", fixtureSBOMPath(t), "--target", "library@2.3.4", "--question", "Explain impact.",
	}, &stdout, &stderr, func() (investigation.Investigator, error) { return fake, nil })
	if err == nil || !strings.Contains(err.Error(), "controlled investigator failure") {
		t.Fatalf("execute() error = %v, want investigator error", err)
	}
	if stdout.Len() != 0 {
		t.Errorf("command wrote success output after investigator error: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "controlled investigator failure") {
		t.Errorf("stderr = %q, want investigator error", stderr.String())
	}
	if fake.calls != 1 {
		t.Errorf("investigator calls = %d, want 1", fake.calls)
	}
}

func TestRunInvestigateOutputIsDeterministic(t *testing.T) {
	sbomPath := fixtureSBOMPath(t)
	args := []string{"investigate", sbomPath, "--target", "library@2.3.4", "--question", "Explain impact."}
	var outputs [2]bytes.Buffer
	for i := range outputs {
		fake := &fakeInvestigator{result: fakeInvestigationResult()}
		if err := runWithInvestigatorFactory(context.Background(), args, &outputs[i], func() (investigation.Investigator, error) {
			return fake, nil
		}); err != nil {
			t.Fatalf("run %d error = %v", i+1, err)
		}
	}
	if outputs[0].String() != outputs[1].String() {
		t.Fatalf("same input/result produced different reports:\n--- first ---\n%s\n--- second ---\n%s", outputs[0].String(), outputs[1].String())
	}
}

func fixtureSBOMPath(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "testdata", "minimal-cyclonedx.json")
}

func evidenceFromFixture(t *testing.T, targetBOMRef string) investigation.Evidence {
	t.Helper()
	data, err := os.ReadFile(fixtureSBOMPath(t))
	if err != nil {
		t.Fatal(err)
	}
	document, err := sbom.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	dependencyGraph, err := graph.New(document)
	if err != nil {
		t.Fatal(err)
	}
	result, err := analysis.Analyze(dependencyGraph, targetBOMRef)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := investigation.FromAnalysis(result)
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}

func fakeInvestigationResult() investigation.Result {
	return investigation.Result{
		Summary: "Potential propagation reaches the supplied app.",
		Findings: []investigation.Finding{{
			Statement: "The app is potentially affected through the supplied dependency path.",
			Evidence:  []investigation.EvidenceRef{{BOMRefs: []string{"library@2.3.4", "app@1.0.0"}}},
		}},
		Uncertainty: []string{"The supplied evidence does not establish whether the app is compromised."},
		NextSteps:   []string{"Verify the app against trusted deployment records."},
	}
}

func writeSBOM(t *testing.T, document sbom.SBOM) string {
	t.Helper()

	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "sbom.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
