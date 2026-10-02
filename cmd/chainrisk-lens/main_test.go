package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jijo-OO7/chainrisk-lens/internal/analysis"
	"github.com/jijo-OO7/chainrisk-lens/internal/sbom"
)

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
