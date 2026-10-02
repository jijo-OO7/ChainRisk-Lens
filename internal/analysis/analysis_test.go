package analysis

import (
	"errors"
	"reflect"
	"testing"

	dependencygraph "github.com/jijo-OO7/chainrisk-lens/internal/graph"
	"github.com/jijo-OO7/chainrisk-lens/internal/sbom"
)

type propagationEdge struct {
	from string
	to   string
}

func TestAnalyze(t *testing.T) {
	tests := []struct {
		name       string
		components []string
		edges      []propagationEdge
		target     string
		wantRefs   []string
		wantDepths []int
		wantPaths  [][]string
		wantMax    int
		wantCycle  bool
		wantError  bool
	}{
		{
			name:       "linear chain",
			components: []string{"target", "A", "B", "C"},
			edges:      []propagationEdge{{"target", "A"}, {"A", "B"}, {"B", "C"}},
			target:     "target",
			wantRefs:   []string{"target", "A", "B", "C"},
			wantDepths: []int{0, 1, 2, 3},
			wantPaths:  [][]string{{"target"}, {"target", "A"}, {"target", "A", "B"}, {"target", "A", "B", "C"}},
			wantMax:    3,
		},
		{
			name:       "branching graph",
			components: []string{"target", "B", "A"},
			edges:      []propagationEdge{{"target", "B"}, {"target", "A"}},
			target:     "target",
			wantRefs:   []string{"target", "A", "B"},
			wantDepths: []int{0, 1, 1},
			wantPaths:  [][]string{{"target"}, {"target", "A"}, {"target", "B"}},
			wantMax:    1,
		},
		{
			name:       "different depth branches",
			components: []string{"target", "A", "B", "C", "D", "E"},
			edges:      []propagationEdge{{"target", "A"}, {"A", "C"}, {"target", "B"}, {"B", "D"}, {"D", "E"}},
			target:     "target",
			wantRefs:   []string{"target", "A", "B", "C", "D", "E"},
			wantDepths: []int{0, 1, 1, 2, 2, 3},
			wantPaths: [][]string{
				{"target"}, {"target", "A"}, {"target", "B"},
				{"target", "A", "C"}, {"target", "B", "D"}, {"target", "B", "D", "E"},
			},
			wantMax: 3,
		},
		{
			name:       "cycle",
			components: []string{"A", "B", "C"},
			edges:      []propagationEdge{{"A", "B"}, {"B", "C"}, {"C", "A"}},
			target:     "A",
			wantRefs:   []string{"A", "B", "C"},
			wantDepths: []int{0, 1, 2},
			wantPaths:  [][]string{{"A"}, {"A", "B"}, {"A", "B", "C"}},
			wantMax:    2,
			wantCycle:  true,
		},
		{
			name:       "target with no dependents",
			components: []string{"target", "unrelated", "outside"},
			edges:      []propagationEdge{{"outside", "unrelated"}},
			target:     "target",
			wantRefs:   []string{"target"},
			wantDepths: []int{0},
			wantPaths:  [][]string{{"target"}},
		},
		{
			name:       "missing target",
			components: []string{"target", "child"},
			edges:      []propagationEdge{{"target", "child"}},
			target:     "missing",
			wantError:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			graph, err := dependencygraph.New(makeSBOM(test.components, test.edges))
			if err != nil {
				t.Fatalf("graph.New() error = %v", err)
			}

			got, err := Analyze(graph, test.target)
			if test.wantError {
				if !errors.Is(err, ErrTargetNotFound) {
					t.Fatalf("Analyze() error = %v, want ErrTargetNotFound", err)
				}
				if got.Target != (dependencygraph.Node{}) || len(got.Impacts) != 0 {
					t.Fatalf("Analyze() result on missing target = %#v, want empty result", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}

			wantTarget := dependencygraph.Node{BOMRef: test.target, Name: test.target, Version: "1"}
			if got.Target != wantTarget {
				t.Errorf("Target = %#v, want %#v", got.Target, wantTarget)
			}

			wantImpacts := make([]Impact, len(test.wantRefs)-1)
			for i, bomRef := range test.wantRefs[1:] {
				wantImpacts[i] = Impact{
					Node:  dependencygraph.Node{BOMRef: bomRef, Name: bomRef, Version: "1"},
					Depth: test.wantDepths[i+1],
				}
			}
			if !reflect.DeepEqual(got.Impacts, wantImpacts) {
				t.Errorf("Impacts = %#v, want %#v", got.Impacts, wantImpacts)
			}
			if got.MaxDepth != test.wantMax {
				t.Errorf("MaxDepth = %d, want %d", got.MaxDepth, test.wantMax)
			}
			if got.Cycle != test.wantCycle {
				t.Errorf("Cycle = %t, want %t", got.Cycle, test.wantCycle)
			}
			for i, bomRef := range test.wantRefs {
				path, exists := got.PathTo(bomRef)
				if !exists || !reflect.DeepEqual(nodeRefs(path), test.wantPaths[i]) {
					t.Errorf("PathTo(%q) = %v, %t; want %v, true", bomRef, nodeRefs(path), exists, test.wantPaths[i])
				}
			}
			if _, exists := got.PathTo("unreachable"); exists {
				t.Error("PathTo(unreachable) unexpectedly succeeded")
			}
		})
	}
}

func TestAnalyzeDeterministic(t *testing.T) {
	components := []string{"target", "A", "B", "C", "leaf"}
	edges := []propagationEdge{
		{"target", "B"}, {"target", "A"},
		{"B", "C"}, {"A", "C"}, {"C", "leaf"},
	}

	firstGraph, err := dependencygraph.New(makeSBOM(components, edges))
	if err != nil {
		t.Fatal(err)
	}
	secondGraph, err := dependencygraph.New(makeSBOM(reverseStrings(components), reverseEdges(edges)))
	if err != nil {
		t.Fatal(err)
	}

	first, err := Analyze(firstGraph, "target")
	if err != nil {
		t.Fatal(err)
	}
	second, err := Analyze(secondGraph, "target")
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(first.Target, second.Target) ||
		!reflect.DeepEqual(first.Impacts, second.Impacts) ||
		first.MaxDepth != second.MaxDepth || first.Cycle != second.Cycle {
		t.Fatalf("equivalent graphs produced different analyses: %#v != %#v", first, second)
	}
	for _, impact := range first.Impacts {
		firstPath, firstExists := first.PathTo(impact.Node.BOMRef)
		secondPath, secondExists := second.PathTo(impact.Node.BOMRef)
		if !firstExists || !secondExists || !reflect.DeepEqual(nodeRefs(firstPath), nodeRefs(secondPath)) {
			t.Errorf("PathTo(%q) differs between equivalent graphs: %v, %v", impact.Node.BOMRef, nodeRefs(firstPath), nodeRefs(secondPath))
		}
	}

	path, exists := first.PathTo("C")
	if !exists || !reflect.DeepEqual(nodeRefs(path), []string{"target", "A", "C"}) {
		t.Errorf("PathTo(C) = %v, %t; want [target A C], true", nodeRefs(path), exists)
	}
}

func makeSBOM(components []string, edges []propagationEdge) sbom.SBOM {
	document := sbom.SBOM{
		Components:   make([]sbom.Component, 0, len(components)),
		Dependencies: make([]sbom.Dependency, 0, len(edges)),
	}
	for _, bomRef := range components {
		document.Components = append(document.Components, sbom.Component{
			BOMRef: bomRef, Name: bomRef, Version: "1",
		})
	}
	for _, edge := range edges {
		document.Dependencies = append(document.Dependencies, sbom.Dependency{
			Ref: edge.to, DependsOn: []string{edge.from},
		})
	}
	return document
}

func nodeRefs(nodes []dependencygraph.Node) []string {
	refs := make([]string, len(nodes))
	for i, node := range nodes {
		refs[i] = node.BOMRef
	}
	return refs
}

func reverseStrings(values []string) []string {
	reversed := make([]string, len(values))
	for i, value := range values {
		reversed[len(values)-1-i] = value
	}
	return reversed
}

func reverseEdges(edges []propagationEdge) []propagationEdge {
	reversed := make([]propagationEdge, len(edges))
	for i, edge := range edges {
		reversed[len(edges)-1-i] = edge
	}
	return reversed
}
