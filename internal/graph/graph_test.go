package graph

import (
	"reflect"
	"strings"
	"testing"

	"github.com/jijo-OO7/chainrisk-lens/internal/sbom"
)

func TestGraphCases(t *testing.T) {
	tests := []struct {
		name             string
		components       []sbom.Component
		dependencies     []sbom.Dependency
		target           string
		wantDependencies []Node
		wantDependents   []Node
		wantBlastRadius  []Node
		wantError        string
	}{
		{
			name: "linear dependency chain",
			components: []sbom.Component{
				{BOMRef: "app", Name: "app", Version: "1.0"},
				{BOMRef: "lib", Name: "library", Version: "2.0"},
				{BOMRef: "core", Name: "core", Version: "3.0"},
			},
			dependencies: []sbom.Dependency{
				{Ref: "app", DependsOn: []string{"lib"}},
				{Ref: "lib", DependsOn: []string{"core"}},
			},
			target:           "core",
			wantDependencies: []Node{},
			wantDependents:   []Node{{BOMRef: "lib", Name: "library", Version: "2.0"}},
			wantBlastRadius: []Node{
				{BOMRef: "core", Name: "core", Version: "3.0"},
				{BOMRef: "lib", Name: "library", Version: "2.0"},
				{BOMRef: "app", Name: "app", Version: "1.0"},
			},
		},
		{
			name: "branching graph",
			components: []sbom.Component{
				{BOMRef: "root", Name: "application", Version: "1.0"},
				{BOMRef: "alpha", Name: "alpha", Version: "1.0"},
				{BOMRef: "beta", Name: "beta", Version: "1.0"},
				{BOMRef: "leaf", Name: "leaf", Version: "1.0"},
			},
			dependencies: []sbom.Dependency{
				{Ref: "root", DependsOn: []string{"beta", "alpha"}},
				{Ref: "alpha", DependsOn: []string{"leaf"}},
				{Ref: "beta", DependsOn: []string{"leaf"}},
			},
			target:           "leaf",
			wantDependencies: []Node{},
			wantDependents: []Node{
				{BOMRef: "alpha", Name: "alpha", Version: "1.0"},
				{BOMRef: "beta", Name: "beta", Version: "1.0"},
			},
			wantBlastRadius: []Node{
				{BOMRef: "leaf", Name: "leaf", Version: "1.0"},
				{BOMRef: "alpha", Name: "alpha", Version: "1.0"},
				{BOMRef: "beta", Name: "beta", Version: "1.0"},
				{BOMRef: "root", Name: "application", Version: "1.0"},
			},
		},
		{
			name: "cyclic graph",
			components: []sbom.Component{
				{BOMRef: "a", Name: "a", Version: "1"},
				{BOMRef: "b", Name: "b", Version: "1"},
				{BOMRef: "c", Name: "c", Version: "1"},
			},
			dependencies: []sbom.Dependency{
				{Ref: "a", DependsOn: []string{"b"}},
				{Ref: "b", DependsOn: []string{"c"}},
				{Ref: "c", DependsOn: []string{"a"}},
			},
			target:           "a",
			wantDependencies: []Node{{BOMRef: "b", Name: "b", Version: "1"}},
			wantDependents:   []Node{{BOMRef: "c", Name: "c", Version: "1"}},
			wantBlastRadius: []Node{
				{BOMRef: "a", Name: "a", Version: "1"},
				{BOMRef: "c", Name: "c", Version: "1"},
				{BOMRef: "b", Name: "b", Version: "1"},
			},
		},
		{
			name: "isolated component",
			components: []sbom.Component{
				{BOMRef: "solo", Name: "standalone", Version: "1.0"},
			},
			target:           "solo",
			wantDependencies: []Node{},
			wantDependents:   []Node{},
			wantBlastRadius:  []Node{{BOMRef: "solo", Name: "standalone", Version: "1.0"}},
		},
		{
			name:       "empty component BOMRef",
			components: []sbom.Component{{Name: "app", Version: "1.0"}},
			wantError:  "empty bom-ref",
		},
		{
			name: "duplicate component BOMRef",
			components: []sbom.Component{
				{BOMRef: "app", Name: "app", Version: "1.0"},
				{BOMRef: "app", Name: "other", Version: "2.0"},
			},
			wantError: "duplicate bom-ref",
		},
		{
			name:         "dependency entry with missing Ref",
			components:   []sbom.Component{{BOMRef: "app", Name: "app", Version: "1.0"}},
			dependencies: []sbom.Dependency{{Ref: "missing"}},
			wantError:    `dependency ref "missing"`,
		},
		{
			name: "missing dependency reference",
			components: []sbom.Component{
				{BOMRef: "app", Name: "app", Version: "1.0"},
			},
			dependencies: []sbom.Dependency{{Ref: "app", DependsOn: []string{"missing"}}},
			wantError:    "does not match a component bom-ref",
		},
		{
			name: "duplicate component names with different BOMRefs",
			components: []sbom.Component{
				{BOMRef: "lib-v1", Name: "library", Version: "1.0"},
				{BOMRef: "lib-v2", Name: "library", Version: "2.0"},
				{BOMRef: "app", Name: "application", Version: "1.0"},
			},
			dependencies:     []sbom.Dependency{{Ref: "app", DependsOn: []string{"lib-v2"}}},
			target:           "lib-v2",
			wantDependencies: []Node{},
			wantDependents:   []Node{{BOMRef: "app", Name: "application", Version: "1.0"}},
			wantBlastRadius: []Node{
				{BOMRef: "lib-v2", Name: "library", Version: "2.0"},
				{BOMRef: "app", Name: "application", Version: "1.0"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			graph, err := New(sbom.SBOM{Components: test.components, Dependencies: test.dependencies})
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("New() error = %v, want error containing %q", err, test.wantError)
				}
				return
			}
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			for _, component := range test.components {
				got, exists := graph.Lookup(component.BOMRef)
				want := Node{BOMRef: component.BOMRef, Name: component.Name, Version: component.Version}
				if !exists || got != want {
					t.Errorf("Lookup(%q) = (%#v, %t), want (%#v, true)", component.BOMRef, got, exists, want)
				}
			}

			gotDependencies, exists := graph.DirectDependencies(test.target)
			if !exists || !reflect.DeepEqual(gotDependencies, test.wantDependencies) {
				t.Errorf("DirectDependencies(%q) = (%#v, %t), want (%#v, true)", test.target, gotDependencies, exists, test.wantDependencies)
			}

			gotDependents, exists := graph.DirectDependents(test.target)
			if !exists || !reflect.DeepEqual(gotDependents, test.wantDependents) {
				t.Errorf("DirectDependents(%q) = (%#v, %t), want (%#v, true)", test.target, gotDependents, exists, test.wantDependents)
			}

			gotBlastRadius, exists := graph.BlastRadius(test.target)
			if !exists || !reflect.DeepEqual(gotBlastRadius, test.wantBlastRadius) {
				t.Errorf("BlastRadius(%q) = (%#v, %t), want (%#v, true)", test.target, gotBlastRadius, exists, test.wantBlastRadius)
			}
		})
	}
}
