package graph

import (
	"fmt"
	"sort"

	"github.com/jijo-OO7/chainrisk-lens/internal/sbom"
)

// Node is a component in the dependency graph.
type Node struct {
	BOMRef  string
	Name    string
	Version string
}

// Graph stores component metadata and both directions of dependency edges.
type Graph struct {
	nodes   map[string]Node
	forward map[string][]string
	reverse map[string][]string
}

// New builds a graph from an SBOM, rejecting ambiguous or unresolved references.
func New(document sbom.SBOM) (*Graph, error) {
	graph := &Graph{
		nodes:   make(map[string]Node, len(document.Components)),
		forward: make(map[string][]string, len(document.Components)),
		reverse: make(map[string][]string, len(document.Components)),
	}

	for _, component := range document.Components {
		if component.BOMRef == "" {
			return nil, fmt.Errorf("component %q has an empty bom-ref", component.Name)
		}
		if _, exists := graph.nodes[component.BOMRef]; exists {
			return nil, fmt.Errorf("duplicate bom-ref %q", component.BOMRef)
		}

		node := Node{BOMRef: component.BOMRef, Name: component.Name, Version: component.Version}
		graph.nodes[node.BOMRef] = node
		graph.forward[node.BOMRef] = nil
		graph.reverse[node.BOMRef] = nil
	}

	forwardSeen := make(map[string]map[string]struct{}, len(document.Components))
	for _, dependency := range document.Dependencies {
		if _, exists := graph.nodes[dependency.Ref]; !exists {
			return nil, fmt.Errorf("dependency ref %q does not match a component bom-ref", dependency.Ref)
		}

		for _, dependencyRef := range dependency.DependsOn {
			if _, exists := graph.nodes[dependencyRef]; !exists {
				return nil, fmt.Errorf("dependency %q of %q does not match a component bom-ref", dependencyRef, dependency.Ref)
			}

			if forwardSeen[dependency.Ref] == nil {
				forwardSeen[dependency.Ref] = make(map[string]struct{})
			}
			if _, exists := forwardSeen[dependency.Ref][dependencyRef]; exists {
				continue
			}
			forwardSeen[dependency.Ref][dependencyRef] = struct{}{}
			graph.forward[dependency.Ref] = append(graph.forward[dependency.Ref], dependencyRef)
			graph.reverse[dependencyRef] = append(graph.reverse[dependencyRef], dependency.Ref)
		}
	}

	for _, refs := range graph.forward {
		sort.Strings(refs)
	}
	for _, refs := range graph.reverse {
		sort.Strings(refs)
	}
	return graph, nil
}

// Lookup returns the component identified by bomRef.
func (graph *Graph) Lookup(bomRef string) (Node, bool) {
	node, exists := graph.nodes[bomRef]
	return node, exists
}

// DirectDependencies returns the components that bomRef directly depends on.
func (graph *Graph) DirectDependencies(bomRef string) ([]Node, bool) {
	if _, exists := graph.nodes[bomRef]; !exists {
		return nil, false
	}
	return graph.nodesFor(graph.forward[bomRef]), true
}

// DirectDependents returns the components that directly depend on bomRef.
func (graph *Graph) DirectDependents(bomRef string) ([]Node, bool) {
	if _, exists := graph.nodes[bomRef]; !exists {
		return nil, false
	}
	return graph.nodesFor(graph.reverse[bomRef]), true
}

// BlastRadius returns bomRef and all downstream dependents in breadth-first order.
func (graph *Graph) BlastRadius(bomRef string) ([]Node, bool) {
	start, exists := graph.nodes[bomRef]
	if !exists {
		return nil, false
	}

	result := []Node{start}
	queue := []string{bomRef}
	visited := map[string]struct{}{bomRef: {}}
	for head := 0; head < len(queue); head++ {
		for _, dependentRef := range graph.reverse[queue[head]] {
			if _, seen := visited[dependentRef]; seen {
				continue
			}
			visited[dependentRef] = struct{}{}
			queue = append(queue, dependentRef)
			result = append(result, graph.nodes[dependentRef])
		}
	}
	return result, true
}

func (graph *Graph) nodesFor(refs []string) []Node {
	nodes := make([]Node, 0, len(refs))
	for _, ref := range refs {
		nodes = append(nodes, graph.nodes[ref])
	}
	return nodes
}
