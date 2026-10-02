package analysis

import (
	"errors"
	"fmt"
	"sort"

	dependencygraph "github.com/jijo-OO7/chainrisk-lens/internal/graph"
)

// ErrTargetNotFound indicates that the requested target is not in the graph.
var ErrTargetNotFound = errors.New("analysis target not found")

// Impact describes a dependent that may be affected through potential
// propagation from the assumed-compromised target. It does not indicate that
// the dependent is compromised.
type Impact struct {
	Node  dependencygraph.Node
	Depth int
}

// Analysis contains target-centric potential impact evidence. Target is the
// component assumed compromised and is not included in Impacts. Impacts contains
// unique reachable dependents in breadth-first order, beginning at depth one.
type Analysis struct {
	Target   dependencygraph.Node
	Impacts  []Impact
	MaxDepth int
	Cycle    bool

	nodes   map[string]dependencygraph.Node
	parents map[string]string
}

// Analyze calculates shortest propagation depths and one deterministic
// shortest path for each reachable component. Paths can be retrieved with
// PathTo; only the first path discovered by breadth-first traversal is kept.
func Analyze(graph *dependencygraph.Graph, targetBOMRef string) (Analysis, error) {
	if graph == nil {
		return Analysis{}, errors.New("cannot analyze a nil graph")
	}

	target, exists := graph.Lookup(targetBOMRef)
	if !exists {
		return Analysis{}, fmt.Errorf("%w: %q", ErrTargetNotFound, targetBOMRef)
	}

	result := Analysis{
		Target:  target,
		Impacts: []Impact{},
		nodes:   map[string]dependencygraph.Node{targetBOMRef: target},
		parents: map[string]string{targetBOMRef: ""},
	}
	depths := map[string]int{targetBOMRef: 0}
	queue := []string{targetBOMRef}

	for head := 0; head < len(queue); head++ {
		currentRef := queue[head]
		dependents, exists := graph.DirectDependents(currentRef)
		if !exists {
			return Analysis{}, fmt.Errorf("reachable component %q is missing from the graph", currentRef)
		}
		sort.Slice(dependents, func(i, j int) bool {
			return dependents[i].BOMRef < dependents[j].BOMRef
		})

		for _, dependent := range dependents {
			if _, visited := depths[dependent.BOMRef]; visited {
				continue
			}

			depth := depths[currentRef] + 1
			depths[dependent.BOMRef] = depth
			result.nodes[dependent.BOMRef] = dependent
			result.parents[dependent.BOMRef] = currentRef
			result.Impacts = append(result.Impacts, Impact{Node: dependent, Depth: depth})
			if depth > result.MaxDepth {
				result.MaxDepth = depth
			}
			queue = append(queue, dependent.BOMRef)
		}
	}

	result.Cycle = hasReachableCycle(graph, queue)
	return result, nil
}

// PathTo returns the one shortest propagation path selected for bomRef. Ties
// are resolved by breadth-first discovery with dependents ordered by BOMRef.
// It returns false when bomRef is not part of this analysis.
func (analysis Analysis) PathTo(bomRef string) ([]dependencygraph.Node, bool) {
	if _, exists := analysis.nodes[bomRef]; !exists {
		return nil, false
	}

	path := make([]dependencygraph.Node, 0)
	for currentRef := bomRef; ; {
		node, exists := analysis.nodes[currentRef]
		if !exists {
			return nil, false
		}
		path = append(path, node)

		parentRef, exists := analysis.parents[currentRef]
		if !exists {
			return nil, false
		}
		if parentRef == "" {
			break
		}
		currentRef = parentRef
	}

	for left, right := 0, len(path)-1; left < right; left, right = left+1, right-1 {
		path[left], path[right] = path[right], path[left]
	}
	return path, true
}

func hasReachableCycle(graph *dependencygraph.Graph, reachable []string) bool {
	reachableSet := make(map[string]struct{}, len(reachable))
	inDegree := make(map[string]int, len(reachable))
	for _, bomRef := range reachable {
		reachableSet[bomRef] = struct{}{}
		inDegree[bomRef] = 0
	}

	for _, bomRef := range reachable {
		dependents, _ := graph.DirectDependents(bomRef)
		for _, dependent := range dependents {
			if _, exists := reachableSet[dependent.BOMRef]; exists {
				inDegree[dependent.BOMRef]++
			}
		}
	}

	queue := make([]string, 0, len(reachable))
	for _, bomRef := range reachable {
		if inDegree[bomRef] == 0 {
			queue = append(queue, bomRef)
		}
	}

	processed := 0
	for head := 0; head < len(queue); head++ {
		bomRef := queue[head]
		processed++
		dependents, _ := graph.DirectDependents(bomRef)
		for _, dependent := range dependents {
			if _, exists := reachableSet[dependent.BOMRef]; !exists {
				continue
			}
			inDegree[dependent.BOMRef]--
			if inDegree[dependent.BOMRef] == 0 {
				queue = append(queue, dependent.BOMRef)
			}
		}
	}

	return processed != len(reachable)
}
