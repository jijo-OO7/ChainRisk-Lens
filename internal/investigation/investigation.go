package investigation

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/jijo-OO7/chainrisk-lens/internal/analysis"
	"github.com/jijo-OO7/chainrisk-lens/internal/graph"
)

// Component is component metadata included in deterministic evidence.
type Component struct {
	BOMRef  string
	Name    string
	Version string
}

// Impact is a potentially affected dependent and its shortest path from Target.
type Impact struct {
	BOMRef  string
	Name    string
	Version string
	Depth   int
	Path    []string
}

// Evidence contains deterministic facts from the security analysis.
type Evidence struct {
	Target   Component
	Impacts  []Impact
	MaxDepth int
	Cycle    bool
}

// FromAnalysis copies deterministic analysis facts into the investigation
// contract, including canonical paths expressed as BOMRefs.
func FromAnalysis(result analysis.Analysis) (Evidence, error) {
	evidence := Evidence{
		Target:   componentFromNode(result.Target),
		Impacts:  make([]Impact, 0, len(result.Impacts)),
		MaxDepth: result.MaxDepth,
		Cycle:    result.Cycle,
	}

	for _, impact := range result.Impacts {
		path, exists := result.PathTo(impact.Node.BOMRef)
		if !exists {
			return Evidence{}, fmt.Errorf("analysis path is unavailable for impact %q", impact.Node.BOMRef)
		}
		pathBOMRefs := make([]string, len(path))
		for i, node := range path {
			pathBOMRefs[i] = node.BOMRef
		}

		evidence.Impacts = append(evidence.Impacts, Impact{
			BOMRef:  impact.Node.BOMRef,
			Name:    impact.Node.Name,
			Version: impact.Node.Version,
			Depth:   impact.Depth,
			Path:    pathBOMRefs,
		})
	}

	sort.Slice(evidence.Impacts, func(i, j int) bool {
		if evidence.Impacts[i].Depth != evidence.Impacts[j].Depth {
			return evidence.Impacts[i].Depth < evidence.Impacts[j].Depth
		}
		return evidence.Impacts[i].BOMRef < evidence.Impacts[j].BOMRef
	})
	if err := evidence.Validate(); err != nil {
		return Evidence{}, fmt.Errorf("invalid analysis evidence: %w", err)
	}
	return evidence, nil
}

// Validate checks evidence invariants before it is supplied to an investigator.
func (evidence Evidence) Validate() error {
	if evidence.Target.BOMRef == "" {
		return fmt.Errorf("target BOM-REF is empty")
	}

	seen := make(map[string]struct{}, len(evidence.Impacts))
	maxDepth := 0
	for _, impact := range evidence.Impacts {
		if impact.BOMRef == "" {
			return fmt.Errorf("impact BOM-REF is empty")
		}
		if impact.BOMRef == evidence.Target.BOMRef {
			return fmt.Errorf("target %q must not appear in impacts", evidence.Target.BOMRef)
		}
		if _, exists := seen[impact.BOMRef]; exists {
			return fmt.Errorf("duplicate impact BOM-REF %q", impact.BOMRef)
		}
		seen[impact.BOMRef] = struct{}{}
		if impact.Depth < 1 {
			return fmt.Errorf("impact %q has invalid depth %d", impact.BOMRef, impact.Depth)
		}
		if len(impact.Path) == 0 {
			return fmt.Errorf("impact %q has an empty path", impact.BOMRef)
		}
		if impact.Path[0] != evidence.Target.BOMRef {
			return fmt.Errorf("impact %q path does not begin at the target", impact.BOMRef)
		}
		if impact.Path[len(impact.Path)-1] != impact.BOMRef {
			return fmt.Errorf("impact %q path does not end at the impact", impact.BOMRef)
		}
		if len(impact.Path) != impact.Depth+1 {
			return fmt.Errorf("impact %q depth %d does not match path length %d", impact.BOMRef, impact.Depth, len(impact.Path))
		}

		pathSeen := make(map[string]struct{}, len(impact.Path))
		for _, bomRef := range impact.Path {
			if bomRef == "" {
				return fmt.Errorf("impact %q path contains an empty BOM-REF", impact.BOMRef)
			}
			if _, exists := pathSeen[bomRef]; exists {
				return fmt.Errorf("impact %q path contains a cycle", impact.BOMRef)
			}
			pathSeen[bomRef] = struct{}{}
		}
		if impact.Depth > maxDepth {
			maxDepth = impact.Depth
		}
	}
	if evidence.MaxDepth != maxDepth {
		return fmt.Errorf("max depth %d does not match impacts max depth %d", evidence.MaxDepth, maxDepth)
	}
	return nil
}

// Request describes the question a future investigator should address.
type Request struct {
	Question string
}

// Result is a structured explanation whose findings cite supplied evidence.
type Result struct {
	Summary     string
	Findings    []Finding
	Uncertainty []string
	NextSteps   []string
}

// Finding is a security-relevant statement with references to supporting evidence.
type Finding struct {
	Statement string
	Evidence  []EvidenceRef
}

// EvidenceRef identifies supplied components relevant to a finding.
type EvidenceRef struct {
	BOMRefs []string
}

// Validate ensures each finding cites only components present in the supplied evidence.
func (result Result) Validate(evidence Evidence) error {
	if err := evidence.Validate(); err != nil {
		return fmt.Errorf("invalid supplied evidence: %w", err)
	}

	knownBOMRefs := make(map[string]struct{}, len(evidence.Impacts)+1)
	knownBOMRefs[evidence.Target.BOMRef] = struct{}{}
	for _, impact := range evidence.Impacts {
		knownBOMRefs[impact.BOMRef] = struct{}{}
	}

	for index, finding := range result.Findings {
		if strings.TrimSpace(finding.Statement) == "" {
			return fmt.Errorf("finding %d has an empty statement", index)
		}
		if len(finding.Evidence) == 0 {
			return fmt.Errorf("finding %d has no evidence references", index)
		}
		for _, reference := range finding.Evidence {
			if len(reference.BOMRefs) == 0 {
				return fmt.Errorf("finding %d contains an empty evidence reference", index)
			}
			for _, bomRef := range reference.BOMRefs {
				if _, exists := knownBOMRefs[bomRef]; !exists {
					return fmt.Errorf("finding %d references BOM-REF %q not present in supplied evidence", index, bomRef)
				}
			}
		}
	}
	return nil
}

// Investigator consumes a request and deterministic evidence to produce an explanation.
type Investigator interface {
	Investigate(ctx context.Context, request Request, evidence Evidence) (Result, error)
}

func componentFromNode(node graph.Node) Component {
	return Component{BOMRef: node.BOMRef, Name: node.Name, Version: node.Version}
}
