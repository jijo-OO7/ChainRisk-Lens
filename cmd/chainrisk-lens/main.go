package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/jijo-OO7/chainrisk-lens/internal/analysis"
	"github.com/jijo-OO7/chainrisk-lens/internal/graph"
	"github.com/jijo-OO7/chainrisk-lens/internal/sbom"
)

const (
	formatHuman = "human"
	formatJSON  = "json"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "chainrisk-lens:", err)
		os.Exit(1)
	}
}

func run(args []string, output io.Writer) error {
	if len(args) == 0 || args[0] != "analyze" {
		return errors.New("usage: chainrisk-lens analyze <sbom-file> --target <BOM-REF>")
	}

	sbomPath, targetBOMRef, outputFormat, err := parseAnalyzeArgs(args[1:])
	if err != nil {
		return err
	}

	data, err := os.ReadFile(sbomPath)
	if err != nil {
		return fmt.Errorf("read SBOM %q: %w", sbomPath, err)
	}

	document, err := sbom.Parse(data)
	if err != nil {
		return fmt.Errorf("parse SBOM %q: %w", sbomPath, err)
	}

	dependencyGraph, err := graph.New(document)
	if err != nil {
		return fmt.Errorf("build dependency graph: %w", err)
	}

	result, err := analysis.Analyze(dependencyGraph, targetBOMRef)
	if err != nil {
		return fmt.Errorf("analyze target %q: %w", targetBOMRef, err)
	}

	if outputFormat == formatJSON {
		report, err := formatJSONReport(result)
		if err != nil {
			return err
		}
		if err := json.NewEncoder(output).Encode(report); err != nil {
			return fmt.Errorf("write analysis report: %w", err)
		}
		return nil
	}

	report, err := formatReport(result)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(output, report); err != nil {
		return fmt.Errorf("write analysis report: %w", err)
	}
	return nil
}

func parseAnalyzeArgs(args []string) (string, string, string, error) {
	var sbomPath string
	var targetBOMRef string
	outputFormat := formatHuman
	targetProvided := false
	formatProvided := false

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--target":
			if targetProvided {
				return "", "", "", errors.New("--target may only be specified once")
			}
			if i+1 >= len(args) || args[i+1] == "" {
				return "", "", "", errors.New("--target requires a BOM-REF")
			}
			targetBOMRef = args[i+1]
			targetProvided = true
			i++
		case strings.HasPrefix(arg, "--target="):
			if targetProvided {
				return "", "", "", errors.New("--target may only be specified once")
			}
			targetBOMRef = strings.TrimPrefix(arg, "--target=")
			if targetBOMRef == "" {
				return "", "", "", errors.New("--target requires a BOM-REF")
			}
			targetProvided = true
		case arg == "--format":
			if formatProvided {
				return "", "", "", errors.New("--format may only be specified once")
			}
			if i+1 >= len(args) || args[i+1] == "" {
				return "", "", "", errors.New("--format requires a value: human or json")
			}
			outputFormat = args[i+1]
			formatProvided = true
			i++
		case strings.HasPrefix(arg, "--format="):
			if formatProvided {
				return "", "", "", errors.New("--format may only be specified once")
			}
			outputFormat = strings.TrimPrefix(arg, "--format=")
			if outputFormat == "" {
				return "", "", "", errors.New("--format requires a value: human or json")
			}
			formatProvided = true
		case strings.HasPrefix(arg, "-"):
			return "", "", "", fmt.Errorf("unknown option %q", arg)
		default:
			if sbomPath != "" {
				return "", "", "", fmt.Errorf("unexpected argument %q", arg)
			}
			sbomPath = arg
		}
	}

	if sbomPath == "" {
		return "", "", "", errors.New("missing SBOM file path")
	}
	if !targetProvided {
		return "", "", "", errors.New("missing required --target <BOM-REF>")
	}
	if outputFormat != formatHuman && outputFormat != formatJSON {
		return "", "", "", fmt.Errorf("unsupported output format %q (want human or json)", outputFormat)
	}
	return sbomPath, targetBOMRef, outputFormat, nil
}

type jsonReport struct {
	Target   jsonComponent `json:"target"`
	Impacts  []jsonImpact  `json:"impacts"`
	MaxDepth int           `json:"maxDepth"`
	Cycle    bool          `json:"cycle"`
}

type jsonComponent struct {
	BOMRef  string `json:"bomRef"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type jsonImpact struct {
	BOMRef  string   `json:"bomRef"`
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Depth   int      `json:"depth"`
	Path    []string `json:"path"`
}

func formatJSONReport(result analysis.Analysis) (jsonReport, error) {
	report := jsonReport{
		Target: jsonComponent{
			BOMRef:  result.Target.BOMRef,
			Name:    result.Target.Name,
			Version: result.Target.Version,
		},
		Impacts:  make([]jsonImpact, 0, len(result.Impacts)),
		MaxDepth: result.MaxDepth,
		Cycle:    result.Cycle,
	}

	for _, impact := range orderedImpacts(result.Impacts) {
		path, exists := result.PathTo(impact.Node.BOMRef)
		if !exists {
			return jsonReport{}, fmt.Errorf("analysis path is unavailable for dependent %q", impact.Node.BOMRef)
		}
		pathBOMRefs := make([]string, len(path))
		for i, node := range path {
			pathBOMRefs[i] = node.BOMRef
		}

		report.Impacts = append(report.Impacts, jsonImpact{
			BOMRef:  impact.Node.BOMRef,
			Name:    impact.Node.Name,
			Version: impact.Node.Version,
			Depth:   impact.Depth,
			Path:    pathBOMRefs,
		})
	}
	return report, nil
}

func formatReport(result analysis.Analysis) (string, error) {
	var report strings.Builder
	fmt.Fprintln(&report, "ChainRisk Lens - Security Impact Analysis")
	fmt.Fprintln(&report)
	fmt.Fprintln(&report, "Compromised Target")
	fmt.Fprintf(&report, "  Name: %s\n", result.Target.Name)
	fmt.Fprintf(&report, "  Version: %s\n", result.Target.Version)
	fmt.Fprintf(&report, "  BOM Ref: %s\n", result.Target.BOMRef)
	fmt.Fprintln(&report)

	fmt.Fprintln(&report, "Potential Impact")
	fmt.Fprintf(&report, "  Potentially affected dependents: %d\n", len(result.Impacts))
	fmt.Fprintf(&report, "  Maximum propagation depth: %d\n", result.MaxDepth)
	cycleStatus := "no"
	if result.Cycle {
		cycleStatus = "yes"
	}
	fmt.Fprintf(&report, "  Reachable cycle: %s\n", cycleStatus)
	if len(result.Impacts) == 0 {
		fmt.Fprintln(&report, "  No downstream dependents found.")
		return report.String(), nil
	}

	fmt.Fprintln(&report)
	fmt.Fprintln(&report, "Propagation")
	fmt.Fprintln(&report)

	impacts := orderedImpacts(result.Impacts)

	currentDepth := 0
	for _, impact := range impacts {
		if impact.Depth != currentDepth {
			if currentDepth != 0 {
				fmt.Fprintln(&report)
			}
			currentDepth = impact.Depth
			kind := "Indirect Dependents"
			if currentDepth == 1 {
				kind = "Direct Dependents"
			}
			fmt.Fprintf(&report, "  Depth %d - %s\n", currentDepth, kind)
		}

		path, exists := result.PathTo(impact.Node.BOMRef)
		if !exists {
			return "", fmt.Errorf("analysis path is unavailable for dependent %q", impact.Node.BOMRef)
		}
		pathLabels := make([]string, len(path))
		for i, node := range path {
			pathLabels[i] = componentLabel(node)
		}

		fmt.Fprintf(&report, "    %s\n", componentLabel(impact.Node))
		fmt.Fprintf(&report, "      BOM Ref: %s\n", impact.Node.BOMRef)
		fmt.Fprintf(&report, "      Path: %s\n", strings.Join(pathLabels, " -> "))
	}

	return report.String(), nil
}

func orderedImpacts(impacts []analysis.Impact) []analysis.Impact {
	ordered := append([]analysis.Impact(nil), impacts...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Depth != ordered[j].Depth {
			return ordered[i].Depth < ordered[j].Depth
		}
		return ordered[i].Node.BOMRef < ordered[j].Node.BOMRef
	})
	return ordered
}

func componentLabel(node graph.Node) string {
	switch {
	case node.Name == "" && node.Version == "":
		return node.BOMRef
	case node.Name == "":
		return node.Version
	case node.Version == "":
		return node.Name
	default:
		return node.Name + "@" + node.Version
	}
}
