package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"

	"github.com/jijo-OO7/chainrisk-lens/internal/agent"
	"github.com/jijo-OO7/chainrisk-lens/internal/analysis"
	"github.com/jijo-OO7/chainrisk-lens/internal/graph"
	"github.com/jijo-OO7/chainrisk-lens/internal/investigation"
	"github.com/jijo-OO7/chainrisk-lens/internal/sbom"
)

const (
	formatHuman          = "human"
	formatJSON           = "json"
	defaultOllamaBaseURL = "http://localhost:11434"
	defaultOllamaModel   = "gemma4:e2b"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	if err := execute(ctx, os.Args[1:], os.Stdout, os.Stderr, defaultInvestigatorFactory); err != nil {
		stop()
		os.Exit(1)
	}
	stop()
}

func run(args []string, output io.Writer) error {
	return runWithInvestigatorFactory(context.Background(), args, output, defaultInvestigatorFactory)
}

type investigatorFactory func(agent.OllamaConfig) (investigation.Investigator, error)

func execute(ctx context.Context, args []string, output, errorOutput io.Writer, factory investigatorFactory) error {
	err := runWithInvestigatorFactory(ctx, args, output, factory)
	if err != nil {
		fmt.Fprintln(errorOutput, "chainrisk-lens:", err)
	}
	return err
}

func runWithInvestigatorFactory(ctx context.Context, args []string, output io.Writer, factory investigatorFactory) error {
	if len(args) > 0 && args[0] == "investigate" {
		return runInvestigate(ctx, args[1:], output, factory)
	}
	return runAnalyze(args, output)
}

func runAnalyze(args []string, output io.Writer) error {
	if len(args) == 0 || args[0] != "analyze" {
		return errors.New("usage: chainrisk-lens analyze <sbom-file> --target <BOM-REF> | investigate <sbom-file> --target <BOM-REF> --question <question> [--model <tag>] [--ollama-url <url>]")
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

func runInvestigate(ctx context.Context, args []string, output io.Writer, factory investigatorFactory) error {
	options, err := parseInvestigateArgs(args)
	if err != nil {
		return err
	}

	data, err := os.ReadFile(options.sbomPath)
	if err != nil {
		return fmt.Errorf("read SBOM %q: %w", options.sbomPath, err)
	}
	document, err := sbom.Parse(data)
	if err != nil {
		return fmt.Errorf("parse SBOM %q: %w", options.sbomPath, err)
	}

	dependencyGraph, err := graph.New(document)
	if err != nil {
		return fmt.Errorf("build dependency graph: %w", err)
	}
	analysisResult, err := analysis.Analyze(dependencyGraph, options.targetBOMRef)
	if err != nil {
		return fmt.Errorf("analyze target %q: %w", options.targetBOMRef, err)
	}
	evidence, err := investigation.FromAnalysis(analysisResult)
	if err != nil {
		return fmt.Errorf("build investigation evidence: %w", err)
	}
	if factory == nil {
		return errors.New("investigator factory is nil")
	}
	investigator, err := factory(options.ollama)
	if err != nil {
		return fmt.Errorf("create investigator: %w", err)
	}
	if investigator == nil {
		return errors.New("investigator factory returned nil")
	}

	request := investigation.Request{Question: options.question}
	result, err := investigator.Investigate(ctx, request, evidence)
	if err != nil {
		return fmt.Errorf("investigate target %q: %w", options.targetBOMRef, err)
	}
	if err := result.Validate(evidence); err != nil {
		return fmt.Errorf("validate investigation result: %w", err)
	}

	report := formatInvestigationReport(request, evidence.Target, result)
	if _, err := io.WriteString(output, report); err != nil {
		return fmt.Errorf("write investigation report: %w", err)
	}
	return nil
}

func defaultInvestigatorFactory(config agent.OllamaConfig) (investigation.Investigator, error) {
	model, err := agent.NewOllamaModel(config)
	if err != nil {
		return nil, err
	}
	return agent.New(model)
}

type investigateOptions struct {
	sbomPath     string
	targetBOMRef string
	question     string
	ollama       agent.OllamaConfig
}

func parseInvestigateArgs(args []string) (investigateOptions, error) {
	options := investigateOptions{ollama: agent.OllamaConfig{
		BaseURL: defaultOllamaBaseURL,
		Model:   defaultOllamaModel,
	}}
	targetProvided := false
	questionProvided := false
	modelProvided := false
	ollamaURLProvided := false

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--target":
			if targetProvided {
				return investigateOptions{}, errors.New("--target may only be specified once")
			}
			if i+1 >= len(args) || args[i+1] == "" {
				return investigateOptions{}, errors.New("--target requires a BOM-REF")
			}
			options.targetBOMRef = args[i+1]
			targetProvided = true
			i++
		case strings.HasPrefix(arg, "--target="):
			if targetProvided {
				return investigateOptions{}, errors.New("--target may only be specified once")
			}
			options.targetBOMRef = strings.TrimPrefix(arg, "--target=")
			if options.targetBOMRef == "" {
				return investigateOptions{}, errors.New("--target requires a BOM-REF")
			}
			targetProvided = true
		case arg == "--question":
			if questionProvided {
				return investigateOptions{}, errors.New("--question may only be specified once")
			}
			if i+1 >= len(args) || strings.TrimSpace(args[i+1]) == "" {
				return investigateOptions{}, errors.New("--question requires a non-empty question")
			}
			options.question = args[i+1]
			questionProvided = true
			i++
		case strings.HasPrefix(arg, "--question="):
			if questionProvided {
				return investigateOptions{}, errors.New("--question may only be specified once")
			}
			options.question = strings.TrimPrefix(arg, "--question=")
			if strings.TrimSpace(options.question) == "" {
				return investigateOptions{}, errors.New("--question requires a non-empty question")
			}
			questionProvided = true
		case arg == "--model":
			if modelProvided {
				return investigateOptions{}, errors.New("--model may only be specified once")
			}
			if i+1 >= len(args) || strings.TrimSpace(args[i+1]) == "" {
				return investigateOptions{}, errors.New("--model requires a non-empty model name")
			}
			options.ollama.Model = strings.TrimSpace(args[i+1])
			modelProvided = true
			i++
		case strings.HasPrefix(arg, "--model="):
			if modelProvided {
				return investigateOptions{}, errors.New("--model may only be specified once")
			}
			options.ollama.Model = strings.TrimSpace(strings.TrimPrefix(arg, "--model="))
			if options.ollama.Model == "" {
				return investigateOptions{}, errors.New("--model requires a non-empty model name")
			}
			modelProvided = true
		case arg == "--ollama-url":
			if ollamaURLProvided {
				return investigateOptions{}, errors.New("--ollama-url may only be specified once")
			}
			if i+1 >= len(args) || strings.TrimSpace(args[i+1]) == "" {
				return investigateOptions{}, errors.New("--ollama-url requires a non-empty URL")
			}
			options.ollama.BaseURL = strings.TrimSpace(args[i+1])
			ollamaURLProvided = true
			i++
		case strings.HasPrefix(arg, "--ollama-url="):
			if ollamaURLProvided {
				return investigateOptions{}, errors.New("--ollama-url may only be specified once")
			}
			options.ollama.BaseURL = strings.TrimSpace(strings.TrimPrefix(arg, "--ollama-url="))
			if options.ollama.BaseURL == "" {
				return investigateOptions{}, errors.New("--ollama-url requires a non-empty URL")
			}
			ollamaURLProvided = true
		case strings.HasPrefix(arg, "-"):
			return investigateOptions{}, fmt.Errorf("unknown option %q", arg)
		default:
			if options.sbomPath != "" {
				return investigateOptions{}, fmt.Errorf("unexpected argument %q", arg)
			}
			options.sbomPath = arg
		}
	}

	if options.sbomPath == "" {
		return investigateOptions{}, errors.New("missing SBOM file path")
	}
	if !targetProvided {
		return investigateOptions{}, errors.New("missing required --target <BOM-REF>")
	}
	if !questionProvided {
		return investigateOptions{}, errors.New("missing required --question <question>")
	}
	return options, nil
}

func formatInvestigationReport(request investigation.Request, target investigation.Component, result investigation.Result) string {
	var report strings.Builder
	fmt.Fprintln(&report, "Investigation")
	fmt.Fprintf(&report, "Question: %s\n\n", request.Question)
	fmt.Fprintln(&report, "Compromised Target:")
	fmt.Fprintf(&report, "  %s %s\n\n", target.BOMRef, investigationComponentLabel(target))
	fmt.Fprintln(&report, "Summary:")
	fmt.Fprintf(&report, "  %s\n\n", result.Summary)

	fmt.Fprintln(&report, "Findings:")
	if len(result.Findings) == 0 {
		fmt.Fprintln(&report, "  None.")
	} else {
		for index, finding := range result.Findings {
			fmt.Fprintf(&report, "  %d. %s\n", index+1, finding.Statement)
			var bomRefs []string
			for _, evidenceRef := range finding.Evidence {
				bomRefs = append(bomRefs, evidenceRef.BOMRefs...)
			}
			fmt.Fprintf(&report, "     Evidence: %s\n", strings.Join(bomRefs, ", "))
		}
	}

	fmt.Fprintln(&report)
	fmt.Fprintln(&report, "Uncertainty:")
	writeReportList(&report, result.Uncertainty)
	fmt.Fprintln(&report)
	fmt.Fprintln(&report, "Next Steps:")
	writeReportList(&report, result.NextSteps)
	return report.String()
}

func writeReportList(report *strings.Builder, items []string) {
	if len(items) == 0 {
		fmt.Fprintln(report, "  None.")
		return
	}
	for _, item := range items {
		fmt.Fprintf(report, "  - %s\n", item)
	}
}

func investigationComponentLabel(component investigation.Component) string {
	switch {
	case component.Name == "" && component.Version == "":
		return component.BOMRef
	case component.Name == "":
		return component.Version
	case component.Version == "":
		return component.Name
	default:
		return component.Name + "@" + component.Version
	}
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
