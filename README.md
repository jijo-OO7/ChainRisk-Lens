# ChainRisk Lens

ChainRisk Lens is an open-source prototype for analyzing dependency impact from a CycloneDX SBOM and optionally using a local language model to explain the resulting evidence.

Its core design separates **deterministic supply-chain evidence** from **AI-assisted investigation**. The dependency graph and impact analysis establish what is reachable from an assumed-compromised target. The model can explain that evidence, but it does not establish new dependency or vulnerability facts.

## What It Does

A software dependency compromise can propagate through applications that depend on the affected package. ChainRisk Lens reads the dependency relationships supplied in a CycloneDX JSON SBOM, identifies downstream dependents, computes their shortest propagation depths and paths, and reports reachable cycles.

The `analyze` command is deterministic and works without Ollama, a model, or network access. The optional `investigate` command sends the validated evidence and a question to an Ollama-compatible model endpoint and validates the model's structured response against the supplied evidence.

## Architecture

```text
CycloneDX SBOM
	|
	v
Parser / normalized component view
	|
	v
BOM-ref dependency graph
	|
	v
Deterministic impact analysis
	|
	v
Validated investigation evidence
	|
	v
Optional model-backed investigation
	|
	v
Human analysis / JSON analysis / human investigation report
```

The analysis output is target-centric. The target is assumed compromised and has depth 0; downstream dependents are listed separately with depths starting at 1. Paths are shortest paths selected deterministically, and reachable cycles are reported as graph evidence.

## Current Capabilities

- Parse CycloneDX JSON, requiring `bomFormat: "CycloneDX"`, into a small normalized component/dependency representation.
- Build a directed dependency graph keyed by CycloneDX BOM-ref, preserving component name and version.
- Reject duplicate BOM-REFs and unresolved dependency references while suppressing duplicate edges.
- Calculate target-centric potential propagation, shortest dependency depth and path, and reachable-cycle information.
- Produce deterministic human-readable or JSON output from `analyze`.
- Convert analysis results into validated, path-aware investigation evidence.
- Optionally request a structured explanation through the provider-neutral model interface and Ollama's local HTTP API.
- Configure the investigation model and Ollama endpoint through command-line options.
- Run read-only environment diagnostics with `setup`.

The parser intentionally extracts only the component and dependency fields used by this MVP; it is not a complete CycloneDX document-preservation or validation library.

## Requirements

- **Go 1.25.0 or newer** to build or test from source.
- A CycloneDX JSON SBOM with a `bomFormat` field set to `CycloneDX` for analysis and investigation.
- Ollama and a model available to that runtime are optional for `analyze`, but required for the default local `investigate` workflow.
- Model memory and performance requirements depend on the selected model, quantization, runtime, and hardware. A model that works on one machine may not fit or run well on another.

The project uses only the Go standard library; no Ollama SDK or inference library is required. ChainRisk Lens does not bundle model weights, install Ollama, or download models.

## Build

From the repository root:

```sh
go build ./cmd/chainrisk-lens
```

To run without first producing a binary:

```sh
go run ./cmd/chainrisk-lens setup
```

## Setup Diagnostics

```sh
chainrisk-lens setup
```

`setup` is read-only. It reports the OS, CPU architecture, best-effort WSL status on Linux, core analysis readiness, local Ollama executable availability where applicable, API availability, and whether the configured default model is listed by the endpoint. The current setup command uses the defaults `http://localhost:11434` and `gemma4:e2b`; it does not accept runtime override flags, install software, start services, download models, or perform model inference. When a model is missing, it prints a manual `ollama pull` command but does not execute it.

## Analyze

Analyze a CycloneDX SBOM and show potential downstream reachability:

```sh
chainrisk-lens analyze testdata/minimal-cyclonedx.json \
  --target library@2.3.4
```

Emit machine-readable JSON instead:

```sh
chainrisk-lens analyze testdata/minimal-cyclonedx.json \
  --target library@2.3.4 \
  --format json
```

Human-readable output is the default. `--format human` is also supported. Analysis requires no Ollama installation or model.

## Investigate

To request an explanation, run Ollama locally, make the selected model available to Ollama, then invoke:

```sh
chainrisk-lens investigate testdata/minimal-cyclonedx.json \
  --target library@2.3.4 \
  --model qwen2.5:3b \
  --question "What could be affected if this component is compromised?"
```

`--model` selects the model tag sent to Ollama. `--ollama-url` selects the Ollama base URL; it defaults to `http://localhost:11434`. Both options accept either `--option value` or `--option=value`. For example:

```sh
chainrisk-lens investigate testdata/minimal-cyclonedx.json \
  --target library@2.3.4 \
  --model=qwen2.5:3b \
  --ollama-url=http://localhost:11434 \
  --question="Explain the potential propagation path."
```

The current CLI default model is `gemma4:e2b`; the example uses `qwen2.5:3b` as one configurable choice, not as a project-wide recommendation. Choose a model that fits the memory and performance available on your machine. ChainRisk Lens does not pull a missing model automatically.

## Security Model

- Deterministic graph and analysis output is the authority for supplied dependency relationships, target identity, downstream reachability, depth, paths, and cycle information.
- The target is assumed compromised because the user selected it for analysis.
- A downstream dependency is **potentially affected or exposed** by propagation; graph reachability does not establish that it is compromised.
- The investigation prompt treats evidence JSON fields as untrusted data, not instructions, and tells the model not to invent security facts.
- The model receives deterministic evidence and must return structured findings with references to supplied BOM-REFs. Result validation checks response structure and that cited BOM-REFs exist in the supplied evidence; it cannot prove that arbitrary prose is semantically entailed by those citations.
- Facts not established by the input should remain unknown or be described as not established by the supplied evidence.

## Limitations

- Analysis depends on the dependency relationships present in the supplied CycloneDX SBOM; missing or incomplete SBOM data can limit reachability results.
- The parser supports a focused CycloneDX JSON subset, not every CycloneDX feature or other SBOM formats.
- ChainRisk Lens does not currently look up CVEs, scan for vulnerabilities, independently verify exploitability, or prove that downstream components are compromised.
- AI output is an interpretation of supplied evidence. Structural and BOM-REF validation do not guarantee the semantic correctness of generated prose.
- Model availability, resource use, and output quality vary by model and local runtime.

## Development

Run the tests and static analysis from the repository root:

```sh
go test ./...
go vet ./...
git diff --check
```

The main packages are `internal/sbom` (CycloneDX parsing), `internal/graph` (dependency graph), `internal/analysis` (deterministic impact evidence), `internal/investigation` (evidence and result contracts), `internal/agent` (prompt, model adapter, and Ollama HTTP client), and `cmd/chainrisk-lens` (CLI orchestration and presentation).
