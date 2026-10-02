package sbom

import (
	"encoding/json"
	"errors"
	"fmt"
)

// SBOM contains the component and dependency data extracted from a CycloneDX document.
type SBOM struct {
	Components   []Component   `json:"components"`
	Dependencies []Dependency `json:"dependencies"`
}

// Component identifies a software component in the SBOM.
type Component struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	BOMRef  string `json:"bom-ref"`
}

// Dependency lists the component references directly required by Ref.
type Dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

// Parse extracts components and dependency relationships from CycloneDX JSON.
func Parse(data []byte) (SBOM, error) {
	var document struct {
		BOMFormat    string        `json:"bomFormat"`
		Components   []Component   `json:"components"`
		Dependencies []Dependency `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return SBOM{}, err
	}
	if document.BOMFormat == "" {
		return SBOM{}, errors.New("missing CycloneDX bomFormat")
	}
	if document.BOMFormat != "CycloneDX" {
		return SBOM{}, fmt.Errorf("unsupported bomFormat %q: expected CycloneDX", document.BOMFormat)
	}
	return SBOM{Components: document.Components, Dependencies: document.Dependencies}, nil
}