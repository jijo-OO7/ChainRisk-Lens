package sbom

import "encoding/json"

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
	var document SBOM
	if err := json.Unmarshal(data, &document); err != nil {
		return SBOM{}, err
	}
	return document, nil
}