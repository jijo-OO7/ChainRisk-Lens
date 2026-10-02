package sbom

import (
	"os"
	"reflect"
	"testing"
)

func TestParse(t *testing.T) {
	data, err := os.ReadFile("../../testdata/minimal-cyclonedx.json")
	if err != nil {
		t.Fatal(err)
	}

	got, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}

	want := SBOM{
		Components: []Component{
			{Name: "app", Version: "1.0.0", BOMRef: "app@1.0.0"},
			{Name: "library", Version: "2.3.4", BOMRef: "library@2.3.4"},
		},
		Dependencies: []Dependency{
			{Ref: "app@1.0.0", DependsOn: []string{"library@2.3.4"}},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Parse() = %#v, want %#v", got, want)
	}
}

func TestParseRequiresCycloneDXFormat(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		wantErr string
	}{
		{
			name:    "missing format",
			data:    `{"components":[],"dependencies":[]}`,
			wantErr: "missing CycloneDX bomFormat",
		},
		{
			name:    "other format",
			data:    `{"bomFormat":"SPDX","components":[],"dependencies":[]}`,
			wantErr: `unsupported bomFormat "SPDX"`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Parse([]byte(test.data)); err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("Parse() error = %v, want error containing %q", err, test.wantErr)
			}
		})
	}
}

func TestParseRejectsMalformedJSON(t *testing.T) {
	if _, err := Parse([]byte(`{"components":`)); err == nil {
		t.Fatal("Parse() error = nil, want malformed JSON error")
	}
}