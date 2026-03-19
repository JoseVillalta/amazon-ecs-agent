//go:build codegen
// +build codegen

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//	http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package main

import (
	"regexp"
	"strings"
	"testing"
)

// apiModelPath is the relative path from the gogenerate directory to the API model.
const apiModelPath = "../acs/model/api/api-2.json"

// copyrightFilePath is the relative path from the gogenerate directory to the copyright file.
const copyrightFilePath = "../../../scripts/copyright_file"

// generateOutput calls the generate function and returns the output as a string.
// It fails the test immediately if generation returns an error.
func generateOutput(t *testing.T) string {
	t.Helper()
	out, err := generate(apiModelPath, copyrightFilePath)
	if err != nil {
		t.Fatalf("generate() returned an error: %v", err)
	}
	return string(out)
}

// TestExceptionFiltering verifies that exception types are excluded from the
// generated output. The API model defines several exception shapes that must
// not appear as struct definitions in the generated code.
func TestExceptionFiltering(t *testing.T) {
	t.Parallel()

	output := generateOutput(t)

	exceptions := []struct {
		name string
	}{
		{"AccessDeniedException"},
		{"BadRequestException"},
		{"InvalidClusterException"},
		{"InvalidInstanceException"},
		{"InactiveInstanceException"},
		{"ServerException"},
	}

	for _, tc := range exceptions {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Check that no struct definition exists for this exception type.
			pattern := `type ` + tc.name + ` struct`
			if strings.Contains(output, pattern) {
				t.Errorf("Generated output should not contain exception type %q, but found %q.", tc.name, pattern)
			}
		})
	}
}

// TestNoValidateMethods verifies that the generated output contains zero
// Validate() method signatures. The simplified generator omits validation
// methods to avoid the aws-sdk-go v1 dependency on request.ErrInvalidParams.
func TestNoValidateMethods(t *testing.T) {
	t.Parallel()

	output := generateOutput(t)

	// Match any Validate method signature like "func (s Foo) Validate() error".
	re := regexp.MustCompile(`func \(s \w+\) Validate\(\)`)
	matches := re.FindAllString(output, -1)
	if len(matches) != 0 {
		t.Errorf("Expected zero Validate() methods, but found %d: %v.", len(matches), matches)
	}
}

// TestNoAwsSdkGoImports verifies that the generated output contains no import
// paths from the aws-sdk-go v1 module. The simplified generator must produce
// code with zero aws-sdk-go dependencies.
func TestNoAwsSdkGoImports(t *testing.T) {
	t.Parallel()

	output := generateOutput(t)

	if strings.Contains(output, "github.com/aws/aws-sdk-go/") {
		t.Error("Generated output must not contain any github.com/aws/aws-sdk-go/ imports.")
	}
}

// TestOnlyFmtImport verifies that the only import in the generated file is the
// "fmt" package from the standard library. No other imports should be present.
func TestOnlyFmtImport(t *testing.T) {
	t.Parallel()

	output := generateOutput(t)

	// Extract all import declarations from the generated output.
	re := regexp.MustCompile(`import\s+"([^"]+)"`)
	matches := re.FindAllStringSubmatch(output, -1)

	if len(matches) != 1 {
		var imports []string
		for _, m := range matches {
			imports = append(imports, m[1])
		}
		t.Fatalf("Expected exactly one import declaration, but found %d: %v.", len(matches), imports)
	}

	if matches[0][1] != "fmt" {
		t.Errorf("Expected the sole import to be \"fmt\", but got %q.", matches[0][1])
	}
}

// TestCopyrightHeader verifies that the generated file starts with the Apache
// 2.0 copyright header and includes the "DO NOT EDIT" marker comment.
func TestCopyrightHeader(t *testing.T) {
	t.Parallel()

	output := generateOutput(t)

	tests := []struct {
		name    string
		check   func(string) bool
		message string
	}{
		{
			name:    "StartsWithComment",
			check:   func(s string) bool { return strings.HasPrefix(s, "//") },
			message: "Generated output should start with a comment line (copyright header).",
		},
		{
			name:    "ContainsCopyright",
			check:   func(s string) bool { return strings.Contains(s, "Copyright") },
			message: "Generated output should contain the word \"Copyright\" in the header.",
		},
		{
			name:    "ContainsApacheLicense",
			check:   func(s string) bool { return strings.Contains(s, "Apache License") },
			message: "Generated output should reference the Apache License.",
		},
		{
			name:    "ContainsDONOTEDIT",
			check:   func(s string) bool { return strings.Contains(s, "DO NOT EDIT") },
			message: "Generated output should contain the \"DO NOT EDIT\" marker.",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if !tc.check(output) {
				t.Error(tc.message)
			}
		})
	}
}

// TestRequiredFieldTags verifies that required fields omit the ",omitempty"
// suffix in their JSON tags, while optional fields include it. The Device
// shape has "hostPath" as required and "containerPath" as optional.
func TestRequiredFieldTags(t *testing.T) {
	t.Parallel()

	output := generateOutput(t)

	tests := []struct {
		name        string
		contains    string
		notContains string
		message     string
	}{
		{
			name:     "HostPathRequired",
			contains: `json:"hostPath"`,
			message:  "Device.HostPath should have json:\"hostPath\" without omitempty because it is required.",
		},
		{
			name:        "HostPathNoOmitempty",
			notContains: `json:"hostPath,omitempty"`,
			message:     "Device.HostPath must not have omitempty because it is a required field.",
		},
		{
			name:     "ContainerPathOptional",
			contains: `json:"containerPath,omitempty"`,
			message:  "Device.ContainerPath should have json:\"containerPath,omitempty\" because it is optional.",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.contains != "" && !strings.Contains(output, tc.contains) {
				t.Error(tc.message)
			}
			if tc.notContains != "" && strings.Contains(output, tc.notContains) {
				t.Error(tc.message)
			}
		})
	}
}

// TestOperationInputOutputTypes verifies that the generator produces Input and
// Output struct types for operations defined in the API model. These types are
// required for compatibility with code that references operation-derived types.
func TestOperationInputOutputTypes(t *testing.T) {
	t.Parallel()

	output := generateOutput(t)

	types := []struct {
		name string
	}{
		{"AttachInstanceNetworkInterfacesInput"},
		{"AttachInstanceNetworkInterfacesOutput"},
	}

	for _, tc := range types {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pattern := "type " + tc.name + " struct"
			if !strings.Contains(output, pattern) {
				t.Errorf("Generated output should contain operation type %q, but it was not found.", tc.name)
			}
		})
	}
}
