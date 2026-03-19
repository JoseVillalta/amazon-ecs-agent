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

// This is a simplified code generator that reads api-2.json and produces plain
// Go structs with JSON tags and String()/GoString() methods. It has zero
// aws-sdk-go v1 dependencies.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/format"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"
	"unicode"
)

// APIModel represents the top-level structure of an AWS API model JSON file.
type APIModel struct {
	Metadata   Metadata             `json:"metadata"`
	Operations map[string]Operation `json:"operations"`
	Shapes     map[string]Shape     `json:"shapes"`
}

// Metadata holds service metadata from the API model.
type Metadata struct {
	EndpointPrefix string `json:"endpointPrefix"`
}

// Operation represents a single API operation with optional input and output shapes.
type Operation struct {
	Name   string    `json:"name"`
	Input  *ShapeRef `json:"input"`
	Output *ShapeRef `json:"output"`
}

// ShapeRef is a reference to a shape by name.
type ShapeRef struct {
	Shape string `json:"shape"`
}

// Shape represents a type definition in the API model.
type Shape struct {
	Type      string               `json:"type"`
	Required  []string             `json:"required"`
	Members   map[string]MemberRef `json:"members"`
	Member    *ShapeRef            `json:"member"`
	Key       *ShapeRef            `json:"key"`
	Value     *ShapeRef            `json:"value"`
	Exception bool                 `json:"exception"`
	Enum      []string             `json:"enum"`
	Sensitive bool                 `json:"sensitive"`
	Box       bool                 `json:"box"`
}

// MemberRef is a reference from a struct member to its shape.
type MemberRef struct {
	Shape string `json:"shape"`
}

// StructField holds the resolved information for a single struct field.
type StructField struct {
	FieldName string
	GoType    string
	JSONTag   string
	TypeTag   string
	Required  bool
	EnumName  string
	Sensitive bool
}

// StructDef holds all information needed to render a single struct definition.
type StructDef struct {
	StructName string
	Fields     []StructField
}

// resolveGoType maps an API model shape name to its Go type string.
func resolveGoType(shapeName string, shapes map[string]Shape) string {
	shape, ok := shapes[shapeName]
	if !ok {
		log.Fatalf("Unknown shape referenced: %s", shapeName)
	}
	switch shape.Type {
	case "string":
		return "*string"
	case "integer":
		return "*int64"
	case "long":
		return "*int64"
	case "boolean":
		return "*bool"
	case "double":
		return "*float64"
	case "list":
		if shape.Member == nil {
			log.Fatalf("List shape %s has no member definition.", shapeName)
		}
		elemType := resolveGoType(shape.Member.Shape, shapes)
		// For list elements, ensure pointer type for primitives.
		if !strings.HasPrefix(elemType, "*") && !strings.HasPrefix(elemType, "[") && !strings.HasPrefix(elemType, "map[") {
			elemType = "*" + elemType
		}
		return "[]" + elemType
	case "map":
		if shape.Value == nil {
			log.Fatalf("Map shape %s has no value definition.", shapeName)
		}
		valType := resolveGoType(shape.Value.Shape, shapes)
		if !strings.HasPrefix(valType, "*") && !strings.HasPrefix(valType, "[") && !strings.HasPrefix(valType, "map[") {
			valType = "*" + valType
		}
		return "map[string]" + valType
	case "structure":
		return "*" + shapeName
	default:
		log.Fatalf("Unsupported shape type %q for shape %s.", shape.Type, shapeName)
		return ""
	}
}

// resolveTypeTag returns the type tag value for a member's referenced shape.
func resolveTypeTag(shapeName string, shapes map[string]Shape) string {
	shape, ok := shapes[shapeName]
	if !ok {
		return ""
	}
	return shape.Type
}

// resolveEnumName returns the enum shape name if the member's shape is a string
// with enum values, or if it is a list whose element is a string enum.
func resolveEnumName(shapeName string, shapes map[string]Shape) string {
	shape, ok := shapes[shapeName]
	if !ok {
		return ""
	}
	// Direct string enum.
	if shape.Type == "string" && len(shape.Enum) > 0 {
		return shapeName
	}
	// List of string enums.
	if shape.Type == "list" && shape.Member != nil {
		memberShape, mok := shapes[shape.Member.Shape]
		if mok && memberShape.Type == "string" && len(memberShape.Enum) > 0 {
			return shape.Member.Shape
		}
	}
	return ""
}

// resolveSensitive returns true if the referenced shape has sensitive: true.
func resolveSensitive(shapeName string, shapes map[string]Shape) bool {
	shape, ok := shapes[shapeName]
	if !ok {
		return false
	}
	return shape.Sensitive
}

// pascalCase capitalizes the first letter of a string.
func pascalCase(s string) string {
	if s == "" {
		return s
	}
	runes := []rune(s)
	runes[0] = unicode.ToUpper(runes[0])
	return string(runes)
}

// buildStructDef builds a StructDef from a shape name and its definition.
func buildStructDef(structName string, shape Shape, shapes map[string]Shape) StructDef {
	requiredSet := make(map[string]bool, len(shape.Required))
	for _, r := range shape.Required {
		requiredSet[r] = true
	}

	fields := make([]StructField, 0, len(shape.Members))
	for memberName, memberRef := range shape.Members {
		goFieldName := pascalCase(memberName)
		goType := resolveGoType(memberRef.Shape, shapes)
		typeTag := resolveTypeTag(memberRef.Shape, shapes)
		enumName := resolveEnumName(memberRef.Shape, shapes)
		sensitive := resolveSensitive(memberRef.Shape, shapes)
		isRequired := requiredSet[memberName]

		jsonTag := memberName
		if !isRequired {
			jsonTag += ",omitempty"
		}

		fields = append(fields, StructField{
			FieldName: goFieldName,
			GoType:    goType,
			JSONTag:   jsonTag,
			TypeTag:   typeTag,
			Required:  isRequired,
			EnumName:  enumName,
			Sensitive: sensitive,
		})
	}

	// Sort fields alphabetically by Go field name.
	sort.Slice(fields, func(i, j int) bool {
		return fields[i].FieldName < fields[j].FieldName
	})

	return StructDef{
		StructName: structName,
		Fields:     fields,
	}
}

// structTemplate is the text/template for rendering a single struct with its methods.
var structTemplate = template.Must(template.New("struct").Parse(`type {{.StructName}} struct {
	_ struct{} ` + "`" + `type:"structure"` + "`" + `
{{range .Fields}}
	{{.FieldName}} {{.GoType}} ` + "`" + `json:"{{.JSONTag}}" type:"{{.TypeTag}}"{{if .Required}} required:"true"{{end}}{{if .EnumName}} enum:"{{.EnumName}}"{{end}}{{if .Sensitive}} sensitive:"true"{{end}}` + "`" + `
{{end}}}

// String returns the string representation of the struct.
func (s {{.StructName}}) String() string {
	type noMethod {{.StructName}}
	return fmt.Sprintf("%+v", noMethod(s))
}

// GoString returns the string representation of the struct.
func (s {{.StructName}}) GoString() string {
	return s.String()
}
`))

// buildCopyrightHeader reads the copyright file and formats it as Go comment lines.
func buildCopyrightHeader(copyrightFile string) string {
	contents, err := os.ReadFile(copyrightFile)
	if err != nil {
		log.Fatalf("Error reading copyright file: %v", err)
	}

	copyrightText := string(contents)
	copyrightText += "\nCode generated by [netlib/gogenerate/awssdk.go] DO NOT EDIT."

	var b strings.Builder
	for i, line := range strings.Split(copyrightText, "\n") {
		if i != 0 {
			b.WriteString("\n")
		}
		b.WriteString("//")
		if line != "" {
			b.WriteString(" ")
			b.WriteString(line)
		}
	}
	b.WriteString("\n")
	return b.String()
}

// generate reads the API model and copyright file, then returns the formatted
// Go source code as a byte slice. This function contains the core generation
// logic and is called by main() as well as unit tests.
func generate(apiFile, copyrightFile string) ([]byte, error) {
	// Read and parse the API model.
	data, err := os.ReadFile(apiFile)
	if err != nil {
		return nil, fmt.Errorf("reading API model file %s: %w", apiFile, err)
	}

	var model APIModel
	if err := json.Unmarshal(data, &model); err != nil {
		return nil, fmt.Errorf("parsing API model JSON: %w", err)
	}

	// Build the copyright header.
	header := buildCopyrightHeader(copyrightFile)

	// Collect all non-exception structure shapes sorted by name.
	var structNames []string
	for name, shape := range model.Shapes {
		if shape.Type == "structure" && !shape.Exception {
			structNames = append(structNames, name)
		}
	}
	sort.Strings(structNames)

	// Collect operation Input/Output type names sorted alphabetically.
	type opType struct {
		TypeName  string
		ShapeName string // Empty string means no referenced shape (empty struct).
	}
	var opTypes []opType
	opTypeSet := make(map[string]bool)

	var opNames []string
	for opName := range model.Operations {
		opNames = append(opNames, opName)
	}
	sort.Strings(opNames)

	for _, opName := range opNames {
		op := model.Operations[opName]
		inputName := opName + "Input"
		if !opTypeSet[inputName] {
			opTypeSet[inputName] = true
			shapeName := ""
			if op.Input != nil {
				shapeName = op.Input.Shape
			}
			opTypes = append(opTypes, opType{TypeName: inputName, ShapeName: shapeName})
		}
		outputName := opName + "Output"
		if !opTypeSet[outputName] {
			opTypeSet[outputName] = true
			shapeName := ""
			if op.Output != nil {
				shapeName = op.Output.Shape
			}
			opTypes = append(opTypes, opType{TypeName: outputName, ShapeName: shapeName})
		}
	}

	// Render all structs into a buffer.
	var buf bytes.Buffer

	// Render non-exception structure shapes.
	for _, name := range structNames {
		shape := model.Shapes[name]
		sd := buildStructDef(name, shape, model.Shapes)
		if err := structTemplate.Execute(&buf, sd); err != nil {
			return nil, fmt.Errorf("rendering struct %s: %w", name, err)
		}
		buf.WriteString("\n")
	}

	// Render operation Input/Output types.
	for _, ot := range opTypes {
		var sd StructDef
		if ot.ShapeName == "" {
			// No referenced shape — emit an empty struct.
			sd = StructDef{StructName: ot.TypeName}
		} else {
			refShape, ok := model.Shapes[ot.ShapeName]
			if !ok {
				return nil, fmt.Errorf("operation references unknown shape: %s", ot.ShapeName)
			}
			sd = buildStructDef(ot.TypeName, refShape, model.Shapes)
		}
		if err := structTemplate.Execute(&buf, sd); err != nil {
			return nil, fmt.Errorf("rendering operation type %s: %w", ot.TypeName, err)
		}
		buf.WriteString("\n")
	}

	// Assemble the full source file.
	var src bytes.Buffer
	src.WriteString(header)
	src.WriteString("\npackage ecsacs\n\nimport \"fmt\"\n\n")
	src.Write(buf.Bytes())

	// Format with go/format.
	formatted, err := format.Source(src.Bytes())
	if err != nil {
		return nil, fmt.Errorf("formatting generated code: %w\nGenerated source:\n%s", err, src.String())
	}

	return formatted, nil
}

func main() {
	copyrightFile := flag.String("copyright_file", "", "Path to copyright header file.")
	flag.Parse()

	if copyrightFile == nil || *copyrightFile == "" {
		log.Fatal("copyright_file flag must be set.")
	}

	apiFile := "./api/api-2.json"
	formatted, err := generate(apiFile, *copyrightFile)
	if err != nil {
		log.Fatalf("Generation failed: %v", err)
	}

	// Read the model again to get the output directory from metadata.
	data, err := os.ReadFile(apiFile)
	if err != nil {
		log.Fatalf("Error re-reading API model file %s: %v", apiFile, err)
	}
	var model APIModel
	if err := json.Unmarshal(data, &model); err != nil {
		log.Fatalf("Error parsing API model JSON: %v", err)
	}

	// Write to ecsacs/api.go.
	outDir := model.Metadata.EndpointPrefix
	if err := os.MkdirAll(outDir, 0755); err != nil {
		log.Fatalf("Error creating output directory %s: %v", outDir, err)
	}
	outFile := filepath.Join(outDir, "api.go")
	if err := os.WriteFile(outFile, formatted, 0644); err != nil {
		log.Fatalf("Error writing output file %s: %v", outFile, err)
	}

	fmt.Printf("Generated %s successfully.\n", outFile)
}
