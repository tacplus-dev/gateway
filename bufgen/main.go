// bufgen scans tacplus/proto for services with google.api.http annotations,
// generates buf.yaml + buf.gen.yaml, runs buf generate, and produces a
// routes.go file that exports gateway routes and proxy service mappings.
//
// Usage: go run ./bufgen [tacplus-dir]
//
// If tacplus-dir is omitted, defaults to "tacplus" relative to cwd.
package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"text/template"
)

// serviceInfo holds metadata extracted from an annotated proto file.
type serviceInfo struct {
	ProtoPackage string // e.g., "fleetwood"
	ServiceName  string // e.g., "FleetwoodService"
	GoImportPath string // e.g., "gitlab.com/.../tacplus/types/services/fleetwood"
	GoAlias      string // e.g., "fleetwood_gw"
}

func main() {
	tacplusDir := "tacplus"
	if len(os.Args) > 1 {
		tacplusDir = os.Args[1]
	}

	protoDir := filepath.Join(tacplusDir, "proto")
	typesDir := filepath.Join(tacplusDir, "types")

	if _, err := os.Stat(protoDir); os.IsNotExist(err) {
		log.Fatalf("proto directory not found: %s", protoDir)
	}

	// Find the go_package module prefix from any service proto.
	modulePrefix, err := findModulePrefix(protoDir)
	if err != nil {
		log.Fatalf("could not determine module prefix: %v", err)
	}

	// Scan for protos with google.api.http annotations and extract service info.
	services, err := findAnnotatedServices(protoDir)
	if err != nil {
		log.Fatalf("scanning protos: %v", err)
	}

	if len(services) == 0 {
		fmt.Println("bufgen: no protos with google.api.http annotations found, skipping")
		return
	}

	var names []string
	for _, s := range services {
		names = append(names, s.ProtoPackage)
	}
	fmt.Printf("bufgen: found %d annotated service(s): %s\n", len(services), strings.Join(names, ", "))

	// Write buf.yaml
	bufYaml := filepath.Join(tacplusDir, "buf.yaml")
	if err := writeBufYaml(bufYaml); err != nil {
		log.Fatalf("writing buf.yaml: %v", err)
	}

	// Write buf.gen.yaml
	bufGenYaml := filepath.Join(tacplusDir, "buf.gen.yaml")
	if err := writeBufGenYaml(bufGenYaml, modulePrefix); err != nil {
		log.Fatalf("writing buf.gen.yaml: %v", err)
	}

	// Run buf generate
	fmt.Println("bufgen: running buf generate...")
	cmd := exec.Command("buf", "generate")
	cmd.Dir = tacplusDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("buf generate failed: %v", err)
	}

	// Generate routes.go
	routesDir := filepath.Join(tacplusDir, "routes")
	if err := os.MkdirAll(routesDir, 0755); err != nil {
		log.Fatalf("creating routes dir: %v", err)
	}
	routesFile := filepath.Join(routesDir, "routes.go")
	if err := writeRoutesGo(routesFile, services); err != nil {
		log.Fatalf("writing routes.go: %v", err)
	}

	// Report what was generated
	var generated []string
	filepath.Walk(typesDir, func(path string, info os.FileInfo, err error) error {
		if err == nil && strings.HasSuffix(path, ".pb.gw.go") {
			rel, _ := filepath.Rel(tacplusDir, path)
			generated = append(generated, rel)
		}
		return nil
	})
	fmt.Printf("bufgen: generated %d gateway stub(s)\n", len(generated))
	for _, f := range generated {
		fmt.Printf("  %s\n", f)
	}
	fmt.Printf("bufgen: generated routes/routes.go with %d service(s)\n", len(services))
}

// findModulePrefix extracts the module prefix from go_package options.
// Given go_package = "gitlab.com/.../tacplus/types/services/fleetwood",
// returns "gitlab.com/.../tacplus/types".
func findModulePrefix(protoDir string) (string, error) {
	goPackageRe := regexp.MustCompile(`option\s+go_package\s*=\s*"([^"]+)"`)

	var prefix string
	filepath.Walk(protoDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".proto") || prefix != "" {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			if m := goPackageRe.FindStringSubmatch(scanner.Text()); len(m) > 1 {
				pkg := m[1]
				// Strip the ";alias" suffix if present
				if idx := strings.Index(pkg, ";"); idx > 0 {
					pkg = pkg[:idx]
				}
				// Find /types/ and take everything up to and including it
				if idx := strings.Index(pkg, "/types/"); idx > 0 {
					prefix = pkg[:idx+len("/types")]
				} else if idx := strings.Index(pkg, "/types"); idx > 0 && idx == len(pkg)-len("/types") {
					prefix = pkg
				}
				if prefix != "" {
					return filepath.SkipAll
				}
			}
		}
		return nil
	})

	if prefix == "" {
		return "", fmt.Errorf("no go_package with /types/ found in %s", protoDir)
	}
	return prefix, nil
}

// findAnnotatedServices scans protoDir for .proto files with google.api.http
// annotations and extracts the proto package, service name, and go_package.
// It finds the specific service block that contains the annotations by tracking
// brace depth.
func findAnnotatedServices(protoDir string) ([]serviceInfo, error) {
	packageRe := regexp.MustCompile(`^package\s+(\w+)\s*;`)
	serviceRe := regexp.MustCompile(`^service\s+(\w+)\s*\{`)
	goPackageRe := regexp.MustCompile(`option\s+go_package\s*=\s*"([^"]+)"`)
	httpRe := regexp.MustCompile(`google\.api\.http`)

	var result []serviceInfo
	err := filepath.Walk(protoDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".proto") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		// Quick check: skip files without any HTTP annotations.
		if !httpRe.Match(data) {
			return nil
		}

		// Parse the proto file to find which service contains the annotations.
		var protoPackage, goPackage string
		var currentService string
		braceDepth := 0
		inService := false
		annotatedServices := make(map[string]bool)

		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			line := scanner.Text()
			trimmed := strings.TrimSpace(line)

			if m := packageRe.FindStringSubmatch(trimmed); len(m) > 1 {
				protoPackage = m[1]
			}
			if m := goPackageRe.FindStringSubmatch(trimmed); len(m) > 1 {
				goPackage = m[1]
				if idx := strings.Index(goPackage, ";"); idx > 0 {
					goPackage = goPackage[:idx]
				}
			}

			if m := serviceRe.FindStringSubmatch(trimmed); len(m) > 1 {
				currentService = m[1]
				inService = true
				braceDepth = 1
				continue
			}

			if inService {
				braceDepth += strings.Count(trimmed, "{") - strings.Count(trimmed, "}")
				if httpRe.MatchString(trimmed) {
					annotatedServices[currentService] = true
				}
				if braceDepth <= 0 {
					inService = false
					currentService = ""
				}
			}
		}

		for svcName := range annotatedServices {
			if protoPackage == "" || goPackage == "" {
				log.Printf("bufgen: warning: incomplete proto metadata in %s (package=%q go_package=%q)", path, protoPackage, goPackage)
				continue
			}
			result = append(result, serviceInfo{
				ProtoPackage: protoPackage,
				ServiceName:  svcName,
				GoImportPath: goPackage,
				GoAlias:      protoPackage + "_gw",
			})
		}
		return nil
	})

	sort.Slice(result, func(i, j int) bool {
		return result[i].ProtoPackage < result[j].ProtoPackage
	})

	return result, err
}

var routesTmpl = template.Must(template.New("routes").Parse(`// Code generated by bufgen. DO NOT EDIT.

package routes

import (
	"context"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
{{range .}}
	{{.GoAlias}} "{{.GoImportPath}}"
{{- end}}
)

// RegisterFunc is the signature of grpc-gateway's RegisterXxxHandlerFromEndpoint.
type RegisterFunc func(ctx context.Context, mux *runtime.ServeMux, endpoint string, opts []grpc.DialOption) error

// Route binds a gateway registration function to a service ID.
type Route struct {
	RegisterFunc RegisterFunc
	ServiceID    string
}

// GatewayRoutes returns the grpc-gateway routes for all annotated services.
var GatewayRoutes = []Route{
{{- range .}}
	{
		RegisterFunc: {{.GoAlias}}.Register{{.ServiceName}}HandlerFromEndpoint,
		ServiceID:    "{{.ProtoPackage}}",
	},
{{- end}}
}

// ProxyServiceMapping maps proto package names to service IDs.
// Used by the transparent gRPC proxy to resolve downstream targets.
var ProxyServiceMapping = map[string]string{
{{- range .}}
	"{{.ProtoPackage}}": "{{.ProtoPackage}}",
{{- end}}
}
`))

func writeRoutesGo(path string, services []serviceInfo) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return routesTmpl.Execute(f, services)
}

func writeBufYaml(path string) error {
	content := `version: v2
modules:
  - path: proto
deps:
  - buf.build/googleapis/googleapis
lint:
  use:
    - STANDARD
  ignore:
    - proto/libs
    - proto/common
    - proto/google
breaking:
  use:
    - FILE
`
	return os.WriteFile(path, []byte(content), 0644)
}

func writeBufGenYaml(path, modulePrefix string) error {
	content := fmt.Sprintf(`version: v2
plugins:
  - remote: buf.build/grpc-ecosystem/gateway
    out: types
    opt:
      - module=%s
inputs:
  - directory: proto
`, modulePrefix)
	return os.WriteFile(path, []byte(content), 0644)
}
