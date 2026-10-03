package state

import (
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite generated docs")

func TestGeneratedDocs(t *testing.T) {
	for file, content := range map[string]string{
		"field-catalog.md": RenderFieldCatalog(),
		"kube-series.md":   RenderKubeSeriesDoc(),
	} {
		path := filepath.Join("..", "..", "docs", file)
		if *update {
			if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%v (run go test ./internal/state -run TestGeneratedDocs -update)", err)
		}
		if string(got) != content {
			t.Fatalf("docs/%s is out of date: run go test ./internal/state -run TestGeneratedDocs -update", file)
		}
		if strings.ContainsAny(content, "\u2013\u2014") {
			t.Fatalf("docs/%s contains a dash character that is not allowed", file)
		}
	}
}

var kindRe = regexp.MustCompile(`^([a-z0-9.]+/)?[A-Z][A-Za-z]+$`)

func TestCatalogWellFormed(t *testing.T) {
	types := map[FieldType]bool{TypeString: true, TypeInt: true, TypeBool: true, TypeQuantity: true, TypeTimestamp: true, TypeStringList: true}
	classes := map[Redaction]bool{RedactStructural: true, RedactReference: true, RedactText: true, RedactAllowlist: true}
	kinds := map[string]bool{}
	for _, s := range Catalog() {
		if kinds[s.Kind] || !kindRe.MatchString(s.Kind) || s.Kind != ProtocolKind(s.GVR.Group, s.APIKind) {
			t.Fatalf("kind %q malformed or duplicated", s.Kind)
		}
		kinds[s.Kind] = true
		paths := map[string]bool{}
		for _, fd := range s.Fields {
			if paths[fd.Path] || !types[fd.Type] || !classes[fd.Redaction] || fd.Source == "" {
				t.Fatalf("%s field %+v malformed or duplicated", s.Kind, fd)
			}
			paths[fd.Path] = true
			for _, ph := range placeholderRe.FindAllString(fd.Path, -1) {
				if !strings.Contains("<container><resource><key><name><type><kind><reason>", ph) {
					t.Fatalf("%s: unknown placeholder %s", s.Kind, ph)
				}
			}
			if (fd.Path == "labels.<key>" || fd.Path == "annotations.<key>") != (fd.Redaction == RedactAllowlist) {
				t.Fatalf("%s: allowlist class misuse on %s", s.Kind, fd.Path)
			}
			if strings.HasSuffix(fd.Path, ".command") || strings.HasSuffix(fd.Path, ".args") || fd.Path == "paths" || fd.Path == "externalName" {
				if fd.Default || fd.Redaction != RedactText {
					t.Fatalf("%s: free-text field %s must be opt-in and redacted", s.Kind, fd.Path)
				}
			}
		}
	}
	if len(kinds) != 21 || CatalogSchema != 1 {
		t.Fatalf("catalog has %d kinds", len(kinds))
	}
	if spec, ok := LookupKind(KindConfigMap); !ok || !spec.MetadataOnly || len(spec.Fields) == 0 {
		t.Fatal("configmap spec")
	}
	if _, ok := LookupKind("example.com/Widget"); ok {
		t.Fatal("unknown kind found")
	}
	if !PathPattern("containers.<container>.requests.<resource>").MatchString("containers.app.requests.nvidia.com/gpu") ||
		PathPattern("containers.<container>.image").MatchString("containers.a.b.image") {
		t.Fatal("path patterns")
	}
}

func TestResolveKinds(t *testing.T) {
	kinds, unsupported := ResolveKinds([]string{"pods", "deployments.apps", "apps/StatefulSet", "Node", "widgets.example.com", "ConfigMap"})
	if strings.Join(kinds, ",") != "ConfigMap,Node,Pod,apps/Deployment,apps/StatefulSet" || strings.Join(unsupported, ",") != "widgets.example.com" {
		t.Fatalf("resolve %v %v", kinds, unsupported)
	}
	all, none := ResolveKinds(nil)
	if len(all) != len(catalog) || len(none) != 0 {
		t.Fatal("default kinds")
	}
}
