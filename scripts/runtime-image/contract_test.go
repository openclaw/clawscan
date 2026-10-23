package runtimeimage

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type workflow struct {
	Permissions map[string]string `yaml:"permissions"`
	Jobs        map[string]job    `yaml:"jobs"`
}

type step struct {
	ID   string            `yaml:"id"`
	If   string            `yaml:"if"`
	Uses string            `yaml:"uses"`
	Run  string            `yaml:"run"`
	With map[string]string `yaml:"with"`
}

type job struct {
	If          string            `yaml:"if"`
	RunsOn      string            `yaml:"runs-on"`
	Uses        string            `yaml:"uses"`
	Needs       string            `yaml:"needs"`
	Permissions map[string]string `yaml:"permissions"`
	With        map[string]string `yaml:"with"`
	Concurrency struct {
		Group  string `yaml:"group"`
		Cancel bool   `yaml:"cancel-in-progress"`
	} `yaml:"concurrency"`
	Strategy struct {
		FailFast bool `yaml:"fail-fast"`
		Matrix   struct {
			Include []struct {
				OS   string `yaml:"os"`
				Arch string `yaml:"arch"`
			} `yaml:"include"`
		} `yaml:"matrix"`
	} `yaml:"strategy"`
	Steps []step `yaml:"steps"`
}

func readWorkflow(t *testing.T, name string) workflow {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", name))
	if err != nil {
		t.Fatal(err)
	}
	var result workflow
	if err := yaml.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestPublicationDoesNotExecuteSDKTestsUnderEmulation(t *testing.T) {
	for _, name := range []string{"runtime-image.yml", "runtime-image-platform.yml"} {
		actual := readWorkflow(t, name)
		for name, job := range actual.Jobs {
			for _, step := range job.Steps {
				if strings.Contains(step.With["platforms"], ",") || strings.HasPrefix(step.Uses, "docker/setup-qemu-action@") {
					t.Errorf("%s executes the timing/signal-sensitive Dockerfile under emulation on %s", name, job.RunsOn)
				}
			}
		}
	}
}

func evaluate(t *testing.T, condition string, values map[string]any) bool {
	t.Helper()
	if condition == "" {
		return true
	}
	expression, err := parser.ParseExpr(strings.ReplaceAll(condition, "'", `"`))
	if err != nil {
		t.Fatal(err)
	}
	var resolve func(ast.Expr) any
	resolve = func(expression ast.Expr) any {
		switch expression := expression.(type) {
		case *ast.BasicLit:
			return strings.Trim(expression.Value, `"`)
		case *ast.Ident:
			if expression.Name == "true" || expression.Name == "false" {
				return expression.Name == "true"
			}
			return expression.Name
		case *ast.SelectorExpr:
			var selector func(ast.Expr) string
			selector = func(value ast.Expr) string {
				switch value := value.(type) {
				case *ast.Ident:
					return value.Name
				case *ast.SelectorExpr:
					return selector(value.X) + "." + value.Sel.Name
				}
				t.Fatal("unsupported selector")
				return ""
			}
			value, ok := values[selector(expression)]
			if !ok {
				t.Fatalf("unknown expression input: %s", selector(expression))
			}
			return value
		case *ast.BinaryExpr:
			left, right := resolve(expression.X), resolve(expression.Y)
			switch expression.Op {
			case token.EQL:
				return left == right
			case token.NEQ:
				return left != right
			case token.LAND:
				return left.(bool) && right.(bool)
			case token.LOR:
				return left.(bool) || right.(bool)
			}
		}
		t.Fatal("unsupported workflow condition")
		return false
	}
	return resolve(expression).(bool)
}

func TestWorkflowPublicationFanInAndPRPermissions(t *testing.T) {
	actual := readWorkflow(t, "runtime-image.yml")
	platform := readWorkflow(t, "runtime-image-platform.yml")
	if actual.Permissions["packages"] != "" {
		t.Fatal("workflow-wide package permission reaches PRs")
	}
	for _, event := range []string{"pull_request", "push", "workflow_dispatch"} {
		for _, result := range []string{"success", "failure", "cancelled", "skipped"} {
			values := map[string]any{"github.event_name": event, "needs.build.result": result}
			for name, call := range actual.Jobs {
				if !evaluate(t, call.If, values) {
					continue
				}
				if event == "pull_request" && call.Permissions["packages"] == "write" {
					t.Fatal("PR can write packages")
				}
				if name == "merge" {
					if event == "pull_request" || result != "success" || call.Needs != "build" {
						t.Fatal("incomplete native matrix can reach production tags")
					}
					continue
				}
				if call.Uses != "./.github/workflows/runtime-image-platform.yml" {
					t.Fatal("verification and publication must share the native build implementation")
				}
				values["inputs.publish"] = call.With["publish"] == "true"
				for _, step := range platform.Jobs["native"].Steps {
					if evaluate(t, step.If, values) && (strings.Contains(step.With["outputs"], "push=true") || strings.HasPrefix(step.Uses, "docker/login-action@")) && event == "pull_request" {
						t.Fatal("PR reaches registry export or login")
					}
				}
			}
			want := event != "pull_request" && result == "success"
			if evaluate(t, actual.Jobs["merge"].If, values) != want {
				t.Fatal("manifest fan-in is not fail closed")
			}
		}
	}
	merge := actual.Jobs["merge"]
	if merge.Concurrency.Group == "" || merge.Concurrency.Cancel {
		t.Fatal("mutable tag writes are not serialized")
	}
}

func TestNativeBuildSmokeAndProvenanceOrder(t *testing.T) {
	native := readWorkflow(t, "runtime-image-platform.yml").Jobs["native"]
	seen := map[string]bool{}
	for _, row := range native.Strategy.Matrix.Include {
		if row.Arch == "arm64" && !strings.HasSuffix(row.OS, "-arm") || row.Arch == "amd64" && strings.HasSuffix(row.OS, "-arm") {
			t.Fatal("native architecture runner mismatch")
		}
		seen[row.Arch] = true
	}
	if len(seen) != 2 || !seen["amd64"] || !seen["arm64"] || native.Strategy.FailFast {
		t.Fatal("both independent native checks are required")
	}
	built, smoked, exported, bound := false, false, false, false
	for _, step := range native.Steps {
		if step.ID == "image" {
			built = step.With["load"] == "true" && step.With["push"] == "false" && step.With["target"] == "" && step.With["context"] == "./docker/clawscan-runtime"
		}
		if strings.HasSuffix(step.Run, "publish.py verify") {
			if !built {
				t.Fatal("smoke runs before the complete Dockerfile build/load")
			}
			smoked = true
		}
		if step.ID == "publish" {
			if !smoked || step.With["provenance"] == "false" || !strings.Contains(step.With["outputs"], "push-by-digest=true") || step.With["tags"] != "" {
				t.Fatal("publication bypasses smoke/provenance or uses mutable platform tags")
			}
			exported = true
		}
		if strings.HasSuffix(step.Run, "publish.py published") {
			bound = exported
		}
		if strings.HasPrefix(step.Uses, "actions/upload-artifact@") && !bound {
			t.Fatal("proof upload is not downstream of registry config binding")
		}
	}
	if !built || !smoked || !exported || !bound {
		t.Fatal("missing native verification/publication stage")
	}
}

func TestWorkflowActionsAreImmutable(t *testing.T) {
	pinned := regexp.MustCompile(`@[0-9a-f]{40}$`)
	for _, name := range []string{"runtime-image.yml", "runtime-image-platform.yml"} {
		for _, job := range readWorkflow(t, name).Jobs {
			for _, step := range job.Steps {
				if step.Uses != "" && !pinned.MatchString(step.Uses) {
					t.Errorf("unpinned action: %s", step.Uses)
				}
			}
		}
	}
}
