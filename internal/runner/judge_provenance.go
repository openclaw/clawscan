package runner

import (
	"path/filepath"
	"regexp"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

var codexModelID = regexp.MustCompile(`^gpt-[a-z0-9][a-z0-9._-]{0,127}$`)

// configuredJudgeModel records a literal request, never a provider-observed model.
// Arbitrary harnesses, shell expansions, and ambiguous invocations remain unknown.
// Parse rather than regex-search shell source: quoted prompts/comments aren't commands.
func configuredJudgeModel(command, goos string, env map[string]string) string {
	if goos == "windows" {
		return ""
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(strings.NewReader(command), "judge")
	if err != nil || len(file.Stmts) == 0 {
		return ""
	}
	last := file.Stmts[len(file.Stmts)-1]
	if last.Negated || last.Background || last.Coprocess || last.Disown {
		return ""
	}
	call, ok := last.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) < 3 {
		return ""
	}
	args := make([]string, len(call.Args))
	for i, word := range call.Args {
		value, literal := literalJudgeWord(word.Parts)
		if !literal {
			return ""
		}
		args[i] = value
	}
	if filepath.Base(args[0]) != "codex" || args[1] != "exec" {
		return ""
	}
	calls, functions := 0, false
	syntax.Walk(file, func(node syntax.Node) bool {
		switch node := node.(type) {
		case *syntax.FuncDecl:
			functions = true
		case *syntax.CallExpr:
			if len(node.Args) > 0 {
				name, literal := literalJudgeWord(node.Args[0].Parts)
				if literal && filepath.Base(name) == "codex" {
					calls++
				}
			}
		}
		return true
	})
	if functions || calls != 1 {
		return ""
	}
	model := ""
	for i := 2; i < len(args); i++ {
		arg := args[i]
		value, isModel := "", false
		switch {
		case arg == "--model" || arg == "-m":
			i++
			if i == len(args) {
				return ""
			}
			value, isModel = args[i], true
		case strings.HasPrefix(arg, "--model="):
			value, isModel = strings.TrimPrefix(arg, "--model="), true
		case arg == "-c" || arg == "--config":
			i++
			if i == len(args) || judgeConfigChangesModel(args[i]) {
				return ""
			}
		case strings.HasPrefix(arg, "--config="):
			if judgeConfigChangesModel(strings.TrimPrefix(arg, "--config=")) {
				return ""
			}
		case strings.HasPrefix(arg, "-c"):
			if judgeConfigChangesModel(strings.TrimPrefix(arg, "-c")) {
				return ""
			}
		case arg == "--cd" || arg == "--sandbox" || arg == "--output-schema" || arg == "--output-last-message":
			i++
			if i == len(args) || strings.HasPrefix(args[i], "-") {
				return ""
			}
		case arg == "--skip-git-repo-check" || arg == "--ignore-user-config" || arg == "--ephemeral" || arg == "--json":
		case arg == "-" && i == len(args)-1:
		default:
			// Unknown flags, prompts, and option terminators can change argv meaning.
			return ""
		}
		if isModel {
			if model != "" || !codexModelID.MatchString(value) || redactEnvValues(value, env) != value {
				return ""
			}
			model = value
		}
	}
	return model
}

func judgeConfigChangesModel(value string) bool {
	key, _, _ := strings.Cut(value, "=")
	return strings.Trim(strings.TrimSpace(key), `"'`) == "model"
}

func literalJudgeWord(parts []syntax.WordPart) (string, bool) {
	var out strings.Builder
	for _, part := range parts {
		switch part := part.(type) {
		case *syntax.Lit:
			if strings.ContainsAny(part.Value, `\*?[]{}~`) {
				return "", false
			}
			out.WriteString(part.Value)
		case *syntax.SglQuoted:
			out.WriteString(part.Value)
		case *syntax.DblQuoted:
			value, ok := literalJudgeWord(part.Parts)
			if !ok {
				return "", false
			}
			out.WriteString(value)
		default:
			return "", false
		}
	}
	return out.String(), true
}
