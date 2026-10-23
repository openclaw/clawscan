package runner

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type outputSafety struct {
	inputs  []string
	targets []string
}

func ValidateOutputPaths(optsList []Options, outputPath string, cwd string) error {
	_, err := prepareOutputSafety(optsList, outputPath, cwd)
	return err
}

func prepareOutputSafety(optsList []Options, outputPath string, cwd string) (outputSafety, error) {
	safety := outputSafety{}
	outputs := []string{}
	if outputPath != "" {
		outputs = append(outputs, outputPath)
	}
	inputs := []string{}
	artifacts := []*Artifact{}
	for _, opts := range optsList {
		inputs = append(inputs, opts.ContextPath)
		if opts.ConfigSource != "built-in" {
			inputs = append(inputs, opts.ConfigSource)
		}
		for _, source := range opts.ScannerResultPaths {
			inputs = append(inputs, source)
		}
		if opts.Judge != nil {
			for _, match := range judgePlaceholderPattern.FindAllStringSubmatch(opts.Judge.Command, -1) {
				source := strings.TrimSpace(match[2])
				switch match[1] {
				case "prompt":
					if source == "" {
						source = defaultJudgePromptPath
					}
				case "output_schema":
					if source == "" {
						source = defaultJudgeOutputSchemaPath
					}
				default:
					continue
				}
				if _, embedded := opts.Judge.Files[judgeSourceKey(source)]; !embedded {
					inputs = append(inputs, source)
				}
			}
		}
		if opts.Benchmark != nil {
			if !isURLTarget(opts.Benchmark.IDsSource) {
				inputs = append(inputs, opts.Benchmark.IDsSource)
			}
			if predictionPath := BenchmarkPredictionsOutputPath(opts); predictionPath != "" {
				outputs = append(outputs, predictionPath)
			}
			continue
		}
		targets, err := ResolveTargetInputs(opts, cwd)
		if err != nil {
			root := cwd
			if root == "" {
				root, err = os.Getwd()
				if err != nil {
					return safety, err
				}
			}
			safety.targets = append(safety.targets, filepath.Join(root, "skills"))
			continue
		}
		for _, target := range targets {
			if !isURLTarget(target) {
				inputs = append(inputs, target)
			}
			targetOpts := opts
			targetOpts.Target = target
			resolved, _ := resolveTargetForOptions(targetOpts)
			artifact := NewArtifact(targetOpts, resolved.resolvedPath, "", "", nil)
			if !isURLTarget(target) {
				source := resolved.resolvedPath
				if source == "" {
					source = target
				}
				safety.targets = append(safety.targets, source)
			}
			artifacts = append(artifacts, &artifact)
		}
	}
	spec := outputBundleSpecFor(outputPath)
	if outputPath != "" {
		for _, paths := range scannerOutputPaths(spec, artifacts) {
			for _, path := range paths {
				outputs = append(outputs, filepath.Join(spec.RootDir, filepath.FromSlash(path)))
			}
		}
	}
	safety.inputs = inputs
	return safety, validateOutputInventory(outputs, inputs)
}

func validateOutputInventory(outputs []string, inputs []string) error {
	for index, output := range outputs {
		for _, input := range append(inputs, outputs[:index]...) {
			if input == "" {
				continue
			}
			same, err := sameFilePath(output, input)
			if err != nil {
				return err
			}
			if same {
				return fmt.Errorf("output %s aliases input or another output %s", output, input)
			}
		}
		if info, err := os.Lstat(output); err == nil && !info.Mode().IsRegular() {
			return fmt.Errorf("refusing non-regular output: %s", output)
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func (safety outputSafety) validateWrite(output string) error {
	if err := validateOutputInventory([]string{output}, safety.inputs); err != nil {
		return err
	}
	if _, err := os.Stat(output); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	for _, target := range safety.targets {
		resolved, err := canonicalFilePath(target)
		if err != nil {
			return err
		}
		err = filepath.WalkDir(resolved, func(source string, entry os.DirEntry, walkErr error) error {
			if errors.Is(walkErr, os.ErrNotExist) {
				return nil
			}
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			same, err := sameFilePath(output, source)
			if err != nil {
				return err
			}
			if same {
				return fmt.Errorf("output %s aliases unconsumed submitted source %s", output, source)
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (safety outputSafety) withArtifacts(artifacts []*Artifact) outputSafety {
	combined := outputSafety{inputs: append([]string(nil), safety.inputs...), targets: append([]string(nil), safety.targets...)}
	for _, artifact := range artifacts {
		combined.inputs = append(combined.inputs, artifact.outputSafety.inputs...)
		combined.targets = append(combined.targets, artifact.outputSafety.targets...)
		if artifact.ConfigSource != nil && *artifact.ConfigSource != "built-in" {
			combined.inputs = append(combined.inputs, *artifact.ConfigSource)
		}
		if !isURLTarget(artifact.Target.Input) {
			combined.inputs = append(combined.inputs, artifact.Target.Input)
			target := artifact.Target.ResolvedPath
			if target == "" {
				target = artifact.Target.Input
			}
			if target != "" {
				combined.targets = append(combined.targets, target)
			}
		}
	}
	pending := []string{}
	for _, target := range combined.targets {
		consumed := false
		for _, artifact := range artifacts {
			source := artifact.Target.ResolvedPath
			if source == "" {
				source = artifact.Target.Input
			}
			if source == "" || isURLTarget(source) {
				continue
			}
			same, err := sameFilePath(target, source)
			if err != nil || !same {
				continue
			}
			consumed = artifact.Complete && artifact.targetConsumed
			if !consumed {
				break
			}
		}
		if !consumed {
			pending = append(pending, target)
		}
	}
	combined.targets = pending
	return combined
}

func canonicalFilePath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err == nil {
		return resolved, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	parent := filepath.Dir(absolute)
	if parent == absolute {
		return "", err
	}
	resolved, err = canonicalFilePath(parent)
	return filepath.Join(resolved, filepath.Base(absolute)), err
}

func sameFilePath(first string, second string) (bool, error) {
	firstPath, err := canonicalFilePath(first)
	if err != nil {
		return false, err
	}
	secondPath, err := canonicalFilePath(second)
	if err != nil {
		return false, err
	}
	if firstPath == secondPath {
		return true, nil
	}
	firstInfo, firstErr := os.Stat(firstPath)
	secondInfo, secondErr := os.Stat(secondPath)
	return firstErr == nil && secondErr == nil && os.SameFile(firstInfo, secondInfo), nil
}

func outputWithinTarget(opts Options, target resolvedTarget) (bool, error) {
	if opts.OutputPath == "" || target.kind == targetKindURL {
		return false, nil
	}
	info, err := os.Stat(target.resolvedPath)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || !info.IsDir() {
		return false, err
	}
	root, err := canonicalFilePath(target.resolvedPath)
	if err != nil {
		return false, err
	}
	output, err := canonicalFilePath(opts.OutputPath)
	if err != nil {
		return false, err
	}
	relative, err := filepath.Rel(root, output)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)), err
}
