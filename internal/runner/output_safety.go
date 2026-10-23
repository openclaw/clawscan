package runner

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func ValidateOutputPaths(optsList []Options, outputPath string, cwd string) error {
	if outputPath == "" {
		hasPredictions := false
		for _, opts := range optsList {
			hasPredictions = hasPredictions || BenchmarkPredictionsOutputPath(opts) != ""
		}
		if !hasPredictions {
			return nil
		}
	}
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
			continue
		}
		for _, target := range targets {
			if !isURLTarget(target) {
				inputs = append(inputs, target)
			}
			artifact := NewArtifact(opts, "", "", "", nil)
			artifact.Target.Input = target
			artifacts = append(artifacts, &artifact)
		}
	}
	spec := outputBundleSpecFor(outputPath)
	for _, paths := range scannerOutputPaths(spec, artifacts) {
		for _, path := range paths {
			outputs = append(outputs, filepath.Join(spec.RootDir, filepath.FromSlash(path)))
		}
	}
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
