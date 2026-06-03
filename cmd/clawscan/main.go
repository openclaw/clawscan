package main

import (
	"fmt"
	"os"

	"github.com/openclaw/clawscan/internal/runner"
)

func main() {
	if err := run(os.Args[1:], os.Environ()); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func run(args []string, environ []string) error {
	opts, err := runner.ParseArgs(args)
	if err != nil {
		return err
	}
	artifact, err := runner.Run(opts, runner.RunContext{Env: runner.EnvMap(environ)})
	if err != nil {
		return err
	}
	if opts.JSON {
		return runner.WriteJSON(os.Stdout, artifact)
	}
	if opts.OutputPath != "" {
		fmt.Fprintf(os.Stdout, "Wrote %s\n", opts.OutputPath)
		return nil
	}
	fmt.Fprintf(os.Stdout, "clawscan %s: %d scanner(s)\n", artifact.SchemaVersion, len(artifact.Scanners))
	return nil
}
