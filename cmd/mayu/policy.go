package main

import (
	"flag"
	"fmt"

	"github.com/kato83/mayu/internal/config"
	"github.com/kato83/mayu/internal/policy"
)

func runPolicy(args []string, _ *config.Config) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: mayu policy <subcommand>\n\nSubcommands:\n  validate   Validate a policy YAML file")
	}

	switch args[0] {
	case "validate":
		return runPolicyValidate(args[1:])
	default:
		return fmt.Errorf("unknown policy subcommand: %q (available: validate)", args[0])
	}
}

func runPolicyValidate(args []string) error {
	fs := flag.NewFlagSet("policy validate", flag.ExitOnError)
	filePath := fs.String("file", "", "Path to policy YAML file to validate")

	fs.Usage = func() {
		fmt.Println("Usage: mayu policy validate --file <path>")
		fmt.Println()
		fmt.Println("Validate a policy YAML file for syntax and semantic errors.")
		fmt.Println()
		fmt.Println("Options:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  mayu policy validate --file policy.yaml")
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *filePath == "" {
		return fmt.Errorf("--file is required")
	}

	pf, err := policy.LoadFile(*filePath)
	if err != nil {
		return err
	}

	errs := policy.Validate(pf)
	if len(errs) > 0 {
		fmt.Printf("✗ %d validation error(s) in %s:\n\n", len(errs), *filePath)
		for _, e := range errs {
			fmt.Printf("  • %v\n", e)
		}
		return fmt.Errorf("policy file is invalid")
	}

	fmt.Printf("✓ %s is valid (%d policies defined)\n", *filePath, len(pf.Policies))
	return nil
}
