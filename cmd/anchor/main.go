// Command anchor is a prototype MCP tool-schema "rug pull" detector.
//
// It answers one narrow question — "was this exact schema published by
// this exact identity, at this time, and is that on the public record?" —
// not whether a schema is safe. See the README for the full design
// rationale.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "sign":
		err = runSign(os.Args[2:])
	case "verify":
		err = runVerify(os.Args[2:])
	case "rotate-identity":
		err = runRotateIdentity(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "anchor: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}

	if err != nil {
		if xerr, ok := err.(*exitError); ok {
			if xerr.err != nil {
				fmt.Fprintf(os.Stderr, "anchor: %v\n", xerr.err)
			}
			os.Exit(xerr.code)
		}
		fmt.Fprintf(os.Stderr, "anchor: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `anchor - provenance for MCP tool schemas

Usage (flags must come before the trailing file argument — Go's flag
package stops parsing flags at the first non-flag token):
  anchor sign --tool-id <id> --publisher-identity <id> --schema-version <v> [--state-dir .anchor] <schema-file>
  anchor verify --tool-id <id> [--state-dir .anchor] <schema-file>
  anchor rotate-identity --tool-id <id> --new-identity <id> [--reason <text>] [--state-dir .anchor]

Each command's -h flag prints its own options.
`)
}

// exitError lets a subcommand request a specific process exit code (e.g.
// verify returning 1 for BLOCKED/FLAGGED) while still going through main's
// single error-printing path.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string {
	if e.err == nil {
		return ""
	}
	return e.err.Error()
}

// silentExit exits with code without printing anything further — used
// when the subcommand has already printed its own verdict to stdout.
func silentExit(code int) error {
	return &exitError{code: code}
}
