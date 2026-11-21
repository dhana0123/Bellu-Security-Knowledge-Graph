// Command bskg is the single Bellu Security Knowledge Graph binary.
package main

import (
	"fmt"
	"io"
	"os"
)

const usage = `usage: bskg <command> [arguments]

commands:
  migrate         apply pending schema migrations
  validate        validate the graph
  sync            run or inspect source synchronization
  worker          run the build queue and daily schedule
  serve           run the REST API
  apikey          create or revoke API keys
  reset           delete the graph content (requires --confirm)
`

var commands = map[string]bool{
	"migrate":  true,
	"validate": true,
	"sync":     true,
	"worker":   true,
	"serve":    true,
	"apikey":   true,
	"reset":    true,
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run dispatches a subcommand and returns the process exit code.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	name := args[0]
	if !commands[name] {
		fmt.Fprintf(stderr, "bskg: unknown command %q\n\n%s", name, usage)
		return 2
	}
	switch name {
	case "migrate":
		return runMigrate(stdout, stderr)
	case "validate":
		return runValidate(args[1:], stdout, stderr)
	case "sync":
		return runSync(args[1:], stdout, stderr)
	case "reset":
		return runReset(args[1:], stdout, stderr)
	case "worker":
		return runWorker(args[1:], stdout, stderr)
	case "serve":
		return runServe(args[1:], stdout, stderr)
	case "apikey":
		return runAPIKey(args[1:], stdout, stderr)
	}
	fmt.Fprintf(stderr, "bskg: %s: not implemented yet\n", name)
	return 1
}
