package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: taintguard hook | taintguard replay <scenarios.json>")
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "hook":
		var root string
		root, err = DefaultStateRoot()
		if err == nil {
			err = RunHook(os.Stdin, os.Stdout, root)
		}
	case "replay":
		if len(os.Args) != 3 {
			err = fmt.Errorf("usage: taintguard replay <scenarios.json>")
		} else {
			err = ReplayFile(os.Args[2], os.Stdout)
		}
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "taintguard:", err)
		os.Exit(1)
	}
}
