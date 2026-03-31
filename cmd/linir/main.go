package main

import (
	"fmt"
	"os"

	"github.com/dogadmin/LinIR/internal/cli"
)

func main() {
	root := cli.NewRootCmd()
	if err := root.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "linir: %v\n", err)
		os.Exit(1)
	}
}
