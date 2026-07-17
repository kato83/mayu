package main

import (
	"fmt"
	"os"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Printf("mayu %s\n", version)
		return
	}

	fmt.Println("Usage: mayu <command>")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  version    Print version information")
}
