package main

import (
	"fmt"
	"os"

	"github.com/self-evolving-research/obfuscator/pkg/integrity"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: inthash <binary-path>\n")
		os.Exit(1)
	}

	hash, err := integrity.ComputeHashForEmbedding(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Print(hash)
}
