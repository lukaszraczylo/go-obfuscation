package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/self-evolving-research/obfuscator/internal/transform"
)

func main() {
	srcDir := flag.String("src", "", "Source directory to transform")
	dstDir := flag.String("dst", "", "Destination directory for transformed source")
	encryptStrings := flag.Bool("strings", true, "Encrypt string literals")
	opaquePreds := flag.Bool("opaque", true, "Inject opaque predicates")
	deadCode := flag.Bool("deadcode", true, "Inject dead code")
	randomize := flag.Bool("randomize", true, "Randomize declaration order")
	indirectDispatch := flag.Bool("indirect", true, "Indirect function dispatch")
	bogusCFG := flag.Bool("bogus-cfg", true, "Bogus control-flow injection")
	flatten := flag.Bool("flatten", true, "Control-flow flattening")
	seed := flag.Int64("seed", 0, "Build seed for polymorphic output (0 = use current timestamp)")
	injectBuildID := flag.Bool("buildid", true, "Inject unique build ID constant")
	virtualizeVM := flag.Bool("vm", true, "Virtualize simple functions into VM bytecode")
	flag.Parse()

	if *srcDir == "" || *dstDir == "" {
		fmt.Fprintf(os.Stderr, "Usage: transformer -src <dir> -dst <dir>\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *seed == 0 {
		*seed = time.Now().UnixNano()
	}

	absSrc, err := filepath.Abs(*srcDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid src path: %v\n", err)
		os.Exit(1)
	}

	absDst, err := filepath.Abs(*dstDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid dst path: %v\n", err)
		os.Exit(1)
	}

	config := transform.Config{
		EncryptStrings:      *encryptStrings,
		InjectOpaquePreds:   *opaquePreds,
		InjectDeadCode:      *deadCode,
		RandomizeOrder:      *randomize,
		IndirectDispatch:    *indirectDispatch,
		BogusControlFlow:    *bogusCFG,
		FlattenControl:      *flatten,
		BuildSeed:           *seed,
		InjectBuildID:       *injectBuildID,
		VirtualizeFunctions: *virtualizeVM,
	}

	t := transform.New(config)

	fmt.Printf("[transformer] src=%s dst=%s\n", absSrc, absDst)
	fmt.Printf("[transformer] seed=%d buildid=%v\n", config.BuildSeed, config.InjectBuildID)
	fmt.Printf("[transformer] strings=%v opaque=%v deadcode=%v bogus=%v flatten=%v vm=%v\n",
		config.EncryptStrings, config.InjectOpaquePreds,
		config.InjectDeadCode, config.BogusControlFlow, config.FlattenControl,
		config.VirtualizeFunctions)

	start := time.Now()

	if err := t.TransformDir(absSrc, absDst); err != nil {
		fmt.Fprintf(os.Stderr, "Transform failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[transformer] done in %v\n", time.Since(start))
}
