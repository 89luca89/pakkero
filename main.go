/*
Package main, calls all the libraries needed and handles cli flags.
*/
package main

import (
	"flag"
	"os"

	"github.com/89luca89/pakkero/internal/pakkero"
)

const programName = "pakkero"
const version = "0.7.0"
const minArgsLen = 2

var dependencies = []string{"ls", "sed", "go", "strip"}
var dependenciesComplete = []string{"upx", "ls", "sed", "go", "strip"}
/*
TestDependencies if all dependencies are present
in the system.
*/
func testDependencies(deps []string) {
	for _, v := range deps {
		if !pakkero.ExecCommand("which", []string{v}) {
			println("Missing Dependency: " + v)
			os.Exit(pakkero.ERR)
		}
	}
}

/*
Print version.
*/
func printVersion() {
	println(programName + " v" + version)
	os.Exit(pakkero.OK)
}

/*
Print Help.
*/
func help() {
	println("Usage: " + programName + " -file /path/to/file -offset OFFSET (-o /path/to/output) (-c) (-register-dep /path/to/file)")
	println("  -file <file>		Target file to Pack")
	println("  -o   <file>		place the output into <file> (default is <inputfile>.enc), optional")
	println("  -c   			compress the output to occupy less space (uses UPX, optional)")
	println("  -offset		Offset where to start the payload (Number of Bytes, optional)")
	println("  -enable-stdout		Whether to wait and handle the process stdout/sterr or not (false by default, optional)")
	println("  -register-dep		/path/to/dependency to analyze and use as fingerprint (absolute path, optional)")
	println("  -v			Check " + programName + " version")
}
func main() {
	if len(os.Args) < minArgsLen {
		help()
		os.Exit(pakkero.ERR)
	}

	flag.Usage = func() {
		help()
	}
	file := flag.String("file", "", "")
	dependency := flag.String("register-dep", "", "")
	output := flag.String("o", "", "")
	offset := flag.Int64("offset", 0, "")
	compress := flag.Bool("c", false, "")
	stdout := flag.Bool("enable-stdout", false, "")
	flag.Bool("v", false, "")
	flag.Parse()

	switch os.Args[1] {
	case "-v":
		printVersion()
	default:
		// fist test if all dependencies are present
		if *compress {
			// compression needs additional upx dependency
			testDependencies(dependenciesComplete)
		} else {
			testDependencies(dependencies)
		}

		// set a default offset if not specified
		if *offset == 0 {
			if *compress {
				*offset = pakkero.Random(750000, 800000)
			} else {
				*offset = pakkero.Random(1910000, 2000000)
			}
		}

		if *file != "" {
			pakkero.Pakkero(*file, *offset, *output, *dependency, *compress, *stdout)
		} else {
			println("Missing arguments or invalid arguments!")
			help()
			os.Exit(pakkero.ERR)
		}
	}
}
