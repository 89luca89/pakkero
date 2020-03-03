/*
Package main, calls all the libraries needed and handles cli flags.
*/
package main

import (
	"flag"
	"os"

	"./lib/packngo"
)

const programName = "packngo"
const version = "0.3.0"

var dependencies = []string{"upx", "ls", "sed", "go", "strip"}

/*
TestDependencies if all dependencies are present
in the system
*/
func testDependencies() error {
	for _, v := range dependencies {
		if !packngo.ExecCommand("which", []string{v}) {
			println("Missing Dependency: " + v)
			os.Exit(1)
		}
	}
	return nil
}

/*
Print version.
*/
func printVersion() {
	println(programName + " v" + version)
	os.Exit(0)
}

/*
Print Help.
*/
func help() {
	println("Usage: " + programName + " -file /path/to/file -offset OFFSET -o /path/to/output")
	println("  -file <file>			Target file to Pack")
	println("  -o   <file>			Place the output into <file> (default is <inputfile>.enc)")
	println("  -offset			Offset where to start the payload (Bytes)")
	println("  -register-dep			/path/to/dependency to analyze and use as fingerprint (absolute)")
	println("				Offset minimal recommended value is 700000")
	println("  -v				Check " + programName + " version")
}
func main() {
	// fist test if all dependencies are present
	if testDependencies() == nil {
		if len(os.Args) == 1 {
			help()
			os.Exit(1)
		}
		flag.Usage = func() {
			help()
		}
		file := flag.String("file", "", "")
		dependency := flag.String("register-dep", "", "")
		output := flag.String("o", "", "")
		offset := flag.Int64("offset", 0, "")
		flag.Bool("v", false, "")
		flag.Parse()

		switch os.Args[1] {
		case "-v":
			printVersion()
		default:
			if *file != "" && *offset >= 0 {
				packngo.PackNGo(*file, *offset, *output, *dependency)
			} else {
				println("Missing arguments or invalid arguments!")
				help()
				os.Exit(1)
			}
		}
	}
}
