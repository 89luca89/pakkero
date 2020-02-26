package main

import (
	"flag"
	"os"

	"./lib/packngo"
)

const programName = "PackNGo"
const version = "0.2.0"

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
	println("Usage: ./encrypt -file /path/to/file -offset OFFSET")
	println("  -file <file>			Target file to Pack")
	println("  -o   <file>			Place the output into <file> (default is <inputfile>.enc)")
	println("  -offset			Offset where to start the payload (Bytes)")
	println("				Offset minimal recommended value is 600000")
	println("  -v				Check " + programName + " version")
}
func main() {
	// fist test if all dependencies are present
	if packngo.TestDependencies() == nil {
		if len(os.Args) == 1 {
			help()
			os.Exit(1)
		}
		flag.Usage = func() {
			help()
		}
		file := flag.String("file", "", "")
		output := flag.String("o", "", "")
		offset := flag.Int64("offset", 0, "")
		flag.Bool("v", false, "")
		flag.Parse()

		switch os.Args[1] {
		case "-v":
			printVersion()
		default:
			if *file != "" && *offset >= 0 {
				packngo.PackNGo(*file, *offset, *output)
			} else {
				println("Missing arguments or invalid arguments!")
				help()
				os.Exit(1)
			}
		}
	}
}
