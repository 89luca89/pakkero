package main

import (
	"fmt"
	mrand "math/rand"
	"os"
	"os/exec"
	"time"
)

const programName = "PackNGo"
const version = "0.2.0"

var dependencies = []string{"upx", "ls", "sed", "go", "strip"}

/*
Deduplicate a given slice
*/
func unique(slice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

/*
Reverse a slice of bytes
*/
func reverseByteArray(input []byte) []byte {
	reversed := []byte{}
	for i := range input {
		n := input[len(input)-1-i]
		reversed = append(reversed, n)
	}
	return reversed
}

/*
Change a byte endianess
*/
func reverseByte(b byte) byte {
	var d byte
	for i := 0; i < 8; i++ {
		d <<= 1
		d |= b & 1
		b >>= 1
	}
	return d
}

/*
Reverse a slice of strings
*/
func reverseStringArray(ss []string) []string {
	last := len(ss) - 1
	for i := 0; i < len(ss)/2; i++ {
		ss[i], ss[last-i] = ss[last-i], ss[i]
	}
	return ss
}

/*
Reverse a string
*/
func reverseString(input string) string {
	var result string
	for _, value := range input {
		result = string(value) + result
	}
	return result
}

/*
Shuffle a slice.
*/
func shuffleSlice(in []string) []string {
	mrand.Seed(time.Now().UnixNano())
	mrand.Shuffle(len(in), func(i, j int) { in[i], in[j] = in[j], in[i] })
	return in
}

/*
Wrapper arount exec.Command to execute a command
and ensure it's result is not err.
Else panic.
*/
func execCommand(name string, args []string) {
	cmd := exec.Command(name, args...)
	err := cmd.Run()
	if err != nil {
		panic(fmt.Sprintf("failed to execute command %s: %s", cmd, err))
	}
}

/*
Test if all dependencies are present
in the system
*/
func testDependencies() error {
	for _, v := range dependencies {
		execCommand("which", []string{v})
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
Print help.
*/
func help() {
	println("Usage: ./encrypt -file /path/to/file -offset OFFSET")
	println("  -file <file>			Target file to Pack")
	println("  -o   <file>			Place the output into <file> (default is <inputfile>.enc)")
	println("  -offset			Offset where to start the payload (Bytes)")
	println("				Offset minimal recommended value is 600000")
	println("  -v				Check " + programName + " version")
}
