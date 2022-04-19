/*
Package pakkero will pack, compress and encrypt any type of executable.
Utilities library
*/
package pakkero

import (
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"os/exec"
)

// Colors for strings.
const (
	SuccessColor = "\033[1;32m%s\033[0m"
	WarningColor = "\033[1;33m%s\033[0m"
	ErrorColor   = "\033[1;31m%s\033[0m"
)

// ERR Is the exit Code 1.
const ERR = 1

// OK Is the exit Code 0.
const OK = 0

/*
RandomInt64 will return a random number in a range.
*/
func RandomInt64(max int64) int64 {
	bg := big.NewInt(max)

	n, err := rand.Int(rand.Reader, bg)
	if err != nil {
		panic(err)
	}

	return n.Int64()
}

/*
Random will return a random number in a range.
*/
func Random(min, max int64) int64 {
	bg := big.NewInt(max - min)

	n, err := rand.Int(rand.Reader, bg)
	if err != nil {
		panic(err)
	}
	// add n to min to support the passed in range
	return n.Int64() + min
}

/*
Unique will deduplicate a given slice.
*/
func Unique(slice []string) []string {
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
ReverseByteArray will reverse a slice of bytes.
*/
func ReverseByteArray(input []byte) []byte {
	reversed := []byte{}

	for i := range input {
		n := input[len(input)-1-i]

		reversed = append(reversed, n)
	}

	return reversed
}

/*
ReverseByte will change a byte endianess.
*/
func ReverseByte(b byte) byte {
	var d byte

	for i := 0; i < 8; i++ {
		d <<= 1
		d |= b & 1
		b >>= 1
	}

	return d
}

/*
ReverseStringArray reverse a slice of strings.
*/
func ReverseStringArray(ss []string) []string {
	last := len(ss) - 1

	for i := 0; i < len(ss)/2; i++ {
		ss[i], ss[last-i] = ss[last-i], ss[i]
	}

	return ss
}

/*
ReverseString reverse a string.
*/
func ReverseString(input string) string {
	var result string

	for _, value := range input {
		result = string(value) + result
	}

	return result
}

/*
ShuffleSlice will shuffle a slice.
*/
func ShuffleSlice(in []string) []string {
	for i := len(in) - 1; i > 0; i-- {
		j := RandomInt64(int64(i) + 1)
		in[i], in[j] = in[j], in[i]
	}

	return in
}

/*
ExecCommand is a wrapper arount exec.Command to execute a command
and ensure it's result is not err.
*/
func ExecCommand(name string, args []string) bool {
	cmd := exec.Command(name, args...)

	errString, err := cmd.CombinedOutput()
	if err != nil {
		println(fmt.Sprintf("failed to execute command %s: %s", cmd, err))
		println(string(errString))

		return false
	}

	return true
}

/*
GenerateRandomGarbage creates random garbage to rise entropy.
*/
func GenerateRandomGarbage(size int64) string {
	randomGarbage := make([]byte, size)

	_, err := rand.Read(randomGarbage)
	if err != nil {
		panic(err)
	}

	return string(randomGarbage)
}

/*
GzipContent an input byte slice and return it compressed.
*/
func GzipContent(input []byte) []byte {
	// GZIP before encrypt
	var zlibPlaintext bytes.Buffer
	zlibWriter := zlib.NewWriter(&zlibPlaintext)

	_, err := zlibWriter.Write(input)
	zlibWriter.Close()

	if err != nil {
		panic(err)
	}

	return zlibPlaintext.Bytes()
}

/*
GenerateNullString will return a string with only void chars.
*/
func GenerateNullString(n int) string {
	result := ""

	for len(result) < n {
		result += string(0)
	}

	return result
}

/*
RegisterDependency will take a file in input and register the
Byte Frequency Distribution (BFD) and some other data to let the launcher
do statystical analysis of the found files.
*/
func RegisterDependency(dependency string) {
	dependencyFile, _ := os.Open(dependency)
	defer dependencyFile.Close()
	dependencyStats, _ := dependencyFile.Stat()
	depenencyLinkStats, _ := os.Lstat(dependency)

	if (depenencyLinkStats.Mode() & os.ModeSymlink) != 0 {
		cleanup()
		fmt.Printf("Invalid path: %s is a symlink, use absolute paths.\n", dependency)
		os.Exit(1)
	}
	// calculate BFD (byte frequency distribution) for the input dependency
	bytes, _ := ioutil.ReadFile(dependency)

	bfd := make([]float64, 256)

	for _, b := range bytes {
		bfd[b]++
	}
	// make a string out of it
	bfdString := "[]float64{"
	for _, v := range bfd {
		bfdString += fmt.Sprintf("%f", v) + ","
	}

	bfdString += "}"

	// add Dependency data to the secrets
	// register BFD
	Secrets[depBFDPlaceholder] = []string{bfdString, "leaveBFD"}
	// register name
	Secrets[depNamePlaceholder] = []string{dependency, GenerateTyposquatName(128)}
	// register size
	Secrets[depSizePlaceholder] = []string{
		fmt.Sprintf("%d", dependencyStats.Size()), GenerateTyposquatName(128),
	}
}
