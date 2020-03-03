/*
Package packngo will pack, compress and encrypt any type of executable.
Utilities library
*/
package packngo

import (
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"fmt"
	mathRand "math/rand"
	"os/exec"
	"time"
)

// Colors for strings
const (
	SuccessColor = "\033[1;32m%s\033[0m"
	WarningColor = "\033[1;33m%s\033[0m"
	ErrorColor   = "\033[1;31m%s\033[0m"
)

/*
Unique will deduplicate a given slice
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
ReverseByteArray will reverse a slice of bytes
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
ReverseByte will change a byte endianess
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
ReverseStringArray reverse a slice of strings
*/
func ReverseStringArray(ss []string) []string {
	last := len(ss) - 1
	for i := 0; i < len(ss)/2; i++ {
		ss[i], ss[last-i] = ss[last-i], ss[i]
	}
	return ss
}

/*
ReverseString reverse a string
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
	mathRand.Seed(time.Now().UnixNano())
	mathRand.Shuffle(len(in), func(i, j int) { in[i], in[j] = in[j], in[i] })
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
		fmt.Println(fmt.Sprintf("failed to execute command %s: %s", cmd, err))
		fmt.Println(string(errString))
		return false
	}
	return true
}

/*
GenerateRandomGarbage creates random garbage to rise entropy
*/
func GenerateRandomGarbage(size int64) string {
	randomGarbage := make([]byte, size)
	rand.Read(randomGarbage)
	return string(randomGarbage)
}

/*
GzipContent an input byte slice and return it compressed
*/
func GzipContent(input []byte) []byte {
	// GZIP before encrypt
	var zlibPlaintext bytes.Buffer
	zlibWriter := zlib.NewWriter(&zlibPlaintext)
	zlibWriter.Write(input)
	zlibWriter.Close()

	return zlibPlaintext.Bytes()
}
