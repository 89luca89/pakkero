package packngo

import (
	"fmt"
	mrand "math/rand"
	"os/exec"
	"time"
)

var dependencies = []string{"upx", "ls", "sed", "go", "strip"}

/*
Deduplicate a given slice
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
Reverse a slice of bytes
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
Change a byte endianess
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
Reverse a slice of strings
*/
func ReverseStringArray(ss []string) []string {
	last := len(ss) - 1
	for i := 0; i < len(ss)/2; i++ {
		ss[i], ss[last-i] = ss[last-i], ss[i]
	}
	return ss
}

/*
Reverse a string
*/
func ReverseString(input string) string {
	var result string
	for _, value := range input {
		result = string(value) + result
	}
	return result
}

/*
Shuffle a slice.
*/
func ShuffleSlice(in []string) []string {
	mrand.Seed(time.Now().UnixNano())
	mrand.Shuffle(len(in), func(i, j int) { in[i], in[j] = in[j], in[i] })
	return in
}

/*
Wrapper arount exec.Command to execute a command
and ensure it's result is not err.
Else panic.
*/
func ExecCommand(name string, args []string) {
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
func TestDependencies() error {
	for _, v := range dependencies {
		ExecCommand("which", []string{v})
	}
	return nil
}
