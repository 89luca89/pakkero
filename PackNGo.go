package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	mrand "math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const programName = "PackNGo"
const version = "0.1.0"

var dependencies = []string{"upx", "ls", "sed", "go", "strip"}

/*
Reverse a slice of bytes
*/
func reverse(input []byte) []byte {
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
func bitReverse(b byte) byte {
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
func arrStringReverse(ss []string) []string {
	last := len(ss) - 1
	for i := 0; i < len(ss)/2; i++ {
		ss[i], ss[last-i] = ss[last-i], ss[i]
	}
	return ss
}

/*
Reverse a string
*/
func stringReverse(input string) string {
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
Typosquat name generator
based on a lenght (128 default) this will create a random
uniqe string composed only of letters and zeroes that are lookalike.
*/
func generateName() string {
	letterRunes := []rune("OÓÕÔÒÖØŌŎŐƠǑȌȎȪȬΌΘΟϴ")
	mixedRunes := []rune("0OÓÕÔÒÖØŌŎŐƠǑȌȎȪȬΌΘΟϴ")
	mrand.Seed(time.Now().UnixNano())
	lenght := 128
	b := make([]rune, lenght)
	mrand.Seed(time.Now().UnixNano())
	// ensure we do not start with a number or we will break code.
	b[0] = letterRunes[mrand.Intn(len(letterRunes))]
	for i := range b {
		if i != 0 {
			b[i] = mixedRunes[mrand.Intn(len(mixedRunes))]
		}
	}
	return string(b)
}

/*
Generate an obfuscated string from input:
    - reverse it
    - b64 it
    - bit fot bit endianess
*/
func generateStaticString(in string) []byte {
	in = stringReverse(in)
	result := []byte(base64.StdEncoding.EncodeToString([]byte(in)))
	for index := range result {
		result[index] = bitReverse(result[index])
	}
	return result
}

/*

This part will attempt to obfuscate the go code of the runner before
compiling it.

Basic techniques are applied:
- Insert anti-debug checks in random order to ensure binaries generated are
  always different
- Insert those anti-debug checks whenever in the code a "// OB_CHECK" is present
- remove comments
- extract all obfuscation-enabled func and var names:
    - those start with ob_* and will bel isted
    - for each matching string generate a typosquatted random string and
      replace all string with that
- insert in the runner the chosen offset
*/
func obfuscate(infile string, offset string) int {

	content, err := ioutil.ReadFile(infile)
	if err != nil {
		panic(fmt.Sprintf("failed reading file: %s", err))
	}
	lines := strings.Split(string(content), "\n")

	// randomize anti-debug checks
	randomChecks := []string{
		`ob_parent_cmdline()`,
		`ob_env_detect()`,
		`ob_environ_parent() `,
		`ob_ld_preload_detect()`,
		`ob_parent_detect()`}
	for i, v := range lines {
		if strings.Contains(v, "// OB_CHECK") {
			sedString := ""
			// randomize order of check to replace
			for j, v := range shuffleSlice(randomChecks) {
				sedString = sedString + v
				if j != (len(randomChecks) - 1) {
					sedString = sedString + `||`
				}
			}
			// add action in case of failed check
			lines[i] = `if ` + sedString + `{ ob_fmt.Println(ob_get_string(ob_link)) }`
		} else if strings.Contains(v, "//") {
			// remove comments
			lines[i] = ""
		}
	}
	// back to single string
	output := strings.Join(lines, "\n")

	// obfuscate functions and variables names
	r := regexp.MustCompile(`ob_[a-zA-Z_]+`)
	words := r.FindAllString(output, -1)
	words = arrStringReverse(words)
	for _, w := range words {
		// generate random name for each matching string
		output = strings.ReplaceAll(output, w, generateName())
	}

	// insert offset
	output = strings.ReplaceAll(output, "PLACEHOLDER_OFFSET", offset)
	// remove indentation
	output = strings.ReplaceAll(output, "\t", "")

	// save.
	ioutil.WriteFile(infile, []byte(output), 0644)

	return 0
}

/*
Using UPX To shrink the binary is good
this will ensure no trace of UPX headers are left
so that reversing will be more challenging and break
simple attempts like "upx -d"
*/
func stripUPX(infile string) {
	// Bit sequence of UPX copyright and header infos
	header := []string{
		`\x49\x6e\x66\x6f\x3a\x20\x54\x68\x69\x73`,
		`\x20\x66\x69\x6c\x65\x20\x69\x73\x20\x70`,
		`\x61\x63\x6b\x65\x64\x20\x77\x69\x74\x68`,
		`\x20\x74\x68\x65\x20\x55\x50\x58\x20\x65`,
		`\x78\x65\x63\x75\x74\x61\x62\x6c\x65\x20`,
		`\x70\x61\x63\x6b\x65\x72\x20\x68\x74\x74`,
		`\x70\x3a\x2f\x2f\x75\x70\x78\x2e\x73\x66`,
		`\x2e\x6e\x65\x74\x20\x24\x0a\x00\x24\x49`,
		`\x64\x3a\x20\x55\x50\x58\x20\x33\x2e\x39`,
		`\x36\x20\x43\x6f\x70\x79\x72\x69\x67\x68`,
		`\x74\x20\x28\x43\x29\x20\x31\x39\x39\x36`,
		`\x2d\x32\x30\x32\x30\x20\x74\x68\x65\x20`,
		`\x55\x50\x58\x20\x54\x65\x61\x6d\x2e\x20`,
		`\x41\x6c\x6c\x20\x52\x69\x67\x68\x74\x73`,
		`\x20\x52\x65\x73\x65\x72\x76\x65\x64\x2e`,
		`\x55\x50\x58\x21`}
	for _, v := range header {
		sedString := ""
		// generate random byte sequence
		replace := make([]byte, 1)
		for len(sedString) < len(v) {
			mrand.Seed(time.Now().UTC().UnixNano())
			rand.Read(replace)
			sedString += `\x` + hex.EncodeToString(replace)
		}
		// replace UPX sequence with random garbage
		cmd := exec.Command("sed", "-i", `s/`+v+`/`+sedString+`/g`, infile)
		err := cmd.Run()
		if err != nil {
			panic(fmt.Sprintf("failed to execute command %s: %s", cmd.String(), err))
		}
	}
}

/*
Wrapper around AESGCM encryption

this will not only encrypt the payload but:
- generate a password using the randomized UPX Binary's md5sum
- cipher the payload with AESGCM using the generated password
- swap endianess on all the encrypted bytes
- reverse the complete payload
*/
func encryptAESGCM(plaintext []byte, outfile string) string {
	// generate a password using the randomized UPX Binary's md5sum
	/*
			    the aes-256 psk is the md5sum of the whole executable
		        this is also useful to protect against NOP attacks to the anti-debug
		        features in the binary.
		        This doubles also as anti-tamper measure.
	*/
	b, err := ioutil.ReadFile(outfile)
	if err != nil {
		panic(fmt.Sprintf("failed reading file: %s", err))
	}
	key := md5.Sum(b)
	//	generate new cipher
	c, err := aes.NewCipher(key[:])
	if err != nil {
		fmt.Println(err)
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		fmt.Println(err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Println(err)
	}

	// cipher the payload with AESGCM using the generated password
	bCiphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	// swap endianess on all the encrypted bytes
	for i := range bCiphertext {
		bCiphertext[i] = bitReverse(bCiphertext[i])
	}

	ciphertext := string(bCiphertext)

	// reverse the complete payload
	ciphertext = string(reverse([]byte(ciphertext)))
	return ciphertext
}

// PackNGo will Encrypt and pack the payload for a secure execution
func PackNGo(infile string, offset int64, outfile string) {

	// get the current script path
	selfPath := filepath.Dir(os.Args[0])
	// declare outfile as original filename + .enc
	if len(outfile) <= 0 {
		outfile = infile + ".enc"
	}
	// offset Hysteresis, this will prevent easy key retrieving
	mrand.Seed(time.Now().UTC().UnixNano())
	offset = offset + (mrand.Int63n(2048-128) + 128)

	copyRunnerSource := exec.Command("cp", selfPath+"/run.go", infile+".go")
	copyRunnerSource.Run()

	// obfuscate
	obfuscate(infile+".go", fmt.Sprintf("%d", offset))

	// compile the runner binary
	buildRunner := exec.Command("go", "build", "-i", "-gcflags", "-N -l", "-ldflags",
		"-s -w -extldflags -static",
		"-o", outfile,
		infile+".go")
	err := buildRunner.Run()
	if err != nil {
		panic(fmt.Sprintf("failed to execute command %s: %s", buildRunner.String(), err))
	}

	// strip symbols
	stripRunner := exec.Command("strip", outfile)
	err = stripRunner.Run()
	if err != nil {
		panic(fmt.Sprintf("failed to execute command %s: %s", stripRunner.String(), err))
	}
	// run UPX to shrink output size
	upxRunner := exec.Command("upx", "--ultra-brute", outfile)
	err = upxRunner.Run()
	if err != nil {
		panic(fmt.Sprintf("failed to execute command %s: %s", upxRunner.String(), err))
	}
	// strip UPX headers
	stripUPX(outfile)

	// remove unused file
	removeRunnerSource := exec.Command("rm", "-f", infile+".go")
	err = removeRunnerSource.Run()
	if err != nil {
		panic(fmt.Sprintf("failed to execute command %s: %s", removeRunnerSource.String(), err))
	}

	// read compiled file
	encFile, err := os.OpenFile(outfile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(fmt.Sprintf("failed writing to file: %s", err))
	}
	defer encFile.Close()
	encFileStat, _ := encFile.Stat()
	encFileSize := encFileStat.Size()
	// calculate where to put garbage and where to put the payload
	blockCount := offset - encFileSize

	// create some random garbage to rise entropy
	randomGarbage := make([]byte, 1)
	for int64(len(randomGarbage)) < blockCount {
		mrand.Seed(time.Now().UTC().UnixNano())
		garbageByte := make([]byte, 1)
		rand.Read(garbageByte)
		randomGarbage = append(randomGarbage, garbageByte[0])
	}

	// append randomness to the runner itself
	_, err = encFile.WriteString(string(randomGarbage))
	if err != nil {
		panic(fmt.Sprintf("failed writing to file: %s", err))
	}

	// get file to encrypt argument
	b, err := ioutil.ReadFile(infile) // just pass the file name
	content := string(b)

	// plaintext content
	plaintext := []byte(base64.StdEncoding.EncodeToString([]byte(content)))

	// encrypt aes256-gcm
	ciphertext := encryptAESGCM(plaintext, outfile)

	// append payload to the runner itself
	_, err = encFile.WriteString(ciphertext)
	if err != nil {
		panic(fmt.Sprintf("failed writing to file: %s", err))
	}
}

/*
Test if all dependencies are present
in the system
*/
func testDependencies() error {
	for _, v := range dependencies {
		cmd := exec.Command("which", v)
		err := cmd.Run()
		if err != nil {
			panic("Missing dependency: " + v)
			return err
		}
	}
	return nil
}

/*
Print help.
*/
func help() {
	fmt.Println("Usage: ./encrypt -file /path/to/file -offset OFFSET")
	fmt.Println("  -file				Target file to Pack")
	fmt.Println("  -o   <file>			Place the output into <file>")
	fmt.Println("  -offset			Offset where to start the payload (Bytes)")
	fmt.Println("				Offset minimal value is 600000")
	fmt.Println("  -v				Check " + programName + " version")
}

/*
Print version.
*/
func printVersion() {
	fmt.Println(programName + " v" + version)
	os.Exit(0)
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
		output := flag.String("o", "", "")
		offset := flag.Int64("offset", 0, "")
		flag.Bool("v", false, "")
		flag.Parse()

		switch os.Args[1] {
		case "-v":
			printVersion()
		default:
			if *file != "" && *offset >= int64(600000) {
				PackNGo(*file, *offset, *output)
			} else {
				fmt.Println("Missing arguments or invalid arguments!")
				help()
				os.Exit(1)
			}
		}
	}
}
