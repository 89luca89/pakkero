package packngo

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	mrand "math/rand"
	"regexp"
	"strings"
	"time"
)

// Secrets are the group of strings that we want to obfuscate
var Secrets = map[string][]string{}

const LauncherStub = "LAUNCHERSTUB"

/*
StripUPXHeaders will ensure no trace of UPX headers are left
so that reversing will be more challenging and break
simple attempts like "upx -d"
*/
func StripUPXHeaders(infile string) {
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
			rand.Read(replace)
			sedString += `\x` + hex.EncodeToString(replace)
		}
		// replace UPX sequence with random garbage
		ExecCommand("sed", []string{"-i", `s/` + v + `/` + sedString + `/g`, infile})
	}
}

/*
StripFile will strip out all unneeded headers from and ELF
file in input
*/
func StripFile(infile string) {

	// strip symbols and headers
	ExecCommand("strip",
		[]string{"-sxXwSgd",
			"--remove-section=.bss",
			"--remove-section=.comment",
			"--remove-section=.eh_frame",
			"--remove-section=.eh_frame_hdr",
			"--remove-section=.fini",
			"--remove-section=.fini_array",
			"--remove-section=.gnu.build.attributes",
			"--remove-section=.gnu.hash",
			"--remove-section=.gnu.version",
			"--remove-section=.got",
			"--remove-section=.note.ABI-tag",
			"--remove-section=.note.gnu.build-id",
			"--remove-section=.note.go.buildid",
			"--remove-section=.shstrtab",
			"--remove-section=.typelink",
			infile})
}

/*
GenerateTyposquatName is a gyposquat name generator
based on a lenght (128 default) this will create a random
uniqe string composed only of letters and zeroes that are lookalike.
*/
func GenerateTyposquatName() string {
	// We divide between an alphabet with number
	// and one without, because function/variable names
	// must not start with a number.
	letterRunes := []rune("OÓÕÔÒÖØŌŎŐƠǑȌȎȪȬΌΘΟϴ")
	mixedRunes := []rune("0OÓÕÔÒÖØŌŎŐƠǑȌȎȪȬΌΘΟϴ")
	lenght := 128
	b := make([]rune, lenght)
	// ensure we do not start with a number or we will break code.
	b[0] = letterRunes[mrand.Intn(len(letterRunes))]
	for i := range b {
		if i != 0 {
			mrand.Seed(time.Now().UnixNano())
			b[i] = mixedRunes[mrand.Intn(len(mixedRunes))]
		}
	}
	return string(b)
}

/*
ObfuscateString will hide a string creating a function that returns
that value as a string encoded with a series og byteshift operations
*/
func ObfuscateString(txt string, function string) string {
	lines := []string{}
	for _, item := range []byte(txt) {
		lines = append(
			lines, GetOnecodedChar(item),
		)
	}
	return fmt.Sprintf("func "+
		function+
		"() string { return string(\n[]byte{\n%s,\n},\n)}",
		strings.Join(lines, ",\n"))
}

/*
GetOnecodedChar will transform a char/byte in a series of operations on value 1

thanks to:
https://github.com/GH0st3rs/obfus/blob/master/obfus.go
*/
func GetOnecodedChar(n byte) (buf string) {
	var arr []byte
	var x uint8
	for n > 1 {
		x = 0
		if n%2 == 1 {
			x = 1
		}
		arr = append(arr, x)
		n = n >> 1
	}
	buf = "1"
	mrand.Seed(time.Now().Unix())
	for i := len(arr) - 1; i >= 0; i-- {
		buf = fmt.Sprintf("%s<<%s", buf, "1")
		if arr[i] == 1 {
			op := "(%s|%s)"
			if mrand.Intn(2) == 0 {
				op = "(%s^%s)"
			}
			buf = fmt.Sprintf(op, buf, "1")
		}
	}
	return buf
}

/*
ObfuscateLauncher the go code of the runner before compiling it.

Basic techniques are applied:
- Insert anti-debug checks in random order to ensure binaries generated are
  always different
- Insert those anti-debug checks whenever in the code a "// OB_CHECK" is present
- extract all plaintext strings denotet with backticks and obfuscate them
	using byteshift wise operations
- extract all obfuscation-enabled func and var names:
    - those start with ob_* and will bel isted
    - for each matching string generate a typosquatted random string and
      replace all string with that
- insert in the runner the chosen offset
*/
func ObfuscateLauncher(infile string, offset string) error {

	content, err := ioutil.ReadFile(infile)
	if err != nil {
		return err
	}
	lines := strings.Split(string(content), "\n")

	// ------------------------------------------------------------------------
	//	--- Start anti-debug
	// ------------------------------------------------------------------------
	// Insert random order of anti-debug check
	// together with inline compilation to induce big number
	// of instructions in random order
	randomChecks := []string{
		`obEnvArgsDetect()`,
		`obPtraceNearHeap()`,
		`obParentTracerDetect()`,
		`obParentCmdLineDetect()`,
		`obEnvDetect()`,
		`obEnvParentDetect() `,
		`obLdPreloadDetect()`,
		`obParentDetect()`}
	// find OB_CHECK and put the checks there.
	for i, v := range lines {
		if strings.Contains(v, "// OB_CHECK") {
			sedString := ""
			// randomize order of check to replace
			for j, v := range ShuffleSlice(randomChecks) {
				sedString = sedString + v
				if j != (len(randomChecks) - 1) {
					sedString = sedString + `||`
				}
			}
			// add action in case of failed check
			lines[i] = `if ` + sedString + "{ println(`https://shorturl.at/crzEZ`); obOS.Exit(127) }"
		}
	}
	// back to single string
	output := strings.Join(lines, "\n")
	// ------------------------------------------------------------------------

	// ------------------------------------------------------------------------
	//	--- Start string obfuscation
	// ------------------------------------------------------------------------
	// Regex all plaintext strings denoted by backticks
	regex := regexp.MustCompile("`[/a-zA-Z.:_-]+`")
	words := regex.FindAllString(output, -1)
	words = Unique(words)
	for _, w := range words {
		// add string to the secrets!
		secret := w[1 : len(w)-1]
		Secrets[GenerateTyposquatName()] = []string{secret, w}
	}
	// create function call
	sedString := ""
	// replace all secrects with the respective obfuscated string
	for k, w := range Secrets {
		sedString = sedString + ObfuscateString(w[0], k) + "\n"
		output = strings.ReplaceAll(output, w[1], k+"()")
	}
	// insert all the functions before the main
	sedString = sedString + "func main() {\n"
	output = strings.ReplaceAll(output, "func main() {", sedString)
	// ------------------------------------------------------------------------

	// ------------------------------------------------------------------------
	//	--- Start function name obfuscation
	// ------------------------------------------------------------------------
	// obfuscate functions and variables names
	regex = regexp.MustCompile(`\bob[a-zA-Z0-9_]+`)
	words = regex.FindAllString(output, -1)
	words = ReverseStringArray(words)
	words = Unique(words)
	for _, w := range words {
		// generate random name for each matching string
		output = strings.ReplaceAll(output, w, GenerateTyposquatName())
	}
	// ------------------------------------------------------------------------

	// save.
	ioutil.WriteFile(infile, []byte(output), 0644)

	return nil
}
