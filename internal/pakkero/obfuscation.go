/*
Package pakkero will pack, compress and encrypt any type of executable.
Obfuscation library
*/
package pakkero

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"regexp"
	"strings"
)

// Secrets are the group of strings that we want to obfuscate.
var Secrets = map[string][]string{}

// LauncherStub Stub of the Launcher.go, put here during compilation time.
var LauncherStub = "unset"

var extras = []string{
	// ELF Headers
	".gopclntab",
	".go.buildinfo",
	".noptrdata",
	".noptrbss",
	".data",
	".rodata",
	".text",
	".itablink",
	".shstrtab",
	".data",
	".dynamic",
	".dynstr",
	".dynsym",
	".gnu.version_r",
	".gopclntab",
	".got.plt",
	".init_array",
	".interp",
	".itablink",
	".rela.dyn",
	".rela.plt",
	".tbss",
	".plt",
	".init",
	// internal golang
	"name", "runtime", "command", "cmd",
	"ptr", "process", "unicode", "main",
	"path", "get", "reflect", "context",
	"debug", "fmt", "sync", "sort",
	"size", "heap", "fatal", "call",
	"fixed", "slice", "bit", "file",
	"read", "write", "buffer", "encrypt",
	"decrypt", "hash", "state",
	"external", "internal", "float",
	// anti debug traces
	"env", "trace", "pid",
}

/*
StripUPXHeaders will ensure no trace of UPX headers are left
so that reversing will be more challenging and break
simple attempts like "upx -d" in case of compression.
*/
func StripUPXHeaders(infile string) bool {
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
		`\x55\x50\x58\x21`,
	}
	result := true

	for _, v := range header {
		sedString := ""
		// generate random byte sequence
		replace := make([]byte, 1)

		for len(sedString) < len(v) {
			_, err := rand.Read(replace)
			if err != nil {
				return false
			}

			sedString += `\x` + hex.EncodeToString(replace)
		}
		// replace UPX sequence with random garbage
		result = ExecCommand("sed", []string{"-i", `s/` + v + `/` + sedString + `/g`, infile})
		if !result {
			return result
		}
	}

	return result
}

/*
StripFile will strip out all unneeded headers from and ELF
file in input.
*/
func StripFile(infile string, launcherFile string) bool {
	// strip symbols and headers
	if !ExecCommand("strip",
		[]string{
			"-sxX",
			"--remove-section=.bss",
			"--remove-section=.comment",
			"--remove-section=.eh_frame",
			"--remove-section=.eh_frame_hdr",
			"--remove-section=.fini",
			"--remove-section=.fini_array",
			"--remove-section=.gnu.build.attributes",
			"--remove-section=.gnu.hash",
			"--remove-section=.gnu.version",
			"--remove-section=.gosymtab",
			"--remove-section=.got",
			"--remove-section=.note.ABI-tag",
			"--remove-section=.note.gnu.build-id",
			"--remove-section=.note.go.buildid",
			"--remove-section=.shstrtab",
			"--remove-section=.typelink",
			infile,
		}) {
		return false
	}

	// ------------------------------------------------------------------------
	// proceede with manual
	// stripping of golang builtins and keyWords strings
	removeStrings := []string{}
	removeStrings = append(removeStrings, extras...)
	// stripping of the dependencies strings
	removeStrings = append(removeStrings, ListImportsFromFile(launcherFile)...)
	// anonymize the launcherFile string to hide the original launcher file name
	removeStrings = append(removeStrings, launcherFile)

	// deduplicate
	removeStrings = Unique(removeStrings)

	// read file to string
	byteContent, err := ioutil.ReadFile(infile)
	if err != nil {
		return false
	}

	input := string(byteContent)

	for _, remove := range removeStrings {
		// generate new random string to place instead
		newName := GenerateNullString(len(remove))
		input = strings.ReplaceAll(input, remove, newName)
		input = strings.ReplaceAll(input, strings.Title(remove), newName)
	}
	// save.
	err = ioutil.WriteFile(infile, []byte(input), 0600)
	// ------------------------------------------------------------------------

	return err == nil
}

/*
GenerateTyposquatName is a typosquat name generator
based on a length (128 default) this will create a random
uniqe string composed only of letters and zeroes that are lookalike.
*/
func GenerateTyposquatName(length int) string {
	// We divide between an alphabet with number
	// and one without, because function/variable names
	// must not start with a number.
	letterRunes := []rune("OÓÕÔÒÖŌŎŐƠΘΟ")
	mixedRunes := []rune("0OÓÕÔÒÖŌŎŐƠΘΟ")
	b := make([]rune, length)
	// ensure we do not start with a number or we will break code.
	b[0] = letterRunes[Random(0, int64(len(mixedRunes)-1))]
	for i := range b {
		if i != 0 {
			b[i] = mixedRunes[Random(0, int64(len(mixedRunes)-1))]
		}
	}

	return string(b)
}

/*
ObfuscateFuncVars will:
  - extract all obfuscation-enabled func and var names:
  - those start with "ob*" and will be listed
  - for each matching string generate a typosquatted random string and
    replace all string with that
*/
func ObfuscateFuncVars(input string) string {
	// obfuscate functions and variables names
	regex := regexp.MustCompile(`\bob[a-zA-Z0-9_]+`)
	words := regex.FindAllString(input, -1)
	words = ReverseStringArray(words)
	words = Unique(words)

	for _, w := range words {
		// generate random name for each matching string
		input = strings.ReplaceAll(input, w, GenerateTyposquatName(128))
	}

	return input
}

/*
GenerateStringFunc will hide a string creating a function that returns
that value as a string encoded with a series of length calculation of randomic
string arrays generated.
*/
func GenerateStringFunc(txt string, function string) string {
	resString := "{"
	for _, b := range []byte(txt) {
		resString += "\"" + GenerateTyposquatName(int(b)) + "\"" + ","
	}
	// remove last comma
	resString = strings.TrimSuffix(resString, ",")
	// close array
	resString += "}"
	result := fmt.Sprintf("func " +
		function +
		"() string {\nobRegistered := []string" + resString +
		"\nvar obResult []byte\nfor _,obValue := range obRegistered " +
		"{\nobResult = append(obResult, byte(len([]rune(obValue))))\n}\nreturn string(obResult)\n}")

	return result
}

/*
ObfuscateStrings will extract all plaintext strings denotet with
backticks and obfuscate them using byteshift wise operations.
*/
func ObfuscateStrings(input string) string {
	// parse the launcher file to create the list of imports in it
	imports := strings.Index(input, "import (")
	endimports := strings.Index(input[imports:], ")")

	// import section
	importSection := input[:imports+endimports+1]

	// the rest of the program
	body := input[imports+endimports+1:]

	// various types of string delimiter
	tickTypes := []string{"`", `'`, `"`}

	// for each ticktype, try to get all the strings and
	// obfuscate them using functions
	for _, v := range tickTypes {
		regex := regexp.MustCompile(v + ".*?" + v)
		words := regex.FindAllString(body, -1)
		words = Unique(words)

		for _, w := range words {
			// string not void, accounting for quotes
			if len(w) > 2 && !strings.Contains(w, `\`) {
				// add string to the secrets! if not present
				_, present := Secrets[w]
				if !present {
					secret := w[1 : len(w)-1]
					Secrets[w] = []string{secret, GenerateTyposquatName(128)}
				}
			}
		}
	}
	// create function call
	funcString := ""
	// replace all secrects with the respective obfuscated string
	for k, w := range Secrets {
		// in case we manually added some secrets that we want to leave
		if !strings.Contains(w[1], "leave") {
			funcString = funcString + GenerateStringFunc(w[0], w[1]) + "\n"
			body = strings.ReplaceAll(body, k, w[1]+"()")
		} else {
			body = strings.ReplaceAll(body, k, w[0])
		}
	}

	// reconstruct the program correctly and
	// insert all the functions before the main
	body = body + "\n" + funcString

	// join back with the import section
	return importSection + body
}

/*
GenerateRandomAntiDebug will Insert random order of anti-debug check
together with inline compilation to induce big number
of instructions in random order.
*/
func GenerateRandomAntiDebug(input string) string {
	lines := strings.Split(input, "\n")
	randomChecks := []string{
		`obDependencyCheck()`,
		`obEnvArgsDetect()`,
		`obParentTracerDetect()`,
		`obParentCmdLineDetect()`,
		`obEnvDetect()`,
		`obEnvParentDetect() `,
		`obLdPreloadDetect()`,
		`obParentDetect()`,
	}
	var obfile []string
	// find OB_CHECK and put the checks there.
	for _, v := range lines {
		if strings.Contains(v, "//") {
			if strings.Contains(v, "// OB_CHECK") {
				threadString := ""
				checkString := ""
				// randomize order of check to replace
				for j, v := range ShuffleSlice(randomChecks) {
					threadString = threadString + "go " + v + ";"
					checkString += v

					if j != (len(randomChecks) - 1) {
						checkString += `||`
					}
				}

				// add action in case of failed check
				obfile = append(obfile, threadString)

				continue
			} else {
				// remove comment, this is more to scramble the line numbers
				// and make error reporting less accurate
				continue
			}
		}

		obfile = append(obfile, v)
	}
	// back to single string
	return strings.Join(obfile, "\n")
}

/*
ObfuscateLauncher the go code of the runner before compiling it.

Basic techniques are applied:
- GenerateRandomAntiDebug
- ObfuscateStrings
- ObfuscateFuncVars.
*/
func ObfuscateLauncher(infile string) error {
	byteContent, err := ioutil.ReadFile(infile)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	content := string(byteContent)

	// ------------------------------------------------------------------------
	//	--- Start anti-debug checks
	content = GenerateRandomAntiDebug(content)
	// ------------------------------------------------------------------------

	// ------------------------------------------------------------------------
	//	--- Start string obfuscation
	content = ObfuscateStrings(content)
	// ------------------------------------------------------------------------

	// ------------------------------------------------------------------------
	//	--- Start function name obfuscation
	content = ObfuscateFuncVars(content)
	// ------------------------------------------------------------------------

	// save.
	err = ioutil.WriteFile(infile, []byte(content), 0600)
	if err != nil {
		return fmt.Errorf("failed to save output file: %w", err)
	}

	return nil
}
