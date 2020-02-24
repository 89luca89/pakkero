package main

import (
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"io/ioutil"
	mrand "math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const offsetPlaceholder = "9999999"

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
	offset = offset + (mrand.Int63n(4096-128) + 128)

	// add offset to the secrets!
	secrets[generateTyposquatName()] = []string{fmt.Sprintf("%d", offset), "`" +
		offsetPlaceholder + "`"}

	copyRunnerSource := exec.Command("cp", selfPath+"/Launcher.go.stub", infile+".go")
	err := copyRunnerSource.Run()
	if err != nil {
		panic(fmt.Sprintf("failed to execute command %s: %s", copyRunnerSource, err))
	}

	// obfuscate
	obfuscateLauncher(infile+".go", fmt.Sprintf("%d", offset))

	// compile the runner binary
	gopath, _ := os.LookupEnv("GOPATH")
	buildRunner := exec.Command("go", "build", "-i",
		"-gcflags=-N",
		"-gcflags=-nolocalimports",
		"-gcflags=-pack",
		"-gcflags=-trimpath="+selfPath,
		"-asmflags=-trimpath="+selfPath,
		"-gcflags=-trimpath="+gopath+"/src/",
		"-asmflags=-trimpath="+gopath+"/src/",
		"-ldflags=-s",
		"-o", outfile,
		infile+".go")
	// -gccgoflags " -Wall -fPIE -O0 -fomit-frame-pointer -finline-small-functions -fcrossjumping -fdata-sections -ffunction-sections "
	err = buildRunner.Run()
	if err != nil {
		panic(fmt.Sprintf("failed to execute command %s: %s", buildRunner, err))
	}

	// strip symbols
	stripRunner := exec.Command("strip", "-s", outfile)
	err = stripRunner.Run()
	if err != nil {
		panic(fmt.Sprintf("failed to execute command %s: %s", stripRunner, err))
	}

	// remove unused file
	removeRunnerSource := exec.Command("rm", "-f", infile+".go")
	err = removeRunnerSource.Run()
	if err != nil {
		panic(fmt.Sprintf("failed to execute command %s: %s", removeRunnerSource, err))
	}

	// read compiled file
	encFile, err := os.OpenFile(outfile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(fmt.Sprintf("failed writing to file: %s", err))
	}
	defer encFile.Close()
	encFileStat, _ := encFile.Stat()
	encFileSize := encFileStat.Size()

	// Ensure input offset is valid comared to compiled file size!
	println(encFileSize)
	println(offset)
	if offset <= encFileSize {
		removeLeftOvers := exec.Command("rm", "-f", outfile)
		err = removeLeftOvers.Run()
		if err != nil {
			panic(fmt.Sprintf("failed writing to file: %s", err))
		}
		panic("ERROR! Calculated offset is lower than launcher size: " +
			fmt.Sprintf("offset=%d, filesize=%d", offset, encFileSize))
	}
	// calculate where to put garbage and where to put the payload
	blockCount := offset - encFileSize

	// create some random garbage to rise entropy
	randomGarbage := make([]byte, 1)
	mrand.Seed(time.Now().UTC().UnixNano())
	rand.Read(randomGarbage)
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

	// GZIP before encrypt
	var zlibPlaintext bytes.Buffer
	zlibWriter := zlib.NewWriter(&zlibPlaintext)
	zlibWriter.Write(plaintext)
	zlibWriter.Close()

	// encrypt aes256-gcm
	ciphertext := encryptAESReversed(zlibPlaintext.Bytes(), outfile)

	// append payload to the runner itself
	_, err = encFile.WriteString(ciphertext)
	if err != nil {
		panic(fmt.Sprintf("failed writing to file: %s", err))
	}

	// calculate final padding
	finalPaddingArray := make([]byte, binary.MaxVarintLen64)
	n := binary.PutVarint(finalPaddingArray, offset)
	finalPaddingB := finalPaddingArray[:n]
	for i := range finalPaddingB {
		finalPaddingB[i] = reverseByte(finalPaddingB[i])
	}
	finalPadding, _ := binary.Varint(finalPaddingB)
	// make it positive!
	if finalPadding < 0 {
		finalPadding = finalPadding * -1
	}

	// create another random garbage to rise entropy
	randomEndGarbage := make([]byte, 1)
	mrand.Seed(time.Now().UTC().UnixNano())
	rand.Read(randomEndGarbage)
	for int64(len(randomEndGarbage)) < finalPadding {
		mrand.Seed(time.Now().UTC().UnixNano())
		garbageByte := make([]byte, 1)
		rand.Read(garbageByte)
		randomEndGarbage = append(randomEndGarbage, garbageByte[0])
	}

	// append random garbage equal to bit-reverse of the offset
	// at the end of the payload
	_, err = encFile.WriteString(string(randomEndGarbage))
	if err != nil {
		panic(fmt.Sprintf("failed writing to file: %s", err))
	}
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
			if *file != "" && *offset >= 0 {
				PackNGo(*file, *offset, *output)
			} else {
				println("Missing arguments or invalid arguments!")
				help()
				os.Exit(1)
			}
		}
	}
}
