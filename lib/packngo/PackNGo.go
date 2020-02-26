package packngo

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	mrand "math/rand"
	"os"
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
	Secrets[GenerateTyposquatName()] = []string{fmt.Sprintf("%d", offset), "`" +
		offsetPlaceholder + "`"}

	// copy the stub from where to start.
	launcherStub, _ := base64.StdEncoding.DecodeString(LauncherStub)
	err := ioutil.WriteFile(infile+".go", launcherStub, 0644)
	// ------------------------------------------------------------------------
	// obfuscate the launcher
	ObfuscateLauncher(infile+".go", fmt.Sprintf("%d", offset))
	// ------------------------------------------------------------------------

	// ------------------------------------------------------------------------
	// compile the launcher binary
	// ------------------------------------------------------------------------
	gopath, _ := os.LookupEnv("GOPATH")
	var flags []string
	os.Setenv("CGO_CFLAGS",
		"-static -Wall -fPIE -O0 -fomit-frame-pointer -finline-small-functions"+
			" -fcrossjumping -fdata-sections -ffunction-sections")
	flags = []string{"build",
		"-gcflags=-N",
		"-gcflags=-nolocalimports",
		"-gcflags=-pack",
		"-gcflags=-trimpath=" + selfPath,
		"-asmflags=-trimpath=" + selfPath,
		"-gcflags=-trimpath=" + gopath + "/src/",
		"-asmflags=-trimpath=" + gopath + "/src/",
		"-ldflags=-extldflags=-static",
		"-ldflags=-s"}
	flags = append(flags, "-o")
	flags = append(flags, outfile)
	flags = append(flags, infile+".go")
	ExecCommand("go", flags)
	// ------------------------------------------------------------------------

	// ------------------------------------------------------------------------
	// Strip File of excess headers
	// ------------------------------------------------------------------------
	StripFile(outfile)
	// ------------------------------------------------------------------------

	// remove unused file
	ExecCommand("rm", []string{"-f", infile + ".go"})

	// read compiled file
	encFile, err := os.OpenFile(outfile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(fmt.Sprintf("failed writing to file: %s", err))
	}
	defer encFile.Close()
	encFileStat, _ := encFile.Stat()
	encFileSize := encFileStat.Size()

	// Ensure input offset is valid comared to compiled file size!
	if offset <= encFileSize {
		ExecCommand("rm", []string{"-f", outfile})
		panic("ERROR! Calculated offset is lower than launcher size: " +
			fmt.Sprintf("offset=%d, filesize=%d", offset, encFileSize))
	}

	// ------------------------------------------------------------------------
	// Pre-Payload Garbage
	// ------------------------------------------------------------------------
	// calculate where to put garbage and where to put the payload
	blockCount := offset - encFileSize
	// append randomness to the runner itself
	_, err = encFile.WriteString(GenerateRandomGarbage(blockCount))
	if err != nil {
		panic(fmt.Sprintf("failed writing to file: %s", err))
	}
	// ------------------------------------------------------------------------

	// ------------------------------------------------------------------------
	// Encryption and compression of the payload
	// ------------------------------------------------------------------------
	// get file to encrypt argument
	byteContent, err := ioutil.ReadFile(infile) // just pass the file name
	content := string(byteContent)

	// plaintext content
	plaintext := []byte(base64.StdEncoding.EncodeToString([]byte(content)))

	// GZIP before encrypt
	plaintext = GzipContent(plaintext)

	// encrypt aes256-gcm
	ciphertext := EncryptAESReversed(plaintext, outfile)

	// append payload to the runner itself
	_, err = encFile.WriteString(ciphertext)
	if err != nil {
		panic(fmt.Sprintf("failed writing to file: %s", err))
	}
	// ------------------------------------------------------------------------

	// ------------------------------------------------------------------------
	// Post-Payload Garbage
	// ------------------------------------------------------------------------
	// calculate final padding
	finalPaddingArray := make([]byte, binary.MaxVarintLen64)
	n := binary.PutVarint(finalPaddingArray, offset)
	finalPaddingB := finalPaddingArray[:n]
	// change endianess to every byte composing
	// the offset
	for i := range finalPaddingB {
		finalPaddingB[i] = ReverseByte(finalPaddingB[i])
	}
	finalPadding, _ := binary.Varint(finalPaddingB)
	// and ensure it is positive!
	if finalPadding < 0 {
		finalPadding = finalPadding * -1
	}

	// append random garbage equal to bit-reverse of the offset
	// at the end of the payload
	_, err = encFile.WriteString(GenerateRandomGarbage(finalPadding))
	if err != nil {
		panic(fmt.Sprintf("failed writing to file: %s", err))
	}
	// ------------------------------------------------------------------------
}
