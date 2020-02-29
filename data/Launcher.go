//go:binary-only-package
package main

/*
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>

// GDB relocates the heap to the end of the bss section
int near_heap() {
	static unsigned char bss;
	unsigned char *testmem = malloc(0x10);

	if (testmem - &bss > 0x20000) {
		return 0;
	} else {
		return -1;
	}

}
*/
import "C"
import (
	obBytes "bytes"
	obZlib "compress/zlib"
	obAES "crypto/aes"
	obCipher "crypto/cipher"
	obMD5 "crypto/md5"
	obBase64 "encoding/base64"
	obBinary "encoding/binary"
	"fmt"
	obIO "io"
	obUtilio "io/ioutil"
	obMath "math"
	obOS "os"
	obExec "os/exec"
	obStrconv "strconv"
	obStrings "strings"
	obSyscall "syscall"
	obUnsafe "unsafe"
)

type obDependency struct {
	obDepSize string
	obDepName string
	obDepELF  string
	obDepBFD  []int64
}

/*
attach to PTRACE, register if successful
attach A G A I N , register if unsuccessful
this protects against custom ptrace (always returning 0)
against NOP attacks and LD_PRELOAD attacks
*/
func obPtraceDetect() {
	var obOffset = 0
	_, _, obResult := obSyscall.RawSyscall(obSyscall.SYS_PTRACE,
		uintptr(obSyscall.PTRACE_TRACEME),
		0,
		0)
	if obResult == 0 {
		obOffset = 5
	}
	_, _, obResult = obSyscall.RawSyscall(obSyscall.SYS_PTRACE,
		uintptr(obSyscall.PTRACE_TRACEME),
		0,
		0)
	if obResult == 1 {
		obOffset *= 3
	}
	if obOffset != 15 {
		obOS.Exit(127)
	}
}

// calculate BFD (byte frequency distribution) for the input dependency
func obBFDCalculation(obInput string) []int64 {
	obFile, _ := obUtilio.ReadFile(obInput)

	obBfd := make([]int64, 256)
	for _, obValue := range obFile {
		obBfd[obValue] = obBfd[obValue] + 1
	}
	return obBfd
}

// Abs returns the absolute value of obInput.
func obAbs(obInput int64) int64 {
	if obInput < 0 {
		return -obInput
	}
	return obInput
}

// calculate the standard deviation of the values of reference over
// retrieved values
func obBFDStdeviation(obDepBFD []int64, obTargetBFD []int64) float64 {
	obDiffs := [256]float64{}
	obSums := 0.0
	obDepSums := 0.0
	// calculate the array of rations between the values
	for obIndex := 0; obIndex < 256; obIndex++ {
		// add 1 to both to work aroung division by zero
		obDiffs[obIndex] = float64(obAbs(obDepBFD[obIndex] - obTargetBFD[obIndex]))
		obSums += obDiffs[obIndex]
		// increase obDep to calculate mean value of registered distribution
		obDepSums += float64(obDepBFD[obIndex])
	}
	// calculate the mean
	obDepSums = obDepSums / 256
	// calculate the mean
	obMean := obSums / 256
	obStdDev := 0.0
	// calculate the standard deviation
	for obIndex := 0; obIndex < 256; obIndex++ {
		obStdDev += obMath.Pow(float64(obDiffs[obIndex]-obMean), 2)
	}
	obStdDev = (obMath.Sqrt(obStdDev / 256)) / obDepSums
	return obStdDev
}

func obDependencyCheck() bool {
	obStrControl1 := `_DEP`
	obStrControl2 := `_NAME`
	obStrControl3 := `_SIZE`
	obDep := obDependency{
		obDepName: `DEPNAME1`,
		obDepSize: `DEPSIZE2`,
		obDepELF:  `DEPELF3`,
		obDepBFD:  `DEPBFD4`}
	// control that we effectively want to control the dependencies
	if (obDep.obDepName != obStrControl1[1:]+obStrControl2[1:]+"1") &&
		(obDep.obDepSize != obStrControl1[1:]+obStrControl3[1:]+"2") {

		// check if the file is a symbolic link
		obLTargetStats, _ := obOS.Lstat(obDep.obDepName)
		if (obLTargetStats.Mode() & obOS.ModeSymlink) != 0 {
			return true
		}
		// open dependency in current environment and check it's size
		obFile, err := obOS.Open(obDep.obDepName)
		if err != nil {
			return true
		}

		obExpected, _ := obStrconv.ParseBool(obDep.obDepELF)
		// check if the header is valid and we expect it to be
		// equivalent to the one we registered
		obELF := make([]byte, 4)
		obFile.Read(obELF)
		if obExpected != obStrings.Contains(string(obELF), `ELF`) {
			return true
		}

		obStatsFile, _ := obFile.Stat()
		obTargetDepSize, _ := obStrconv.ParseInt(obDep.obDepSize, 10, 64)
		obTargetTreshold := (obTargetDepSize / 100) * 15
		// first check if file size is +/- 15% of registered size
		if (obStatsFile.Size()-obTargetDepSize) < (-1*(obTargetTreshold)) ||
			(obStatsFile.Size()-obTargetDepSize) > obTargetTreshold {
			return true
		}

		// Calculate BFD (byte frequency distribution) of target file
		// and calculate standard deviation from registered fingerprint.
		obTargetBFD := obBFDCalculation(obDep.obDepName)
		obStdDev := obBFDStdeviation(obDep.obDepBFD, obTargetBFD)
		// standard deviation should not be greater than 1
		if obStdDev > 1 {
			return true
		}
	}
	return false
}

func obPtraceNearHeap() bool {
	return C.near_heap() < 0
}

func obParentCmdLineDetect() bool {
	obPidParent := obOS.Getppid()

	obNameFile := `/proc/` + obStrconv.FormatInt(int64(obPidParent), 10) +
		`/cmdline`
	obStatParent, _ := obUtilio.ReadFile(obNameFile)
	if obStrings.Contains(string(obStatParent), `gdb`) ||
		obStrings.Contains(string(obStatParent), `strace`) ||
		obStrings.Contains(string(obStatParent), `ltrace`) ||
		obStrings.Contains(string(obStatParent), `lldb`) ||
		obStrings.Contains(string(obStatParent), `valgrind`) ||
		obStrings.Contains(string(obStatParent), `dlv`) ||
		obStrings.Contains(string(obStatParent), `edb`) ||
		obStrings.Contains(string(obStatParent), `frida`) ||
		obStrings.Contains(string(obStatParent), `ghidra`) ||
		obStrings.Contains(string(obStatParent), `ida`) ||
		obStrings.Contains(string(obStatParent), `godebug`) {
		return true
	}
	return false
}
func obParentTracerDetect() bool {
	obPidParent := obOS.Getppid()

	obNameFile := `/proc/` + obStrconv.FormatInt(int64(obPidParent), 10) +
		`/status`
	obStatParent, _ := obUtilio.ReadFile(obNameFile)
	obStatLines := obStrings.Split(string(obStatParent), "\n")
	for _, obValue := range obStatLines {
		if obStrings.Contains(obValue, `TracerPid`) {
			obSplitArray := obStrings.Split(obValue, `:`)
			obSplitValue := obStrings.Replace(obSplitArray[1], " ", "", -1)
			obSplitValue = obStrings.Replace(obSplitArray[1], "\t", "", -1)
			if obSplitValue != `0` {
				return true
			}
		}
	}
	return false
}

func obParentDetect() bool {
	obPidParent := obOS.Getppid()

	obNameFile := `/proc/` + obStrconv.FormatInt(int64(obPidParent), 10) +
		`/stat`
	obStatParent, _ := obUtilio.ReadFile(obNameFile)
	if obStrings.Contains(string(obStatParent), `gdb`) ||
		obStrings.Contains(string(obStatParent), `strace`) ||
		obStrings.Contains(string(obStatParent), `ltrace`) ||
		obStrings.Contains(string(obStatParent), `lldb`) ||
		obStrings.Contains(string(obStatParent), `valgrind`) ||
		obStrings.Contains(string(obStatParent), `dlv`) ||
		obStrings.Contains(string(obStatParent), `edb`) ||
		obStrings.Contains(string(obStatParent), `frida`) ||
		obStrings.Contains(string(obStatParent), `ghidra`) ||
		obStrings.Contains(string(obStatParent), `ida`) ||
		obStrings.Contains(string(obStatParent), `godebug`) {
		return true
	}
	return false
}

func obEnvArgsDetect() bool {
	obLines, _ := obOS.LookupEnv(`_`)
	return obLines != obOS.Args[0]
}

func obEnvParentDetect() bool {
	obLines, _ := obOS.LookupEnv(`_`)
	if obStrings.Contains(string(obLines), `gdb`) ||
		obStrings.Contains(string(obLines), `strace`) ||
		obStrings.Contains(string(obLines), `ltrace`) ||
		obStrings.Contains(string(obLines), `lldb`) ||
		obStrings.Contains(string(obLines), `valgrind`) ||
		obStrings.Contains(string(obLines), `dlv`) ||
		obStrings.Contains(string(obLines), `frida`) ||
		obStrings.Contains(string(obLines), `edb`) ||
		obStrings.Contains(string(obLines), `ghidra`) ||
		obStrings.Contains(string(obLines), `ida`) ||
		obStrings.Contains(string(obLines), `godebug`) {
		return true
	}
	return false
}
func obEnvDetect() bool {
	_, obLines := obOS.LookupEnv(`LINES`)
	_, obColumns := obOS.LookupEnv(`COLUMNS`)
	_, obLineLdPreload := obOS.LookupEnv(`LD_PRELOAD`)
	if obLines || obColumns || obLineLdPreload {
		return true
	}
	return false
}

func obLdPreloadDetect() bool {
	if obEnvDetect() == false {
		obOS.Setenv(`LD_PRELOAD`, `obstring`)
		obLineLdPreload, _ := obOS.LookupEnv(`LD_PRELOAD`)
		if obLineLdPreload == `obstring` {
			obOS.Unsetenv(`LD_PRELOAD`)
			return false
		}
		return true
	}
	return false
}

/*
Reverse a slice of bytes
*/
func obReverseByteArray(obInput []byte) []byte {
	obResult := []byte{}
	for i := range obInput {
		n := obInput[len(obInput)-1-i]
		obResult = append(obResult, n)
	}
	return obResult
}

// Change byte endianess
func obByteReverse(obBar byte) byte {
	var obFoo byte
	for obStart := 0; obStart < 8; obStart++ {
		obFoo <<= 1
		obFoo |= obBar & 1
		obBar >>= 1
	}
	return obFoo
}

const (
	obCloexec uint = 1
	// allow seal operations to be performed
	obAllowSealing uint = 2
	// memfd is now immutable
	obSealAll = 0x0001 | 0x0002 | 0x0004 | 0x0008
	// amd64 specific
	obSysFCNTL       = obSyscall.SYS_FCNTL
	obSysMEMFDCreate = 319
)

func obProceede() {
	// OB_CHECK
	obNameFile, _ := obOS.Executable()
	obFile, _ := obOS.Open(obNameFile)
	defer obFile.Close()

	// OB_CHECK
	obOffset, _ := obStrconv.ParseInt(`9999999`, 10, 64)
	obStatsFile, _ := obFile.Stat()

	// calculate final padding
	obArrayFinalPadding := make([]byte, obBinary.MaxVarintLen64)
	obByteFinalPadding := obArrayFinalPadding[:obBinary.PutVarint(obArrayFinalPadding, obOffset)]
	for obIndex := range obByteFinalPadding {
		obByteFinalPadding[obIndex] = obByteReverse(obByteFinalPadding[obIndex])
	}
	obFinalPadding, _ := obBinary.Varint(obByteFinalPadding)
	// make it positive!
	if obFinalPadding < 0 {
		obFinalPadding = obFinalPadding * -1
	}
	// read the complete executable
	obKey := make([]byte, obOffset)
	obFile.Read(obKey)

	// OB_CHECK
	obSizeFile := obStatsFile.Size() - obOffset

	// OB_CHECK
	obFile.Seek(obOffset, 0)
	obCiphertext := make([]byte, obSizeFile)
	// OB_CHECK
	obFile.Read(obCiphertext)
	obCiphertext = obCiphertext[:int64(len(obCiphertext))-obFinalPadding]
	// OB_CHECK
	// the payload was reversed!
	obCiphertext = obReverseByteArray(obCiphertext)

	// OB_CHECK
	// restore endianess
	for obIndex := range obCiphertext {
		obCiphertext[obIndex] = obByteReverse(obCiphertext[obIndex])
	}

	// OB_CHECK
	/*		    the aes-256 psk is the md5sum of the whole executable
	this is also useful to protect against NOP attacks to the anti-debug
	features in the binary.
	This doubles also as anti-tamper measure.
	*/
	obPassword := obMD5.Sum([]byte(obKey))
	// OB_CHECK
	obCipherBlock, _ := obAES.NewCipher(obPassword[:])

	// OB_CHECK
	obGCM, _ := obCipher.NewGCM(obCipherBlock)

	// OB_CHECK
	obSizeNonce := obGCM.NonceSize()

	// OB_CHECK
	// decrypt!!!
	obNonce, obCiphertext := obCiphertext[:obSizeNonce], obCiphertext[obSizeNonce:]
	obCompressedPlaintext, _ := obGCM.Open(nil, obNonce, obCiphertext, nil)

	// OB_CHECK
	// the payload was compressed!
	obBufferPlaintext := obBytes.NewReader(obCompressedPlaintext)
	// OB_CHECK
	obZlibReader, err := obZlib.NewReader(obBufferPlaintext)
	if err != nil {
		println(err)
	}
	// OB_CHECK
	obPlaintext, _ := obUtilio.ReadAll(obZlibReader)
	obZlibReader.Close()
	// OB_CHECK
	// payload was in b64
	obPayload, _ := obBase64.StdEncoding.DecodeString(string(obPlaintext))

	// OB_CHECK
	obFDName := ``
	obFileDescriptor, _, _ := obSyscall.Syscall(obSysMEMFDCreate,
		uintptr(obUnsafe.Pointer(&obFDName)),
		uintptr(obCloexec|obAllowSealing), 0)

	// OB_CHECK
	// write payload to FD
	obSyscall.Write(int(obFileDescriptor), obPayload)
	// OB_CHECK
	// make it immutable
	obSyscall.Syscall(obSysFCNTL,
		obFileDescriptor,
		uintptr(1024+9),
		uintptr(obSealAll))

	// OB_CHECK
	obFDPath := `/proc/` +
		obStrconv.Itoa(obOS.Getpid()) +
		`/fd/` +
		obStrconv.Itoa(int(obFileDescriptor))
	// OB_CHECK
	obCommand := obExec.Command(obFDPath)
	// OB_CHECK
	obCommand.Args = obOS.Args
	// OB_CHECK
	obStdoutIn, _ := obCommand.StdoutPipe()
	obStderrIn, _ := obCommand.StderrPipe()
	// OB_CHECK
	var obStdoutBuf, obStderrBuf obBytes.Buffer
	// OB_CHECK
	stdout := obIO.MultiWriter(obOS.Stdout, &obStdoutBuf)
	stderr := obIO.MultiWriter(obOS.Stderr, &obStderrBuf)
	// OB_CHECK
	obCommand.Start()
	// async fetch stdout
	go func() {
		// OB_CHECK
		obIO.Copy(stdout, obStdoutIn)
	}()
	// async fetch stderr
	go func() {
		// OB_CHECK
		obIO.Copy(stderr, obStderrIn)
	}()
	// OB_CHECK
	obCommand.Wait()
}

func main() {
	go obPtraceDetect()
	if obDependencyCheck() || obPtraceNearHeap() || obEnvArgsDetect() ||
		obParentTracerDetect() || obParentCmdLineDetect() ||
		obEnvDetect() || obEnvParentDetect() ||
		obLdPreloadDetect() || obParentDetect() {
		println(`https://shorturl.at/crzEZ`)
		obOS.Exit(127)
	} else {
		obProceede()
	}
}
