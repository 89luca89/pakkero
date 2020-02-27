//go:binary-only-package
package main

/*
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>

// attach to PTRACE, register if successful
// attach A G A I N , register if unsuccessful
// this protects against custom ptrace (always returning 0)
// against NOP attacks and LD_PRELOAD attacks
int ptrace_detect () {
	int offset = 0;

	if (ptrace(PTRACE_TRACEME, 0, 1, 0) == 0){
		offset = 2;
	}
	if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1){
		offset = offset * 3;
	}

	if (offset == 2 * 3){
		return 0;
	} else {
		return -1;
	}
}

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
	obIO "io"
	obUtilio "io/ioutil"
	obOS "os"
	obExec "os/exec"
	obStrconv "strconv"
	obStrings "strings"
	obSyscall "syscall"
	obUnsafe "unsafe"
)

// check_block_start
func obPtraceDetect() {
	if C.ptrace_detect() < 0 {
		println(`https://shorturl.at/crzEZ`)
		obOS.Exit(127)
	}
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
		obOS.Setenv(`LD_PRELOAD`, `/stat`)
		obLineLdPreload, _ := obOS.LookupEnv(`LD_PRELOAD`)
		if obLineLdPreload == `/stat` {
			obOS.Unsetenv(`LD_PRELOAD`)
			return false
		}
		return true
	}
	return false
}

// check_block_end

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
	// de caeserize
	for obIndex := range obCiphertext {
		obCiphertext[obIndex] = obByteReverse(obCiphertext[obIndex])
	}

	// OB_CHECK
	//
	//		    the aes-256 psk is the md5sum of the whole executable
	//		 	        this is also useful to protect against NOP attacks to the anti-debug
	//		 	        features in the binary.
	//		 	        This doubles also as anti-tamper measure.
	//
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
	obFileDescriptor, _, _ := obSyscall.Syscall(319, uintptr(obUnsafe.Pointer(&obFDName)),
		uintptr(0x0001), 0)
	obSyscall.Write(int(obFileDescriptor), obPayload)

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
	go func() {
		// OB_CHECK
		obIO.Copy(stdout, obStdoutIn)
	}()
	go func() {
		// OB_CHECK
		obIO.Copy(stderr, obStderrIn)
	}()
	// OB_CHECK
	obCommand.Wait()
}

func main() {
	go obPtraceDetect()
	if obPtraceNearHeap() || obEnvArgsDetect() ||
		obParentTracerDetect() || obParentCmdLineDetect() ||
		obEnvDetect() || obEnvParentDetect() ||
		obLdPreloadDetect() || obParentDetect() {
		println(`https://shorturl.at/crzEZ`)
	} else {
		obProceede()
	}
}
