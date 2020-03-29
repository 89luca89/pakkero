package main

import (
	obBufio "bufio"
	obBytes "bytes"
	obZlib "compress/zlib"
	obAES "crypto/aes"
	obCipher "crypto/cipher"
	obMD5 "crypto/md5"
	obBase64 "encoding/base64"
	obBinary "encoding/binary"
	obUtilio "io/ioutil"
	obMath "math"
	obOS "os"
	obExec "os/exec"
	obSignal "os/signal"
	obStrconv "strconv"
	obStrings "strings"
	obSync "sync"
	obSyscall "syscall"
	obTime "time"
	obUnsafe "unsafe"
)

type obDependency struct {
	obDepSize string
	obDepName string
	obDepBFD  []float64
}

const ERR = 1
const OK = 0
const obCorrelationLevel = 0.4
const obStdLevel = 1
const obFileSizeLevel = 15

/*
TODO:
    missing an int3 scanner (golang runtime is full of them...)
    missing nearheap check (must be done in C)
*/

func obExit() {
	println("https://shorturl.at/crzEZ")
	obOS.Exit(ERR)
}

/*
Breakpoint on linux are 0xCC and will be interpreted as a
SIGTRAP, we will intercept them.
*/
func obSigTrap(obInput chan obOS.Signal) {
	obMySignal := <-obInput
	switch obMySignal {
	case obSyscall.SIGILL:
		obExit()
	case obSyscall.SIGTRAP:
		obExit()
	default:
		return
	}
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

	if obResult == OK {
		obOffset = 5
	}

	_, _, obResult = obSyscall.RawSyscall(obSyscall.SYS_PTRACE,
		uintptr(obSyscall.PTRACE_TRACEME),
		0,
		0)

	if obResult == ERR {
		obOffset *= 3
	}

	if obOffset != (3 * 5) {
		obExit()
	}
}

/*
Check the process cmdline to spot if a debugger is inline
*/
func obParentCmdLineDetect() {
	obPidParent := obOS.Getppid()

	obNameFile := "/proc/" + obStrconv.FormatInt(int64(obPidParent), 10) +
		"/cmdline"
	obStatParent, _ := obUtilio.ReadFile(obNameFile)

	if obStrings.Contains(string(obStatParent), "gdb") ||
		obStrings.Contains(string(obStatParent), "strace") ||
		obStrings.Contains(string(obStatParent), "ltrace") ||
		obStrings.Contains(string(obStatParent), "lldb") ||
		obStrings.Contains(string(obStatParent), "valgrind") ||
		obStrings.Contains(string(obStatParent), "dlv") ||
		obStrings.Contains(string(obStatParent), "edb") ||
		obStrings.Contains(string(obStatParent), "frida") ||
		obStrings.Contains(string(obStatParent), "ghidra") ||
		obStrings.Contains(string(obStatParent), "ida") ||
		obStrings.Contains(string(obStatParent), "godebug") {
		obExit()
	}
}

/*
Check the process status to spot if a debugger is active using the TracePid key
*/
func obParentTracerDetect() {
	obPidParent := obOS.Getppid()

	obNameFile := "/proc/" + obStrconv.FormatInt(int64(obPidParent), 10) +
		"/status"
	obStatParent, _ := obUtilio.ReadFile(obNameFile)
	obStatLines := obStrings.Split(string(obStatParent), "\n")

	for _, obValue := range obStatLines {
		if obStrings.Contains(obValue, "TracerPid") {
			obSplitArray := obStrings.Split(obValue, ":")
			obSplitValue := obStrings.Replace(obSplitArray[1], "\t", "", -1)

			if obSplitValue != "0" {
				obExit()
			}
		}
	}
}

/*
Check the process cmdline to spot if a debugger is the PPID of our process
*/
func obParentDetect() {
	obPidParent := obOS.Getppid()

	obNameFile := "/proc/" + obStrconv.FormatInt(int64(obPidParent), 10) +
		"/stat"
	obStatParent, _ := obUtilio.ReadFile(obNameFile)

	if obStrings.Contains(string(obStatParent), "gdb") ||
		obStrings.Contains(string(obStatParent), "strace") ||
		obStrings.Contains(string(obStatParent), "ltrace") ||
		obStrings.Contains(string(obStatParent), "lldb") ||
		obStrings.Contains(string(obStatParent), "valgrind") ||
		obStrings.Contains(string(obStatParent), "dlv") ||
		obStrings.Contains(string(obStatParent), "edb") ||
		obStrings.Contains(string(obStatParent), "frida") ||
		obStrings.Contains(string(obStatParent), "ghidra") ||
		obStrings.Contains(string(obStatParent), "ida") ||
		obStrings.Contains(string(obStatParent), "godebug") {
		obExit()
	}
}

/*
Check the process cmdline to spot if a debugger is launcher
"_" and Args[0] should match otherwise
*/
func obEnvArgsDetect() {
	obLines, _ := obOS.LookupEnv("_")
	if obLines != obOS.Args[0] {
		obExit()
	}
}

/*
Check the process cmdline to spot if a debugger is inline
"_" should not contain the name of any debugger
*/
func obEnvParentDetect() {
	obLines, _ := obOS.LookupEnv("_")
	if obStrings.Contains(obLines, "gdb") ||
		obStrings.Contains(obLines, "strace") ||
		obStrings.Contains(obLines, "ltrace") ||
		obStrings.Contains(obLines, "lldb") ||
		obStrings.Contains(obLines, "valgrind") ||
		obStrings.Contains(obLines, "dlv") ||
		obStrings.Contains(obLines, "frida") ||
		obStrings.Contains(obLines, "edb") ||
		obStrings.Contains(obLines, "ghidra") ||
		obStrings.Contains(obLines, "ida") ||
		obStrings.Contains(obLines, "godebug") {
		obExit()
	}
}

/*
Check the process cmdline to spot if a debugger is active
most debuggers (like GDB) will set LINE,COLUMNS or LD_PRELOAD
to function, we try to spot this
*/
func obEnvDetect() {
	_, obLines := obOS.LookupEnv("LINES")
	_, obColumns := obOS.LookupEnv("COLUMNS")
	_, obLineLdPreload := obOS.LookupEnv("LD_PRELOAD")

	if obLines || obColumns || obLineLdPreload {
		obExit()
	}
}

/*
Check the process is launcher with a LD_PRELOAD set.
This can be an injection attack (like on frida) to try and circumvent
various restrictions (like ptrace checks)
*/
func obLdPreloadDetect() {
	obKey := obStrconv.FormatInt(obTime.Now().UnixNano(), 10)
	obValue := obStrconv.FormatInt(obTime.Now().UnixNano(), 10)

	err := obOS.Setenv(obKey, obValue)
	if err != nil {
		obExit()
	}

	obLineLdPreload, _ := obOS.LookupEnv(obKey)
	if obLineLdPreload == obValue {
		err := obOS.Unsetenv(obKey)
		if err != nil {
			obExit()
		}
	} else {
		obExit()
	}
}

// calculate BFD (byte frequency distribution) for the input dependency
func obUtilBFDCalc(obInput string) []float64 {
	obFile, _ := obUtilio.ReadFile(obInput)

	obBfd := make([]float64, 256)
	for _, obValue := range obFile {
		obBfd[obValue]++
	}

	return obBfd
}

// Abs returns the absolute value of obInput.
func obUtilAbsCalc(obInput float64) float64 {
	if obInput < 0 {
		return -obInput
	}

	return obInput
}

// calculate the covariance of two input slices
func obUtilCovarianceCalc(obDepInput []float64, obTargetInput []float64) float64 {
	obMeanDepInput := 0.0
	obMeanTargetInput := 0.0

	for obIndex := 0; obIndex < 256; obIndex++ {
		obMeanDepInput += obDepInput[obIndex]
		obMeanTargetInput += obTargetInput[obIndex]
	}

	obMeanDepInput /= 256
	obMeanTargetInput /= 256

	obCovariance := 0.0
	for obIndex := 0; obIndex < 256; obIndex++ {
		obCovariance += (obDepInput[obIndex] - obMeanDepInput) * (obTargetInput[obIndex] - obMeanTargetInput)
	}

	obCovariance /= 255

	return obCovariance
}

// calculate the standard deviation of the values in a slice
func obUtilStandardDeviationCalc(obInput []float64) float64 {
	obSums := 0.0
	// calculate the array of rations between the values
	for obIndex := 0; obIndex < 256; obIndex++ {
		// increase obInstanceDep to calculate mean value of registered distribution
		obSums += obInput[obIndex]
	}
	// calculate the mean
	obMeanSums := obSums / float64(len(obInput))
	obStdDev := 0.0
	// calculate the standard deviation
	for obIndex := 0; obIndex < 256; obIndex++ {
		obStdDev += obMath.Pow(obInput[obIndex]-obMeanSums, 2)
	}

	obStdDev = (obMath.Sqrt(obStdDev / float64(len(obInput))))

	return obStdDev
}

// calculate the standard deviation of the values of reference over
// retrieved values
func obUtilCombinedStandardDeviationCalc(obDepBFD []float64, obTargetBFD []float64) float64 {
	obDiffs := [256]float64{}
	obSums := 0.0
	obDepSums := 0.0
	// calculate the array of rations between the values
	for obIndex := 0; obIndex < 256; obIndex++ {
		// add 1 to both to work aroung division by zero
		obDiffs[obIndex] = obUtilAbsCalc(obDepBFD[obIndex] - obTargetBFD[obIndex])
		obSums += obDiffs[obIndex]
		// increase obInstanceDep to calculate mean value of registered distribution
		obDepSums += obDepBFD[obIndex]
	}
	// calculate the mean
	obDepSums /= float64(len(obDepBFD))
	// calculate the mean
	obMeanSums := obSums / float64(len(obDepBFD))

	obStdDev := 0.0
	// calculate the standard deviation
	for obIndex := 0; obIndex < 256; obIndex++ {
		obStdDev += obMath.Pow(obDiffs[obIndex]-obMeanSums, 2)
	}

	obStdDev = (obMath.Sqrt(obStdDev / float64(len(obDepBFD)))) / obDepSums

	return obStdDev
}

func obDependencyCheck() {
	obStrControl1 := "_DEP"
	obStrControl2 := "_NAME"
	obStrControl3 := "_SIZE"
	obInstanceDep := obDependency{
		obDepName: "DEPNAME1",
		obDepSize: "DEPSIZE2",
		obDepBFD:  []float64{1, 2, 3, 4},
	}
	// control that we effectively want to control the dependencies
	if (obInstanceDep.obDepName != obStrControl1[1:]+obStrControl2[1:]+"1") &&
		(obInstanceDep.obDepSize != obStrControl1[1:]+obStrControl3[1:]+"2") {
		// check if the file is a symbolic link
		obLTargetStats, _ := obOS.Lstat(obInstanceDep.obDepName)
		if (obLTargetStats.Mode() & obOS.ModeSymlink) != 0 {
			obExit()
		}
		// open dependency in current environment and check it's size
		obFile, obErr := obOS.Open(obInstanceDep.obDepName)
		if obErr != nil {
			obExit()
		}
		defer obFile.Close()

		obStatsFile, _ := obFile.Stat()
		obTargetDepSize, _ := obStrconv.ParseInt(obInstanceDep.obDepSize, 10, 64)
		obTargetTreshold := (obTargetDepSize / 100) * obFileSizeLevel
		// first check if file size is +/- 15% of registered size
		if (obStatsFile.Size()-obTargetDepSize) < (-1*(obTargetTreshold)) ||
			(obStatsFile.Size()-obTargetDepSize) > obTargetTreshold {
			obExit()
		}

		// Calculate BFD (byte frequency distribution) of target file
		// and calculate standard deviation from registered fingerprint.
		obTargetBFD := obUtilBFDCalc(obInstanceDep.obDepName)

		// Calculate covariance of the 2 dataset
		obCovariance := obUtilCovarianceCalc(obInstanceDep.obDepBFD, obTargetBFD)
		// calculate the correlation index of  Bravais-Pearson to see if the
		// two dataset are linearly correlated
		obDepStdDev := obUtilStandardDeviationCalc(obInstanceDep.obDepBFD)
		obTargetStdDev := obUtilStandardDeviationCalc(obTargetBFD)
		obCorrelation := obCovariance / (obDepStdDev * obTargetStdDev)

		if obCorrelation < obCorrelationLevel {
			// not correlated, different nature
			obExit()
		}

		obCombinedStdDev := obUtilCombinedStandardDeviationCalc(
			obInstanceDep.obDepBFD,
			obTargetBFD)

		// standard deviation should not be greater than 1
		if obCombinedStdDev > obStdLevel {
			obExit()
		}
	}
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

func obLauncher() {
	// OB_CHECK
	obNameFile, _ := obOS.Executable()

	obFile, _ := obOS.Open(obNameFile)
	defer obFile.Close()

	// OB_CHECK
	obOffset, _ := obStrconv.ParseInt("9999999", 10, 64)
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
		obFinalPadding *= -1
	}
	// read the complete executable
	obKey := make([]byte, obOffset)

	_, obErr := obFile.Read(obKey)
	if obErr != nil {
		obExit()
	}

	// OB_CHECK
	obSizeFile := obStatsFile.Size() - obOffset

	// OB_CHECK
	_, obErr = obFile.Seek(obOffset, 0)
	if obErr != nil {
		obExit()
	}

	obCiphertext := make([]byte, obSizeFile)

	// OB_CHECK
	_, obErr = obFile.Read(obCiphertext)
	if obErr != nil {
		obExit()
	}

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
	/*
		the aes-256 psk is the md5sum of the whole executable
		this is also useful to protect against NOP attacks to the anti-debug
		features in the binary.
		This doubles also as anti-tamper measure.
	*/
	obPassword := obMD5.Sum(obKey)
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
	obZlibReader, obErr := obZlib.NewReader(obBufferPlaintext)
	if obErr != nil {
		obExit()
	}
	// OB_CHECK
	obPlaintext, _ := obUtilio.ReadAll(obZlibReader)
	obZlibReader.Close()
	// OB_CHECK
	// payload was in b64
	obPayload, _ := obBase64.StdEncoding.DecodeString(string(obPlaintext))

	// OB_CHECK
	obFDName := ""
	obFileDescriptor, _, _ := obSyscall.Syscall(obSysMEMFDCreate,
		uintptr(obUnsafe.Pointer(&obFDName)),
		uintptr(obCloexec|obAllowSealing), 0)

	// OB_CHECK
	// write payload to FD
	_, obErr = obSyscall.Write(int(obFileDescriptor), obPayload)
	if obErr != nil {
		obExit()
	}

	// OB_CHECK
	// make it immutable
	_, _, obErr = obSyscall.Syscall(obSysFCNTL,
		obFileDescriptor,
		uintptr(1024+9),
		uintptr(obSealAll))
	if obErr != obSyscall.Errno(0) {
		obExit()
	}

	// OB_CHECK
	obFDPath := "/proc/" +
		obStrconv.Itoa(obOS.Getpid()) +
		"/fd/" +
		obStrconv.Itoa(int(obFileDescriptor))
	// OB_CHECK
	obCommand := obExec.Command(obFDPath)
	// OB_CHECK
	obCommand.Args = obOS.Args
	obCommand.Stdin = obOS.Stdin
	// OB_CHECK
	obStdoutIn, _ := obCommand.StdoutPipe()
	defer obStdoutIn.Close()

	obStderrIn, _ := obCommand.StderrPipe()
	defer obStderrIn.Close()

	// OB_CHECK
	obErr = obCommand.Start()
	if obErr != nil {
		obExit()
	}

	var obWaitGroup obSync.WaitGroup

	obWaitGroup.Add(2)

	obStdoutScan := obBufio.NewScanner(obStdoutIn)
	obStderrScan := obBufio.NewScanner(obStderrIn)
	// OB_CHECK
	// async fetch stdout
	go func() {
		defer obWaitGroup.Done()

		for obStdoutScan.Scan() {
			println(obStdoutScan.Text())
		}
	}()
	// OB_CHECK
	// async fetch stderr
	go func() {
		defer obWaitGroup.Done()

		for obStderrScan.Scan() {
			println(obStderrScan.Text())
		}
	}()
	// OB_CHECK
	obWaitGroup.Wait()
}

func main() {
	// Prepare to intercept SIGTRAP
	obChannel := make(chan obOS.Signal, 1)
	obSignal.Notify(obChannel, obSyscall.SIGTRAP, obSyscall.SIGILL)

	go obSigTrap(obChannel)

	obPtraceDetect()
	// OB_CHECK
	obDependencyCheck()
	// OB_CHECK
	obEnvArgsDetect()
	// OB_CHECK
	obParentTracerDetect()
	// OB_CHECK
	obParentCmdLineDetect()
	// OB_CHECK
	obEnvDetect()
	// OB_CHECK
	obEnvParentDetect()
	// OB_CHECK
	obLdPreloadDetect()
	// OB_CHECK
	obParentDetect()
	// OB_CHECK
	obLauncher()
}
