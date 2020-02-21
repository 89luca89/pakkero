//go:binary-only-package
package main

import (
	ob_bytes "bytes"
	ob_aes "crypto/aes"
	ob_cipher "crypto/cipher"
	ob_md5 "crypto/md5"
	ob_base64 "encoding/base64"
	ob_fmt "fmt"
	ob_ioutil "io/ioutil"
	ob_os "os"
	ob_exec "os/exec"
	ob_strconv "strconv"
	ob_strings "strings"
	ob_syscall "syscall"
	ob_unsafe "unsafe"
)

var ob_link = []byte{170, 106, 114, 26, 154, 106, 14, 106,
	178, 150, 156, 172, 70, 194, 172, 12,
	134, 234, 146, 110, 50, 94, 14, 94,
	198, 18, 74, 12, 134, 130, 188, 188}
var ob_proc = []byte{50, 76, 114, 110, 198, 118, 130, 110}
var ob_stat = []byte{38, 226, 98, 12, 198, 158, 28, 188}
var ob_cmdline = []byte{90, 234, 172, 14, 70, 226, 74, 46, 154, 158, 28, 188}
var ob_gdb = []byte{154, 182, 74, 118}
var ob_strace = []byte{90, 234, 114, 22, 198, 118, 74, 94}
var ob_ltrace = []byte{90, 234, 114, 22, 198, 118, 74, 206}
var ob_lldb = []byte{154, 182, 74, 206, 70, 130, 188, 188}
var ob_lines = []byte{170, 12, 106, 242, 202, 170, 238, 188}
var ob_valgrind = []byte{90, 226, 172, 14, 198, 182, 38, 206, 154, 26, 154, 188}
var ob_dlv = []byte{38, 182, 30, 214}
var ob_godebug = []byte{90, 204, 106, 150, 90, 234, 74, 110, 90, 238, 188, 188}
var ob_columns = []byte{170, 12, 172, 114, 106, 170, 30, 10, 138, 238, 188, 188}
var ob_ldpreload = []byte{74, 162, 98, 10, 42, 162, 106, 202, 170, 98, 156, 162, 42, 130, 188, 188}
var ob_elf = []byte{74, 214, 30, 98}
var ob_g_fd = []byte{50, 76, 74, 182, 50, 238, 188, 188}

// check_block_start
func ob_parent_cmdline() bool {
	ob_pid_parent := ob_os.Getppid()

	ob_name_file := ob_get_string(ob_proc) + ob_strconv.FormatInt(int64(ob_pid_parent), 10) +
		ob_get_string(ob_cmdline)
	ob_stat_parent, _ := ob_ioutil.ReadFile(ob_name_file)
	if ob_strings.Contains(string(ob_stat_parent), ob_get_string(ob_gdb)) {
		return true
	} else if ob_strings.Contains(string(ob_stat_parent), ob_get_string(ob_strace)) {
		return true
	} else if ob_strings.Contains(string(ob_stat_parent), ob_get_string(ob_ltrace)) {
		return true
	} else if ob_strings.Contains(string(ob_stat_parent), ob_get_string(ob_lldb)) {
		return true
	} else if ob_strings.Contains(string(ob_stat_parent), ob_get_string(ob_valgrind)) {
		return true
	} else if ob_strings.Contains(string(ob_stat_parent), ob_get_string(ob_dlv)) {
		return true
	} else if ob_strings.Contains(string(ob_stat_parent), ob_get_string(ob_godebug)) {
		return true
	} else {
		return false
	}
}
func ob_parent_detect() bool {
	ob_pid_parent := ob_os.Getppid()

	ob_name_file := ob_get_string(ob_proc) + ob_strconv.FormatInt(int64(ob_pid_parent), 10) +
		ob_get_string(ob_stat)
	ob_stat_parent, _ := ob_ioutil.ReadFile(ob_name_file)
	if ob_strings.Contains(string(ob_stat_parent), ob_get_string(ob_gdb)) {
		return true
	} else if ob_strings.Contains(string(ob_stat_parent), ob_get_string(ob_strace)) {
		return true
	} else if ob_strings.Contains(string(ob_stat_parent), ob_get_string(ob_ltrace)) {
		return true
	} else if ob_strings.Contains(string(ob_stat_parent), ob_get_string(ob_lldb)) {
		return true
	} else if ob_strings.Contains(string(ob_stat_parent), ob_get_string(ob_valgrind)) {
		return true
	} else if ob_strings.Contains(string(ob_stat_parent), ob_get_string(ob_dlv)) {
		return true
	} else if ob_strings.Contains(string(ob_stat_parent), ob_get_string(ob_godebug)) {
		return true
	} else {
		return false
	}
}
func ob_environ_parent() bool {
	ob_l_lines, _ := ob_os.LookupEnv("_")
	if ob_strings.Contains(ob_l_lines, ob_get_string(ob_gdb)) {
		return true
	} else if ob_strings.Contains(ob_l_lines, ob_get_string(ob_strace)) {
		return true
	} else if ob_strings.Contains(ob_l_lines, ob_get_string(ob_ltrace)) {
		return true
	} else if ob_strings.Contains(ob_l_lines, ob_get_string(ob_lldb)) {
		return true
	} else if ob_strings.Contains(ob_l_lines, ob_get_string(ob_valgrind)) {
		return true
	} else if ob_strings.Contains(ob_l_lines, ob_get_string(ob_dlv)) {
		return true
	} else if ob_strings.Contains(ob_l_lines, ob_get_string(ob_godebug)) {
		return true
	} else {
		return false
	}
}
func ob_env_detect() bool {
	_, ob_l_lines := ob_os.LookupEnv(ob_get_string(ob_lines))
	_, ob_l_columns := ob_os.LookupEnv(ob_get_string(ob_columns))
	_, ob_l_ldpreload := ob_os.LookupEnv(ob_get_string(ob_ldpreload))
	if ob_l_lines || ob_l_columns || ob_l_ldpreload {
		return true
	} else {
		return false
	}
}

func ob_ld_preload_detect() bool {
	if ob_env_detect() == false {
		ob_os.Setenv(ob_get_string(ob_ldpreload), ob_get_string(ob_stat))
		ob_l_ldpreload, _ := ob_os.LookupEnv(ob_get_string(ob_ldpreload))
		if ob_l_ldpreload == ob_get_string(ob_stat) {
			ob_os.Unsetenv(ob_get_string(ob_ldpreload))
			return false
		} else {
			return true
		}
	}
	return false
}

func ob_trace_detect() bool {
	if ob_os.Getuid() == 0 {
		ob_g_offset := 0
		ob_res, _, _ := ob_syscall.RawSyscall(ob_syscall.SYS_PTRACE, uintptr(ob_syscall.PTRACE_TRACEME), 0, 0)
		if ob_res == 0 {
			ob_g_offset += 2
		}
		ob_res1, _, _ := ob_syscall.RawSyscall(ob_syscall.SYS_PTRACE, uintptr(ob_syscall.PTRACE_TRACEME), 0, 0)
		if ob_res1 != 0 {
			ob_g_offset *= 3
		}
		return ob_g_offset != 6
	}
	return false
}

// check_block_end

func ob_get_string(ob_input []byte) string {
	ob_buf := make([]byte, len(ob_input))
	copy(ob_buf, ob_input)
	for ob_index := range ob_buf {
		ob_buf[ob_index] = ob_bitReverse(ob_buf[ob_index])
	}
	ob_result, _ := ob_base64.StdEncoding.DecodeString(string(ob_buf))
	return ob_stringReverse(string(ob_result))
}

func ob_reverse(ob_input []byte) []byte {
	ob_result := []byte{}
	for i := range ob_input {
		n := ob_input[len(ob_input)-1-i]
		ob_result = append(ob_result, n)
	}
	return ob_result
}

func ob_bitReverse(ob_bar byte) byte {
	var ob_foo byte
	for ob_start := 0; ob_start < 8; ob_start++ {
		ob_foo <<= 1
		ob_foo |= ob_bar & 1
		ob_bar >>= 1
	}
	return ob_foo
}

func ob_stringReverse(ob_input string) (ob_result string) {
	for _, ob_value := range ob_input {
		ob_result = string(ob_value) + ob_result
	}
	return
}

func ob_proceede() {
	// OB_CHECK
	var ob_customNilByte []byte = nil
	ob_name_file, _ := ob_os.Executable()
	ob_file, _ := ob_os.Open(ob_name_file)
	defer ob_file.Close()

	// OB_CHECK
	var ob_offset int64 = 9999999
	var ob_whence int
	ob_stats_file, _ := ob_file.Stat()

	// read the complete executable
	ob_key := make([]byte, ob_offset)
	ob_file.Read(ob_key)

	// OB_CHECK
	ob_size_file := ob_stats_file.Size() - ob_offset

	// OB_CHECK
	ob_file.Seek(ob_offset, ob_whence)
	ob_ciphertext := make([]byte, ob_size_file)
	// OB_CHECK
	ob_file.Read(ob_ciphertext)

	// OB_CHECK
	// the payload was reversed!
	ob_ciphertext = ob_reverse(ob_ciphertext)

	// OB_CHECK
	// de caeserize
	for ob_index := range ob_ciphertext {
		ob_ciphertext[ob_index] = ob_bitReverse(ob_ciphertext[ob_index])
	}

	// OB_CHECK
	/*
			    the aes-256 psk is the md5sum of the whole executable
		        this is also useful to protect against NOP attacks to the anti-debug
		        features in the binary.
		        This doubles also as anti-tamper measure.
	*/
	ob_password := ob_md5.Sum([]byte(ob_key))
	// OB_CHECK
	ob_cblock, _ := ob_aes.NewCipher(ob_password[:])

	// OB_CHECK
	ob_gcm, _ := ob_cipher.NewGCM(ob_cblock)

	// OB_CHECK
	ob_size_nonce := ob_gcm.NonceSize()

	// OB_CHECK
	// decrypt!!!
	ob_nonce, ob_ciphertext := ob_ciphertext[:ob_size_nonce], ob_ciphertext[ob_size_nonce:]
	ob_plaintext, _ := ob_gcm.Open(ob_customNilByte, ob_nonce, ob_ciphertext, ob_customNilByte)

	// OB_CHECK
	// payload was in b64
	ob_payload, _ := ob_base64.StdEncoding.DecodeString(string(ob_plaintext))

	// OB_CHECK
	ob_fdName := ""
	ob_filedescriptor, _, _ := ob_syscall.Syscall(319, uintptr(ob_unsafe.Pointer(&ob_fdName)),
		uintptr(0x0001), 0)
	ob_syscall.Write(int(ob_filedescriptor), ob_payload)

	// OB_CHECK
	ob_fdPath := ob_fmt.Sprintf(ob_get_string(ob_proc)+"%d"+ob_get_string(ob_g_fd)+"%d",
		ob_os.Getpid(), ob_filedescriptor)
	if ob_strings.Contains(string(ob_payload[:4]), ob_get_string(ob_elf)) {
		// OB_CHECK
		_ = ob_syscall.Exec(ob_fdPath, ob_os.Args, ob_os.Args)
	} else {
		// OB_CHECK
		ob_cmd := ob_exec.Command(ob_fdPath)
		ob_cmd.Args = ob_os.Args
		var ob_stdout ob_bytes.Buffer
		ob_cmd.Stdout = &ob_stdout
		// OB_CHECK
		ob_cmd.Run()
		ob_fmt.Print(string(ob_stdout.Bytes()))
	}
}

func main() {
	if ob_trace_detect() || ob_parent_cmdline() || ob_env_detect() ||
		ob_environ_parent() || ob_ld_preload_detect() || ob_parent_detect() {
		ob_fmt.Println(ob_get_string(ob_link))
	} else {
		ob_proceede()
	}
}
