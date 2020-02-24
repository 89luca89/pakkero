package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
)

/*
Wrapper around AESGCM encryption

this will not only encrypt the payload but:
- generate a password using the randomized UPX Binary's md5sum
- cipher the payload with AESGCM using the generated password
- swap endianess on all the encrypted bytes
- reverse the complete payload
*/
func encryptAESReversed(plaintext []byte, outfile string) string {
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
		println(err)
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		println(err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		println(err)
	}

	// cipher the payload with AESGCM using the generated password
	bCiphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	// swap endianess on all the encrypted bytes
	for i := range bCiphertext {
		bCiphertext[i] = reverseByte(bCiphertext[i])
	}

	ciphertext := string(bCiphertext)

	// reverse the complete payload
	ciphertext = string(reverseByteArray([]byte(ciphertext)))
	return ciphertext
}
