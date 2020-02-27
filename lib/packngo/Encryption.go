/*
Package packngo will pack, compress and encrypt any type of executable.
Encryption library
*/
package packngo

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"io"
	"io/ioutil"
)

/*
EncryptAESReversed Wrapper around AESGCM encryption

this will not only encrypt the payload but:
- generate a password using the randomized UPX Binary's md5sum
- cipher the payload with AESGCM using the generated password
- swap endianess on all the encrypted bytes
- reverse the complete payload
*/
func EncryptAESReversed(plaintext []byte, outfile string) (string, error) {
	// generate a password using the randomized UPX Binary's md5sum
	/*
			    the aes-256 psk is the md5sum of the whole executable
		        this is also useful to protect against NOP attacks to the anti-debug
		        features in the binary.
		        This doubles also as anti-tamper measure.
	*/
	b, err := ioutil.ReadFile(outfile)
	if err != nil {
		return "", err
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
		bCiphertext[i] = ReverseByte(bCiphertext[i])
	}

	ciphertext := string(bCiphertext)

	// reverse the complete payload
	ciphertext = string(ReverseByteArray([]byte(ciphertext)))
	return ciphertext, nil
}
