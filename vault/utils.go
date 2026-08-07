package vault

import (
	"crypto/rand"
)

const base32HexCharset = "0123456789ABCDEFGHIJKLMNOPQRSTUV"

func GenerateRandomPassword(charsets string, len int) string {
	return ""
}

func GenerateRandomMemorablePassword(words []string, len int) string {
	return ""
}

func GenerateSecureSalt(len uint8) []byte {
	salt := make([]byte, len)
	// ignored because read.Read will never return an error
	_, _ = rand.Read(salt)
	return salt
}

func GenerateSecretKey() []byte {
	src := make([]byte, 32)
	dst := make([]byte, 32)
	// ignored because read.Read will never return an error
	_, _ = rand.Read(src)
	for i, v := range src {
		// transform byte from range 0 to 255 to 0 to 31 with right shift operation
		dst[i] = base32HexCharset[v>>3]
	}
	// add secret key version
	dst[0] = 'A'
	dst[1] = '1'
	// add hyphen every 6 characters
	for i := 2; i < 32; i += 6 {
		dst[i] = '-'
	}
	return dst
}
