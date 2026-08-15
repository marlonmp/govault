package vault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"io"
	"math/big"
	"strings"

	"github.com/google/uuid"
	"github.com/marlonmp/govault/src/user"
	"golang.org/x/text/unicode/norm"
)

const (
	// version len + account id len + secret len + hypens len
	SecretKeyLen            = 2 + 6 + 26 + 6
	SecretKeyDefaultVersion = "A3"
	SecretKeyCharset        = "01234567890ABCDEFGHIJKLMNOPQRSTUVXYZ"

	AuthenticationSaltLen = 32
	EncrytionSaltLen      = 32

	PrivateKeyBits      = 2048
	VaultSecretKeyBytes = 32

	HKDFSaltLen         = 32
	PBKDF2PasswordIters = 650_000
	PBKDF2PasswordLen   = 16
)

var (
	CipherContentTooShort = errors.New("vault: gcm decrypt: cipher content too short")
)

// This function generates the user secret key
func GeneratSecretKey(accountID uuid.UUID) []byte {
	mem := make([]byte, 0, SecretKeyLen)
	buff := bytes.NewBuffer(mem)
	// append the secret key version
	buff.WriteString(SecretKeyDefaultVersion)
	buff.WriteByte('-')
	// append account ID
	accIDB36 := new(big.Int).
		// convert the uuid into a big int
		SetBytes(accountID[:]).
		// convert that number from base 10 into base 36
		Text(36)
	accIDB36 = accIDB36[:6]
	accIDB36 = strings.ToUpper(accIDB36)
	buff.WriteString(accIDB36)
	buff.WriteByte('-')
	// generate secret
	charsetOptions := big.NewInt(int64(len(SecretKeyCharset)))
	control := 1
	for i := 0; i < 26+4; i++ {
		// ensures the first group consists of 6 characters
		// and the remaining consisis of 5 characters
		if i == 5 {
			idx, _ := rand.Int(rand.Reader, charsetOptions)
			buff.WriteByte(SecretKeyCharset[idx.Int64()])
			buff.WriteByte('-')
			i++
			control--
			continue
		}
		// each 6 or 5 characters a hypen must be insert then
		if (i+control)%6 == 0 {
			buff.WriteByte('-')
			continue
		}
		idx, _ := rand.Int(rand.Reader, charsetOptions)
		buff.WriteByte(SecretKeyCharset[idx.Int64()])
	}
	return buff.Bytes()
}

// This function trim any leading and trailing spaces and apply NFKD normalization to the password.
func normalizePassword(password []byte) []byte {
	password = bytes.TrimSpace(password)
	return norm.NFKD.Bytes(password)
}

// This function generate a random key, this function is used to generate salts and valut secret keys
func GenerateRandomKey(size uint8) []byte {
	buff := make([]byte, size)
	_, _ = rand.Read(buff)
	return buff
}

// This function generates a derivated key with two given secrets.
// This is a strongest method designeb by 1Password to create a stronges key.
// This derived key is used to generate the Account Unlock Key (AUK) and the client secret used in SRP (SRP-x)
func TwoSecretKeyDerivation(password, secretKey, salt, version []byte, user user.User) ([]byte, error) {
	// trim and normalize password
	password = normalizePassword(password)
	// generate a derivated salt with HKDF SHA256
	derivatedSalt, err := hkdf.Key(sha256.New, salt, version, user.Email, HKDFSaltLen)
	if err != nil {
		return nil, err
	}
	// apply slow hash PBKDF2-HMAC-SHA256 to the password
	derivatedPassword, err := pbkdf2.Key(sha256.New, string(password), derivatedSalt, PBKDF2PasswordIters, PBKDF2PasswordLen)
	if err != nil {
		return nil, err
	}
	// generate a intermediate as the same len of the password key with the secret key
	derivatedSecretKey, err := hkdf.Key(sha256.New, secretKey, version, user.UUID.String(), len(derivatedPassword))
	if err != nil {
		return nil, err
	}
	// XOR the results from the password in PBKDF2 and the secret key in HKDF
	derivationKey := make([]byte, len(derivatedPassword))
	for i := range len(derivatedPassword) {
		derivationKey[i] = derivatedPassword[i] ^ derivatedSecretKey[i]
	}
	return derivationKey, nil
}

// This method is a wrapper of `rsa.GenerateKey()` providing a defaust bits value
func GeneratePrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, PrivateKeyBits)
}

// This functions encrypt an input with a key using AES-GCM
func EncryptAESGCM(src, key []byte) ([]byte, error) {
	// generate an AES cipher block with 256-bit
	block, err := aes.NewCipher(key)
	if err != nil {
		return make([]byte, 0), err
	}
	// wrap the block cipher with GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return make([]byte, 0), err
	}
	// generate a unique nonce slice
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return make([]byte, 0), err
	}
	// encrypt the content and append
	cipherContent := gcm.Seal(nonce, nonce, src, nil)
	return cipherContent, nil
}

// This function decrypts an input with a key using AES-GCM
func DecryptAESGCM(src, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil
	}
	nonceSize := gcm.NonceSize()
	if len(src) < nonceSize {
		return nil, CipherContentTooShort
	}
	nonce, cipherContent := src[:nonceSize], src[nonceSize:]
	return gcm.Open(nil, nonce, cipherContent, nil)
}
