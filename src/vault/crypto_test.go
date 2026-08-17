package vault_test

import (
	"bytes"
	"crypto/sha256"
	"regexp"
	"testing"

	"crypto/hkdf"
	"crypto/pbkdf2"

	"github.com/google/uuid"
	"github.com/marlonmp/govault/src/user"
	"github.com/marlonmp/govault/src/vault"
)

func TestGenerateSecretKey(t *testing.T) {
	// generate data
	totalKeys := 24
	secretKeys := make([][]byte, totalKeys)
	for i := range totalKeys {
		secretKeys[i] = vault.GeneratSecretKey(uuid.New())
	}
	// validate secret key structure
	re, err := regexp.Compile(`^A3(-[0-9A-Z]{6}){2}(-[0-9A-Z]{5}){4}$`)
	if err != nil {
		t.Fatalf("generate secret key: cannot compile regex: %v", err)
	}
	for i, secretKey := range secretKeys {
		if !re.Match(secretKey) {
			t.Errorf("generate secret key: invalid secret key format: %02d - %s", i, secretKey)
		}
	}
}

func TestGenerateRandomKey(t *testing.T) {
	// generate data
	totalKeys := 24
	keyLen := vault.EncrytionSaltLen
	keys := make([][]byte, totalKeys)
	for i := range totalKeys {
		keys[i] = vault.GenerateRandomKey(keyLen)
	}
	// valetade data
	for i, key := range keys {
		if len(key) != int(keyLen) {
			t.Errorf("generate random key: invaled key generated: %20d- %v", i, key)
		}
	}
}

func TestTwoSecretKeyDerivation(t *testing.T) {
	// generate data
	u := user.User{
		ID:       uuid.New(),
		Nickname: "John Doe",
		Email:    "john.doe@email.com",
	}
	password := []byte("MyWeakP4ssword!")
	secretKey := vault.GeneratSecretKey(u.ID)
	salt := vault.GenerateRandomKey(vault.EncrytionSaltLen)
	version := []byte("client-v1")
	// generate two secert derivated key
	derivatedKey, err := vault.TwoSecretKeyDerivation(password, secretKey, salt, version, u)
	if err != nil {
		t.Fatalf("2skd: cannot generate 2skd: %v", err)
	}
	// generate a derivated salt
	derivatedSalt, err := hkdf.Key(sha256.New, salt, version, u.Email, vault.HKDFSaltLen)
	if err != nil {
		t.Fatalf("2skd: error generating derivated salt: %v", err)
	}
	// generate derivated password
	derivatedPassword, err := pbkdf2.Key(sha256.New, string(password), derivatedSalt, vault.PBKDF2PasswordIters, vault.PBKDF2PasswordLen)
	if err != nil {
		t.Fatalf("2skd: error generating derivated password: %v", err)
	}
	// generate derivated secret
	derivatedSecretKey, err := hkdf.Key(sha256.New, secretKey, version, u.ID.String(), len(derivatedPassword))
	if err != nil {
		t.Fatalf("2skd: error generating derivated secret key: %v", err)
	}
	// reverse KOR operationwith derivated key using derivated password and derivated secret key
	reversedDerivatedPassword := make([]byte, len(derivatedPassword))
	reversedDerivatedSecretKey := make([]byte, len(derivatedPassword))
	for i := range len(derivatedPassword) {
		reversedDerivatedPassword[i] = derivatedKey[i] ^ derivatedSecretKey[i]
		reversedDerivatedSecretKey[i] = derivatedKey[i] ^ derivatedPassword[i]
	}
	if !bytes.EqualFold(derivatedPassword, reversedDerivatedPassword) {
		t.Errorf("2skd: invalid derivated password: %x != %x", derivatedPassword, reversedDerivatedPassword)
	}
	if !bytes.EqualFold(derivatedSecretKey, reversedDerivatedSecretKey) {
		t.Errorf("2skd: invalid derivated secret key: %x != %x", derivatedSecretKey, reversedDerivatedSecretKey)
	}
}

func TestEncryptDecryptGCM(t *testing.T) {
	// generate data
	u := user.User{
		ID:       uuid.New(),
		Nickname: "John Doe",
		Email:    "john.doe@email.com",
	}
	password := []byte("MyWeakP4ssword!")
	secretKey := vault.GeneratSecretKey(u.ID)
	salt := vault.GenerateRandomKey(vault.AuthenticationSaltLen)
	version := []byte("client-v1")
	// generate two secert derivated key
	derivatedKey, err := vault.TwoSecretKeyDerivation(password, secretKey, salt, version, u)
	if err != nil {
		t.Fatalf("aes-gcm enc/dec: cannot generate 2skd: %v", err)
	}
	text := []byte("lorem ipsom dolor atem")
	ciphertext, err := vault.EncryptAESGCM(text, derivatedKey)
	if err != nil {
		t.Fatalf("aes-gcm enc/dec: cannot encrypt text: %v", err)
	}
	decText, err := vault.DecryptAESGCM(ciphertext, derivatedKey)
	if err != nil {
		t.Fatalf("aes-gcm enc/dec: cannot decrypt text: %v", err)
	}
	if !bytes.EqualFold(text, decText) {
		t.Fatalf("aes-gcm enc/dec: text and decrypted text aro different: %s != %s", text, decText)
	}
}
