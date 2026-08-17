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

func FuzzTwoSecretKeyDerivation(f *testing.F) {
	testcases := []struct {
		User     user.User
		Password []byte
		MustFail bool
	}{
		{
			User: user.User{
				Nickname: "Jhon Doe Smith",
				Email:    "jhon.doe.smith@email.com",
			},
			Password: []byte("@A!Realy&str0nG3st#P4ssWord!"),
		},
		{
			User: user.User{
				Nickname: "Acme INC.",
				Email:    "support@acme.ai",
			},
			Password: []byte("!Ia%Eua#ia!@3oEAuFg#1uaEiaei01"),
		},
		{
			User: user.User{
				Nickname: "Paul",
				Email:    "paul@gmail.com",
			},
			Password: []byte("P4ssword"),
		},
		{
			User: user.User{
				Nickname: "Margarita",
				Email:    "margaritak@outlook.com",
			},
			Password: []byte("!IaEua#ia!@3oEAu"),
		},
		{
			User: user.User{
				Nickname: "nick2",
				Email:    "nick2@yahoo.com",
			},
			Password: []byte("!Ia%Eua#ia!@3oEAuFg#1uaEiaei01!Ia%Eua#ia!@3oEAuFg#1uaEiaei01"),
		},
		{
			User: user.User{
				Nickname: "Margarita2",
				Email:    "margaritak2@outlook.com",
			},
			Password: []byte("!IaEua#ia!@3oEAu!IaEua#ia!@3oEAu"),
		},
		{
			User: user.User{
				Nickname: "Paul 2",
				Email:    "paul2@gmail.com",
			},
			Password: []byte("P4s"),
		},
		{
			User: user.User{
				Nickname: "Paul 2",
				Email:    "paul2@gmail.com",
			},
			Password: []byte(""),
		},
		{
			User: user.User{
				Nickname: "Paul 3",
				Email:    "paul2@gmail.com",
			},
			Password: []byte("P"),
		},
		{
			User: user.User{
				Nickname: "nick",
				Email:    "nick@yahoo.com",
			},
			Password: []byte("!IaEua#ia!@3oEAu"),
		},
		{
			User: user.User{
				Nickname: "nick3",
				Email:    "nick3@yahoo.com",
			},
			Password: []byte("!Ia%Eua#ia!@3oEAuFg#1uaEiaei01!Ia%Eua#ia!@3oEAuFg#1uaEiaei01!Ia%Eua#ia!@3oEAuFg#1uaEiaei01!Ia%Eua#ia!@3oEAuFg#1uaEiaei01"),
		},
	}
	// generate secret key, salt and version
	for _, tcase := range testcases {
		id := uuid.New()
		tcase.User.ID = id
		secretKey := vault.GeneratSecretKey(id)
		salt := vault.GenerateRandomKey(vault.EncrytionSaltLen)
		version := []byte("client-v1")
		derivatedKey, err := vault.TwoSecretKeyDerivation(tcase.Password, secretKey, salt, version, tcase.User)
		if err != nil {
			f.Errorf("2skd: cannot generate 2skd: %v", err)
		}
		f.Add(id.String(), tcase.User.Email, string(tcase.Password), version, salt, secretKey, derivatedKey)
	}
	f.Fuzz(func(t *testing.T, id, email, password string, version, salt, secretKey, derivatedKey []byte) {
		// generate a derivated salt
		derivatedSalt, err := hkdf.Key(sha256.New, salt, version, email, vault.HKDFSaltLen)
		if err != nil {
			t.Fatalf("2skd: error generating derivated salt: %v", err)
		}
		// generate derivated password
		derivatedPassword, err := pbkdf2.Key(sha256.New, password, derivatedSalt, vault.PBKDF2PasswordIters, vault.PBKDF2PasswordLen)
		if err != nil {
			t.Fatalf("2skd: error generating derivated password: %v", err)
		}
		// generate derivated secret
		derivatedSecretKey, err := hkdf.Key(sha256.New, secretKey, version, id, len(derivatedPassword))
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
	})
}

func FuzzEnrcyptDecryptGCM(f *testing.F) {
	testcases := []struct {
		User     user.User
		Password []byte
		Content  []byte
	}{
		{
			User: user.User{
				Nickname: "Jhon Doe Smith",
				Email:    "jhon.doe.smith@email.com",
			},
			Password: []byte("@A!Realy&str0nG3st#P4ssWord!"),
			Content:  []byte("lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."),
		},
		{
			User: user.User{
				Nickname: "Acme INC.",
				Email:    "support@acme.ai",
			},
			Password: []byte("!Ia%Eua#ia!@3oEAuFg#1uaEiaei01"),
			Content:  []byte("lorem ipsum dolor sit amet"),
		},
		{
			User: user.User{
				Nickname: "Paul",
				Email:    "paul@gmail.com",
			},
			Password: []byte("P4ssword"),
			Content:  []byte("lorem"),
		},
		{
			User: user.User{
				Nickname: "Margarita",
				Email:    "margaritak@outlook.com",
			},
			Password: []byte("!IaEua#ia!@3oEAu"),
			Content:  []byte("l"),
		},
		{
			User: user.User{
				Nickname: "nick2",
				Email:    "nick2@yahoo.com",
			},
			Password: []byte("!Ia%Eua#ia!@3oEAuFg#1uaEiaei01!Ia%Eua#ia!@3oEAuFg#1uaEiaei01"),
			Content:  []byte(""),
		},
		{
			User: user.User{
				Nickname: "Margarita2",
				Email:    "margaritak2@outlook.com",
			},
			Password: []byte("!IaEua#ia!@3oEAu!IaEua#ia!@3oEAu"),
			Content:  []byte("lorem ipsum dolor sit amet"),
		},
		{
			User: user.User{
				Nickname: "Paul 2",
				Email:    "paul2@gmail.com",
			},
			Password: []byte("P4s"),
			Content:  []byte("lorem ipsum dolor sit amet"),
		},
		{
			User: user.User{
				Nickname: "Paul 2",
				Email:    "paul2@gmail.com",
			},
			Password: []byte(""),
			Content:  []byte(""),
		},
		{
			User: user.User{
				Nickname: "Paul 3",
				Email:    "paul2@gmail.com",
			},
			Password: []byte("P"),
			Content:  []byte("amet"),
		},
		{
			User: user.User{
				Nickname: "nick",
				Email:    "nick@yahoo.com",
			},
			Password: []byte("!IaEua#ia!@3oEAu"),
			Content:  []byte("a"),
		},
		{
			User: user.User{
				Nickname: "nick3",
				Email:    "nick3@yahoo.com",
			},
			Password: []byte("!Ia%Eua#ia!@3oEAuFg#1uaEiaei01!Ia%Eua#ia!@3oEAuFg#1uaEiaei01!Ia%Eua#ia!@3oEAuFg#1uaEiaei01!Ia%Eua#ia!@3oEAuFg#1uaEiaei01"),
			Content:  []byte("lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."),
		},
	}
	// generate secret key, salt and version
	for _, tcase := range testcases {
		id := uuid.New()
		tcase.User.ID = id
		secretKey := vault.GeneratSecretKey(id)
		salt := vault.GenerateRandomKey(vault.EncrytionSaltLen)
		version := []byte("client-v1")
		derivatedKey, err := vault.TwoSecretKeyDerivation(tcase.Password, secretKey, salt, version, tcase.User)
		if err != nil {
			f.Errorf("2skd: cannot generate 2skd: %v", err)
		}
		ciphertext, err := vault.EncryptAESGCM(tcase.Content, derivatedKey)
		if err != nil {
			f.Fatalf("aes-gcm enc/dec: cannot encrypt text: %v", err)
		}
		f.Add(tcase.Content, ciphertext, derivatedKey)
	}
	// execute test for every test case
	f.Fuzz(func(t *testing.T, text, ciphertext, derivatedKey []byte) {
		decText, err := vault.DecryptAESGCM(ciphertext, derivatedKey)
		if err != nil {
			t.Fatalf("aes-gcm enc/dec: cannot decrypt text: %v", err)
		}
		if !bytes.EqualFold(text, decText) {
			t.Fatalf("aes-gcm enc/dec: text and decrypted text aro different: %s != %s", text, decText)
		}
	})

}

