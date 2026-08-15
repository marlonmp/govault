package vault_test

import (
	"bytes"
	"testing"

	"github.com/marlonmp/govault/src/vault"
)

func isErasedSecurely(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for i := range len(b) {
		if b[i] != 0 {
			return false
		}
	}
	return true
}

func TestVaultLockUnlack(t *testing.T) {
	priv, err := vault.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("vault: private key: cannot generate private key: %v", err)
	}
	pub := &priv.PublicKey
	v := vault.New("test-vault")
	item := vault.Item{
		Title:      "Gmail",
		URL:        "https://gmail.com",
		User:       "test@gmail.com",
		Password:   []byte("MyW3akP4ssword!"),
		OTPAuthURI: []byte("otpauth://totp/test:user@test.com?secret=BCXDH52EKRYXBUZKQVWTB6XMTOR3HQQ2&issuer=test&algorithm=SHA1&digits=6&period=30"),
	}
	err = v.AddItem(&item)
	if err != nil {
		t.Fatalf("vault: add item: cannot add item: %v", err)
	}
	if !isErasedSecurely(item.Password) {
		t.Errorf("vault: item check: item password was not erased securely")
	}
	if !isErasedSecurely(item.OTPAuthURI) {
		t.Errorf("vault: item check: item password was not erased securely")
	}
	encVault, err := v.Lock(pub)
	if err != nil {
		t.Fatalf("vault: lock: cannot lock vault: %v", err)
	}
	v, err = encVault.Unlock(priv)
	if err != nil {
		t.Fatalf("enc vault: unlock: cannot unlock enc valut: %v", err)
	}
	decItem, err := v.UnlockItem(item.ID)
	if err != nil {
		t.Fatalf("vault: unlock item: cannot unlock item: %v", err)
	}
	if !bytes.Equal(decItem.Password, item.Password) {
		t.Errorf("vault: unlock: non equal passwords: expected %s but got %s", item.Password, decItem.Password)
	}
}
