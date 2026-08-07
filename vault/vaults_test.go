package vault

import (
	"path/filepath"
	"testing"
	"time"
)

func isSafeErased(slice []byte) bool {
	if slice == nil {
		// a nil slice is not safe because data keeps in memory until the garbage colletor deletes it
		return false
	}
	for _, v := range slice {
		if v != 0 {
			return false
		}
	}
	return true
}

func areVaultSafeErased(vaults []Vault) bool {
	if vaults == nil {
		// a nil slice is not safe because data keeps in memory until the garbage colletor deletes it
		return false
	}
	for _, vault := range vaults {
		for _, item := range vault.Items {
			if !isSafeErased(item.Password) || !isSafeErased(item.OTP) {
				return false
			}
		}
	}
	return true
}

func TestMasterVaultConfig(t *testing.T) {
	config := NewMasterVaultConfug().
		// set invalid values into kdf settings
		SetKDFAlgorithm("invalid value").
		SetKDFDecriptionTime(6 * time.Second).
		// set invalid values in master vault config
		SetAlgorithm("invalid value").
		SetCompressionAlgorithm("invalid value")
	// check if invalid values has been set to default
	kdf := config.KeyDerivationFunction
	if kdf.Algorithm != KDFAlgorithmDefault {
		t.Errorf("config: kdf: algorithm: invalid default value: expected %s got %s", KDFAlgorithmDefault, kdf.Algorithm)
	}
	if kdf.DecryptionTime != KDFDecryptionTimeDefault {
		t.Errorf("config: kdf: decryption time: invalid default value: expected %d got %d", KDFDecryptionTimeDefault, kdf.DecryptionTime)
	}
	if config.Algorithm != MasterVaultAlgorithmDefault {
		t.Errorf("config: algorithm: invalid default value: expected %s got %s", MasterVaultAlgorithmDefault, config.Algorithm)
	}
	if config.ComplessoinAlgorithm != MasterVaultComplessionAlgorithmDefault {
		t.Errorf("config: complession algorithm: invalid default value: expected %s got %s", MasterVaultComplessionAlgorithmDefault, config.ComplessoinAlgorithm)
	}
}

func TestLockedManager(t *testing.T) {
	// file
	tmpDir := t.TempDir()
	filename := filepath.Join(tmpDir, "test_database.json")
	// config
	config := NewMasterVaultConfug()
	// secrets
	password := []byte("AWeakP4ssword!")
	secretKey := GenerateSecretKey()
	// clone password and secret key
	passwordClone := make([]byte, len(password))
	secretKeyClone := make([]byte, len(secretKey))
	copy(password, passwordClone)
	copy(secretKey, secretKeyClone)
	// create manager
	masterVault := NewMasterVault(filename, passwordClone, secretKeyClone, config)
	// check if clone password and secret key were erased
	if !isSafeErased(passwordClone) {
		t.Errorf("unlocked master valut: password clone not erased safetly")
	}
	if !isSafeErased(secretKey) {
		t.Errorf("unlocked master valut: secret key clone not erased safetly")
	}
	// create the file with the encrypted database and its parameters
	err := masterVault.Write()
	if err != nil {
		t.Fatalf("unlocked master vault: cannot write data: %s", err)
	}
	// bring sencitive data to chekc if is removed from memory after lock
	password = masterVault.password
	secretKey = masterVault.secretKey
	vaults := masterVault.vaults
	// lock the master vault deleting every data from memory
	lockedMasterVault, err := masterVault.Lock()
	if err != nil {
		t.Errorf("unlocked master vault: cannot lock master vault: %s", err)
	}
	// check if values are deleted safelly from memory
	if !isSafeErased(masterVault.password) {
		t.Errorf("unlocked master valut: password not erased safetly")
	}
	if !isSafeErased(masterVault.secretKey) {
		t.Errorf("unlocked master valut: secretKey not erased safetly")
	}
	if !areVaultSafeErased(vaults) {
		t.Errorf("unlocked master valut: vaults not erased safetly")
	}
	// check if file is written in disk and is unlockable
	if _, err = lockedMasterVault.Unlock(password, secretKey); err != nil {
		t.Errorf("unlocked master vault: cannot verify file creation: %s", err)
	}
}
