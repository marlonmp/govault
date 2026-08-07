package vault

import (
	"crypto/subtle"
	"encoding/json"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	MasterVaultFormatV1 = "v1"

	MasterVaultAlgorithmAES256      = "AES-256"
	MasterVaultAlgorithmTwoFish256  = "TwoFish-256"
	MasterVaultAlgorithmChaCha20256 = "ChaCha20-256"
	MasterVaultAlgorithmDefault     = MasterVaultAlgorithmAES256

	MasterVaultComplessionAlgorithmGZIP    = "gzip"
	MasterVaultComplessionAlgorithmDefault = MasterVaultComplessionAlgorithmGZIP

	MasterVaultIVLen = 12

	// TODO: kDFAlgorithmArgon2d  = "argon2d"
	KDFAlgorithmArgon2id = "argon2id"
	KDFAlgorithmDefault  = KDFAlgorithmArgon2id

	KDFSaltLen         uint8  = 32
	KDFDerivatedKeyLen uint32 = 32

	KDFTimeCostMin     uint32 = 1
	KDFTimeCostMax     uint32 = (1 << 32) - 1
	KDFTimeCostDefault uint32 = 6

	KDFMemoryCostMin     uint32 = 8 << 10       // 8KiB
	KDFMemoryCostMax     uint32 = (1 << 32) - 1 // 4TB
	KDFMemoryCostDefault uint32 = 64 << 20      // 64 MB

	KDFThreadsMin     uint8 = 1
	KDFThreadsMiax    uint8 = (1 << 8) - 1
	KDFThreadsDefault uint8 = 4

	KDFDecryptionTimeMin     = 100 * time.Millisecond
	KDFDecryptionTimeMax     = 5 * time.Second
	KDFDecryptionTimeDefault = 1 * time.Second
)

type keyDerivationFunction struct {
	Algorithm      string          `json:"alg"`
	TimeCost       uint32          `json:"time_cost"`
	MemoryCost     uint32          `json:"memory_cost"`
	Threads        uint8           `json:"threads"`
	DecryptionTime time.Duration   `json:"decryption_time"`
	Salt           json.RawMessage `json:"salt"`
}

func NewKeyDerivationFunction() keyDerivationFunction {
	return keyDerivationFunction{
		Algorithm:      KDFAlgorithmDefault,
		TimeCost:       KDFTimeCostDefault,
		MemoryCost:     KDFMemoryCostDefault,
		Threads:        KDFThreadsDefault,
		DecryptionTime: KDFDecryptionTimeDefault,
		Salt:           GenerateSecureSalt(KDFSaltLen),
	}
}

type masterVaultConfig struct {
	FileFormat            string                `json:"format"`
	Algorithm             string                `json:"alg"`
	ComplessoinAlgorithm  string                `json:"complession"`
	InitializationVector  json.RawMessage       `json:"iv"`
	AuthTag               json.RawMessage       `json:"auth_tag"`
	KeyDerivationFunction keyDerivationFunction `json:"kdf"`
}

func NewMasterVaultConfug() masterVaultConfig {
	return masterVaultConfig{
		FileFormat:            MasterVaultFormatV1,
		Algorithm:             MasterVaultAlgorithmDefault,
		ComplessoinAlgorithm:  MasterVaultComplessionAlgorithmDefault,
		InitializationVector:  GenerateSecureSalt(MasterVaultIVLen),
		KeyDerivationFunction: NewKeyDerivationFunction(),
	}
}

// KDF methods

func (mvc masterVaultConfig) SetKDFAlgorithm(alg string) masterVaultConfig {
	// TODO: add validations when argon2d implemented
	switch alg {
	case KDFAlgorithmArgon2id:
		mvc.KeyDerivationFunction.Algorithm = alg
	default:
		mvc.KeyDerivationFunction.Algorithm = KDFAlgorithmDefault
	}
	return mvc
}

func (mvc masterVaultConfig) SetKDFTimeCost(timeCost uint32) masterVaultConfig {
	mvc.KeyDerivationFunction.TimeCost = timeCost
	return mvc
}

func (mvc masterVaultConfig) SetKDFMemoryCost(memoryCost uint32) masterVaultConfig {
	mvc.KeyDerivationFunction.MemoryCost = memoryCost
	return mvc
}

func (mvc masterVaultConfig) SetKDFThreads(threads uint8) masterVaultConfig {
	mvc.KeyDerivationFunction.Threads = threads
	return mvc
}

func (mvc masterVaultConfig) SetKDFDecriptionTime(decryptionTime time.Duration) masterVaultConfig {
	if decryptionTime < KDFDecryptionTimeMin || decryptionTime > KDFDecryptionTimeMax {
		decryptionTime = KDFDecryptionTimeDefault
	}
	mvc.KeyDerivationFunction.DecryptionTime = decryptionTime
	return mvc
}

func (mvc masterVaultConfig) ReGenetareKDFSalt(decryptionTime time.Duration) masterVaultConfig {
	mvc.KeyDerivationFunction.Salt = GenerateSecureSalt(KDFSaltLen)
	return mvc
}

func (mvc masterVaultConfig) GenerateDerivatedKey(secret []byte) []byte {
	kdf := mvc.KeyDerivationFunction
	kg := NewKeyGenerator(kdf.Algorithm)
	return kg.GenerateKey(secret, kdf.Salt, kdf.TimeCost, kdf.MemoryCost, kdf.Threads, KDFDerivatedKeyLen)
}

// master vault config methods

func (mvc masterVaultConfig) SetAlgorithm(alg string) masterVaultConfig {
	switch alg {
	case MasterVaultAlgorithmAES256:
	case MasterVaultAlgorithmTwoFish256:
	case MasterVaultAlgorithmChaCha20256:
		mvc.Algorithm = alg
	default:
		mvc.Algorithm = MasterVaultAlgorithmDefault
	}
	return mvc
}

func (mvc masterVaultConfig) SetCompressionAlgorithm(alg string) masterVaultConfig {
	switch alg {
	case MasterVaultComplessionAlgorithmGZIP:
		mvc.ComplessoinAlgorithm = alg
	default:
		mvc.ComplessoinAlgorithm = MasterVaultComplessionAlgorithmDefault
	}
	return mvc
}

func (mvc masterVaultConfig) ReGenerateInitializationVector() masterVaultConfig {
	mvc.InitializationVector = GenerateSecureSalt(MasterVaultIVLen)
	return mvc
}

type LockedMasterVault struct {
	filename      string
	config        masterVaultConfig
	encryptedData json.RawMessage
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

func OpenLockedMasterVault(path string) (*LockedMasterVault, error) {
	return &LockedMasterVault{}, nil
}

func (lmv *LockedMasterVault) descompress() ([]byte, error) {
	return make([]byte, 0), nil
}

func (lmv *LockedMasterVault) decrypt() ([]byte, error) {
	return make([]byte, 0), nil
}

func (lmv *LockedMasterVault) Unlock(password, secretKey []byte) (*UnlockedMasterVault, error) {
	return &UnlockedMasterVault{}, nil
}

type VaultItem struct {
	UUID      uuid.UUID       `json:"uuid"`
	Title     string          `json:"title"`
	Username  string          `json:"username"`
	Password  json.RawMessage `json:"password"`
	Website   string          `json:"website"`
	OTP       json.RawMessage `json:"otp"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

func (vi *VaultItem) eraseItem() {
	// force the CPU to overwrite the slices with zeros
	subtle.XORBytes(vi.Password, vi.Password, vi.Password)
	subtle.XORBytes(vi.OTP, vi.OTP, vi.OTP)
}

type Vault struct {
	UUID      uuid.UUID   `json:"uuid"`
	Title     string      `json:"title"`
	Items     []VaultItem `json:"items"`
	CreatedAt time.Time   `json:"created_at"`
	UpdatedAt time.Time   `json:"updated_at"`
}

func (v *Vault) eraseItems() {
	for _, item := range v.Items {
		item.eraseItem()
	}
}

type UnlockedMasterVault struct {
	filename  string
	password  []byte
	secretKey []byte
	config    masterVaultConfig
	vaults    []Vault
	CreatedAt time.Time
	UpdatedAt time.Time
}

func NewMasterVault(filename string, password, secretKey []byte, config masterVaultConfig) *UnlockedMasterVault {
	// clone password and secret key
	newPassword := make([]byte, len(password), cap(password))
	newSecurytyKey := make([]byte, len(secretKey), cap(secretKey))
	copy(password, newPassword)
	copy(secretKey, newSecurytyKey)
	// erase password and secret key from memory
	subtle.XORBytes(password, password, password)
	subtle.XORBytes(secretKey, secretKey, secretKey)
	return &UnlockedMasterVault{
		filename:  filename,
		password:  newPassword,
		secretKey: newSecurytyKey,
		config:    config,
		vaults:    make([]Vault, 0),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

func (umv *UnlockedMasterVault) ListVaults() []Vault {
	return make([]Vault, 0, 0)
}

func (umv *UnlockedMasterVault) AddVault(vault Vault) {
}

func (umv *UnlockedMasterVault) SetVaultTitle(id uuid.UUID, title string) error {
	return nil
}

func (umv *UnlockedMasterVault) DeleteVault(id uuid.UUID) (Vault, error) {
	return Vault{}, nil
}

func (umv *UnlockedMasterVault) AddVaultItem(id uuid.UUID, vi VaultItem) error {
	return nil
}

func (umv *UnlockedMasterVault) ChangeVaultItem(id uuid.UUID, vi VaultItem) error {
	return nil
}

func (umv *UnlockedMasterVault) DeleteVaultItem(id uuid.UUID, vi VaultItem) (VaultItem, error) {
	return VaultItem{}, nil
}

func (umv *UnlockedMasterVault) compress() ([]byte, error) {
	return make([]byte, 0, 0), nil
}

func (umv *UnlockedMasterVault) encrypt() ([]byte, error) {
	secret := make([]byte, len(umv.password) + len(umv.secretKey) + 1)
	derivadetKey := umv.config.GenerateDerivatedKey()
	return make([]byte, 0, 0), nil
}

func (umv *UnlockedMasterVault) erasePasswords() {
	// if no vaults skyp concurrent erasing
	if len(umv.vaults) == 0 {
		subtle.XORBytes(umv.password, umv.password, umv.password)
		subtle.XORBytes(umv.secretKey, umv.secretKey, umv.secretKey)
		return
	}
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 4)

	// erase data from vaults concurrently
	go func() {
		wg.Add(1)
		defer wg.Done()

		for _, vault := range umv.vaults {
			wg.Add(1)
			semaphore <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-semaphore }()
				vault.eraseItems()
			}()
		}
	}()
	// erase password and secret key
	subtle.XORBytes(umv.password, umv.password, umv.password)
	subtle.XORBytes(umv.secretKey, umv.secretKey, umv.secretKey)
	// wait the vaults to be erased
	wg.Wait()
}

func (umv *UnlockedMasterVault) WriteAs(path string) error {
	return nil
}

func (umv *UnlockedMasterVault) Write() error {
	return umv.WriteAs(umv.filename)
}

func (umv *UnlockedMasterVault) Lock() (LockedMasterVault, error) {
	umv.erasePasswords()
	return LockedMasterVault{}, nil
}

func (umv *UnlockedMasterVault) MarshalJSON() ([]byte, error) {
	type Alias struct {
		masterVaultConfig
		EncryptedData json.RawMessage `json:"data"`
		CreatedAt     time.Time       `json:"created_at"`
		UpdatedAt     time.Time       `json:"updated_at"`
	}

	data, err := umv.encrypt()
	if err != nil {
		return nil, err
	}

	return json.Marshal(&Alias{
		masterVaultConfig: umv.config,
		EncryptedData:     data,
		CreatedAt:         umv.CreatedAt,
		UpdatedAt:         umv.UpdatedAt,
	})
}
