package manager

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	ManagerFormatV1 = "v1"

	ManagerAlgorithmAES256      = "AES-256"
	ManagerAlgorithmTwoFish256  = "TwoFish-256"
	ManagerAlgorithmChaCha20256 = "ChaCha20-256"
	ManagerAlgorithmDefault     = ManagerAlgorithmAES256

	KDFAlgorithmArgon2d  = "argon2d"
	KDFAlgorithmArgon2id = "argon21d"

	KDFTimeCostMin     uint32 = 1
	KDFTimeCostDefault        = 3

	KDFMemoryCostMin     uint32 = 8 << 10  // 8KiB
	KDFMemoryCostDefault        = 64 << 20 // 64 MB

	KDFThreadsMin     uint32 = 1
	KDFThreadsDefault        = 4

	KDFDecryptionTimeMin     = 100 * time.Millisecond
	KDFDecryptionTimeMax     = 5 * time.Second
	KDFDecryptionTimeDefault = 1 * time.Second
)

type KeyDerivationFunction struct {
	Algorithm      string          `json:"alg"`
	TimeCost       uint32          `json:"time_cost"`
	MemoryCost     uint32          `json:"memory_cost"`
	Threads        uint32          `json:"threads"`
	DecryptionTime time.Duration   `json:"decryption_time"`
	Salt           json.RawMessage `json:"salt"`
}

func NewKeyDerivationFunctionWithSalt(kdf KeyDerivationFunction) KeyDerivationFunction {
	return KeyDerivationFunction{}
}

func (kdf KeyDerivationFunction) GenerateKey() ([]byte, error) {
	return make([]byte, 0), nil
}

type LockedManager struct {
	path string

	VaultFormat           string                `json:"format"`
	Algorithm             string                `json:"alg"`
	InitializationVector  string                `json:"iv"`
	KeyDerivationFunction KeyDerivationFunction `json:"kdf"`
	ComplessoinAlgorithm  string                `json:"complession"`
	EncryptedData         json.RawMessage       `json:"data"`
	CreatedAt             time.Time             `json:"created_at"`
	UpdatedAt             time.Time             `json:"updated_at"`
}

func NewLockedVault(kdf KeyDerivationFunction) (*LockedManager, error) {
	return &LockedManager{}, nil
}

func OpenLockedVault(path string) (*LockedManager, error) {
	return &LockedManager{}, nil
}

func (lv *LockedManager) Descompress() ([]byte, error) {
	return make([]byte, 0, 0), nil
}

func (lv *LockedManager) Decrypt() ([]byte, error) {
	return make([]byte, 0, 0), nil
}

func (lv *LockedManager) Unlock(password, secretKey []byte) (*UnlockedManager, error) {
	return &UnlockedManager{}, nil
}

type VaultItem struct {
	UUID      uuid.UUID `json:"uuid"`
	Title     string    `json:"title"`
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	Website   string    `json:"website"`
	OTP       string    `json:"otp"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Vault struct {
	UUID      uuid.UUID   `json:"uuid"`
	Title     string      `json:"title"`
	Items     []VaultItem `json:"items"`
	CreatedAt time.Time   `json:"created_at"`
	UpdatedAt time.Time   `json:"updated_at"`
}

type UnlockedManager struct {
	path      string
	password  []byte
	secretKey []byte

	vaults    []Vault
	mu sync.Mutex

	VaultFormat           string                `json:"format"`
	Algorithm             string                `json:"alg"`
	KeyDerivationFunction KeyDerivationFunction `json:"kdf"`
	ComplessoinAlgorithm  string                `json:"complession"`
	EncryptedData         string                `json:"data"`
	CreatedAt             time.Time             `json:"created_at"`
	UpdatedAt             time.Time             `json:"updated_at"`
}

func (um *UnlockedManager) ListVaults() []Vault {
	return make([]Vault, 0, 0)
}

func (um *UnlockedManager) AddVault(vault Vault) {
}

func (um *UnlockedManager) SetVaultTitle(id uuid.UUID, title string) error {
	return nil
}

func (um *UnlockedManager) DeleteVault(id uuid.UUID) (Vault, error) {
	return Vault{}, nil
}

func (um *UnlockedManager) AddVaultItem(id uuid.UUID, vi VaultItem) error {
	return nil
}

func (um *UnlockedManager) ChangeVaultItem(id uuid.UUID, vi VaultItem) error {
}

func (um *UnlockedManager) DeleteVaultItem(id uuid.UUID, vi VaultItem) (VaultItem, error) {
	return VaultItem{}, nil
}

func (um *UnlockedManager) Compress() ([]byte, error) {
	return make([]byte, 0, 0), nil
}

func (um *UnlockedManager) Encrypt() ([]byte, error) {
	return make([]byte, 0, 0), nil
}

func (um *UnlockedManager) WriteAs(path string) error {
	return nil
}

func (um *UnlockedManager) Write() error {
	return um.WriteAs(um.path)
}

func (um *UnlockedManager) Lock() (LockedManager, error) {
	return LockedManager{}, nil
}
