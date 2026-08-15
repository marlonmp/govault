package vault

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
)

var (
	NoVaultItemFoundError = errors.New("vault: enc items: no item found with given id")
)

func generateVaultLabel(id uuid.UUID) []byte {
	var label bytes.Buffer
	label.WriteString("vault-id-")
	label.WriteString(id.String())
	return label.Bytes()
}

type encryptedItem struct {
	ID        uuid.UUID `json:"id"`
	Title     string    `json:"titile"`
	URL       string    `json:"url"`
	User      string    `json:"user"`
	Tags      []string  `json:"tags"`
	Content   []byte    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type itemContent struct {
	Password   []byte `json:"password"`
	OTPAuthURI []byte `json:"otpauth_uri"`
}

func (ic *itemContent) erase() {
	subtle.XORBytes(ic.Password, ic.Password, ic.Password)
	subtle.XORBytes(ic.OTPAuthURI, ic.OTPAuthURI, ic.OTPAuthURI)
}

func (ei encryptedItem) copy() encryptedItem {
	// clone enc item
	clone := ei
	clone.Tags = make([]string, 0)
	if len(ei.Tags) > 0 {
		clone.Tags = make([]string, len(ei.Tags))
		copy(clone.Tags, ei.Tags)
	}
	clone.Content = make([]byte, 0)
	if len(ei.Content) > 0 {
		clone.Content = make([]byte, len(ei.Content))
		copy(clone.Content, ei.Content)
	}
	return clone
}

func (ei encryptedItem) unlock(key []byte) (*Item, error) {
	jsonItem, err := DecryptAESGCM(ei.Content, key)
	if err != nil {
		return nil, err
	}
	content := itemContent{}
	err = json.Unmarshal(jsonItem, &content)
	if err != nil {
		return nil, err
	}
	tags := make([]string, len(ei.Tags))
	copy(tags, ei.Tags)
	item := Item{
		ID: ei.ID,
		Title: ei.Title,
		URL: ei.URL,
		User: ei.User,
		Tags: tags,
		Password: content.Password,
		OTPAuthURI: content.OTPAuthURI,
		CreatedAt: ei.CreatedAt,
		UpdatedAt: ei.UpdatedAt,
	}
	content.erase()
	return &item, nil
}

type Item struct {
	ID         uuid.UUID
	Title      string
	URL        string
	User       string
	Tags       []string
	Password   []byte
	OTPAuthURI []byte
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// securely erase item password and otpauth uri from memory
func (i *Item) eraseContent() {
	subtle.XORBytes(i.Password, i.Password, i.Password)
	subtle.XORBytes(i.OTPAuthURI, i.OTPAuthURI, i.OTPAuthURI)
}

func (i *Item) lock(key []byte) (encryptedItem, error) {
	// generate content
	content := itemContent{
		Password:   i.Password,
		OTPAuthURI: i.OTPAuthURI,
	}
	// marshal the content
	jsonContent, err := json.Marshal(content)
	if err != nil {
		return encryptedItem{}, err
	}
	// encrypt content
	cipherContent, err := EncryptAESGCM(jsonContent, key)
	if err != nil {
		return encryptedItem{}, err
	}
	// copy tags
	tags := make([]string, len(i.Tags))
	copy(tags, i.Tags)
	// build encrypted item
	encItem := encryptedItem{
		ID:        i.ID,
		Title:     i.Title,
		URL:       i.URL,
		User:      i.User,
		Tags:      tags,
		Content:   cipherContent,
		CreatedAt: i.CreatedAt,
		UpdatedAt: i.UpdatedAt,
	}
	// erase password and otp auth uri from memory
	content.erase()
	i.eraseContent()
	return encItem, nil
}

func (i *Item) GenerateTOTP() (string, error) {
	otpauthuri := string(i.OTPAuthURI)
	return totp.GenerateCode(otpauthuri, time.Now())
}

type encryptedVault struct {
	ID        uuid.UUID `json:"id"`
	Title     string    `json:"titile"`
	Key       []byte    `json:"key"`
	Content   []byte    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (ev encryptedVault) Unlock(priv *rsa.PrivateKey) (*vault, error) {
	// generate key encryption label
	label := generateVaultLabel(ev.ID)
	// decrypt the vault key
	key, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, ev.Key, label)
	if err != nil {
		return nil, err
	}
	// decrypt the content
	jsonItems, err := DecryptAESGCM(ev.Content, key)
	// unmarshal the content
	items := make([]encryptedItem, 0)
	err = json.Unmarshal(jsonItems, &items)
	if err != nil {
		return nil, nil
	}
	// build vault
	vault := &vault{
		id:        ev.ID,
		title:     ev.Title,
		key:       key,
		encItems:  items,
		createdAt: ev.CreatedAt,
		updatedAt: ev.UpdatedAt,
	}
	return vault, nil
}

type vault struct {
	id        uuid.UUID
	title     string
	key       []byte
	encItems  []encryptedItem
	createdAt time.Time
	updatedAt time.Time
}

func New(title string) *vault {
	// generate encryption key
	key := GenerateRandomKey(VaultSecretKeyBytes)
	return &vault{
		id:        uuid.New(),
		title:     title,
		key:       key,
		encItems:  make([]encryptedItem, 0),
		createdAt: time.Now(),
		updatedAt: time.Now(),
	}
}

// creates a enc items deep copy
func (v *vault) GetItems() []encryptedItem {
	if len(v.encItems) == 0 {
		return make([]encryptedItem, 0)
	}
	encItems := make([]encryptedItem, len(v.encItems))
	for i := range len(v.encItems) {
		encItems[i] = v.encItems[i].copy()
	}
	return encItems
}

func (v *vault) AddItem(item *Item) error {
	// ensure default data
	item.ID = uuid.New()
	item.CreatedAt = time.Now()
	item.UpdatedAt = time.Now()
	// encrypt item
	encItem, err := item.lock(v.key)
	if err != nil {
		return err
	}
	defer item.eraseContent()
	if len(v.encItems) == 0 {
		v.encItems = make([]encryptedItem, 1)
		v.encItems[0] = encItem
		return nil
	}
	// add item
	v.encItems = append(v.encItems, encItem)
	// securely erase item content
	return nil
}

func (v *vault) UpdateItem(item *Item) error {
	// zero items check
	if len(v.encItems) == 0 {
		return NoVaultItemFoundError
	}
	// one item check
	if len(v.encItems) == 1 && v.encItems[0].ID != item.ID {
		return NoVaultItemFoundError
	}
	item.UpdatedAt = time.Now()
	encItem, err := item.lock(v.key)
	if err != nil {
		return nil
	}
	defer item.eraseContent()
	if len(v.encItems) == 1 && v.encItems[0].ID == item.ID {
		v.encItems[0] = encItem
		return nil
	}
	// find in items list
	idx := new(uint32)
	for i, ei := range v.encItems {
		if ei.ID == item.ID {
			n := uint32(i)
			idx = &n
			break
		}
	}
	if idx == nil {
		return NoVaultItemFoundError
	}
	v.encItems[*idx] = encItem
	return nil
}

func (v *vault) DeleteItem(id uuid.UUID) error {
	// zero items check
	if len(v.encItems) == 0 {
		return NoVaultItemFoundError
	}
	// one item check
	if len(v.encItems) == 1 && v.encItems[0].ID != id {
		return NoVaultItemFoundError
	}
	if len(v.encItems) == 1 && v.encItems[0].ID == id {
		v.encItems = make([]encryptedItem, 0)
		return nil
	}
	// find in items list
	idx := new(uint32)
	for i, ei := range v.encItems {
		if ei.ID == id {
			n := uint32(i)
			idx = &n
			break
		}
	}
	if idx == nil {
		return NoVaultItemFoundError
	}
	encItems := make([]encryptedItem, len(v.encItems)-1)
	for i := range len(encItems) {
		if uint32(i) == *idx {
			continue
		}
		encItems[i] = v.encItems[i]
	}
	v.encItems = encItems
	return nil
}

func (v *vault) UnlockItem(id uuid.UUID) (*Item, error) {
	if len(v.encItems) == 0 {
		return nil, NoVaultItemFoundError
	}
	if len(v.encItems) == 1 && v.encItems[0].ID != id {
		return nil, NoVaultItemFoundError
	}
	if len(v.encItems) == 1 && v.encItems[0].ID == id {
		return v.encItems[0].unlock(v.key)
	}
	// find in items list
	idx := new(uint32)
	for i, ei := range v.encItems {
		if ei.ID == id {
			n := uint32(i)
			idx = &n
			break
		}
	}
	if idx == nil {
		return nil, NoVaultItemFoundError
	}
	return v.encItems[*idx].unlock(v.key)
}

// This method securely erases the key from memory
func (v *vault) eraseKey() {
	subtle.XORBytes(v.key, v.key, v.key)
}

// This method encrypt the vault items and the vault key and returns an encrypted vault
func (v *vault) Lock(pub *rsa.PublicKey) (*encryptedVault, error) {
	// marshal encrypted items list
	jsonEncItems, err := json.Marshal(v.encItems)
	if err != nil {
		return nil, err
	}
	// encrypt encrypted items list
	cipherEncItems, err := EncryptAESGCM(jsonEncItems, v.key)
	if err != nil {
		return nil, err
	}
	// generate key encryption label
	label := generateVaultLabel(v.id)
	// encrypt the encryption key with the public key
	cipherKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, v.key, label)
	if err != nil {
		return nil, err
	}
	encVault := &encryptedVault{
		ID:        v.id,
		Title:     v.title,
		Key:       cipherKey,
		Content:   cipherEncItems,
		CreatedAt: v.createdAt,
		UpdatedAt: v.updatedAt,
	}
	// securely erase the key from memory
	v.eraseKey()
	return encVault, nil
}
