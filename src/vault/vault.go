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

type itemContent struct {
	Password   []byte `json:"password"`
	OTPAuthURI []byte `json:"otpauth_uri"`
}

func (ic *itemContent) erase() {
	subtle.XORBytes(ic.Password, ic.Password, ic.Password)
	subtle.XORBytes(ic.OTPAuthURI, ic.OTPAuthURI, ic.OTPAuthURI)
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

func (ei *encryptedItem) erase() {
	ei = new(encryptedItem)
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
		ID:         ei.ID,
		Title:      ei.Title,
		URL:        ei.URL,
		User:       ei.User,
		Tags:       tags,
		Password:   content.Password,
		OTPAuthURI: content.OTPAuthURI,
		CreatedAt:  ei.CreatedAt,
		UpdatedAt:  ei.UpdatedAt,
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

// securely erase the item password and otpauth uri from memory
func (i *Item) Erase() {
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
	i.Erase()
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
		return nil, err
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

// if an item exists return the item index else returns
// `NoVaultItemFoundError` error
func (v *vault) getItemIdx(id uuid.UUID) (int, error) {
	// if there are no items, the item does not exist
	if len(v.encItems) == 0 {
		return -1, NoVaultItemFoundError
	}
	// if there is one item and the ids are different, the item does not exist
	if len(v.encItems) == 1 && v.encItems[0].ID != id {
		return -1, NoVaultItemFoundError
	}
	// if there is one item and the ids are equal, the item exist
	if len(v.encItems) == 1 && v.encItems[0].ID == id {
		return 0, nil
	}
	idx := -1
	for i, ei := range v.encItems {
		if ei.ID == id {
			idx = i
			break
		}
	}
	if idx == -1 {
		return -1, NoVaultItemFoundError
	}
	return idx, nil
}

// creates a enc items list deep copy
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

// appends a new locked item in the enc items list
func (v *vault) AddItem(item *Item) (uuid.UUID, error) {
	// ensure default data
	item.ID = uuid.New()
	item.CreatedAt = time.Now()
	item.UpdatedAt = time.Now()
	// encrypt item
	encItem, err := item.lock(v.key)
	if err != nil {
		return uuid.Nil, err
	}
	defer item.Erase()
	if len(v.encItems) == 0 {
		v.encItems = make([]encryptedItem, 1)
		v.encItems[0] = encItem
		return item.ID, nil
	}
	// add item
	v.encItems = append(v.encItems, encItem)
	// securely erase item content
	return item.ID, nil
}

// if there is an item with the given id, updates the enc item with the
// locked givet item
func (v *vault) UpdateItem(item *Item) error {
	idx, err := v.getItemIdx(item.ID)
	if err != nil {
		return err
	}
	// manualy updated at
	item.UpdatedAt = time.Now()
	encItem, err := item.lock(v.key)
	if err != nil {
		return err
	}
	defer item.Erase()
	v.encItems[idx] = encItem
	return nil
}

// if there is a item with the given id, creates a new list of enc items
// without the item found
func (v *vault) DeleteItem(id uuid.UUID) error {
	idx, err := v.getItemIdx(id)
	if err != nil {
		return err
	}
	encItems := make([]encryptedItem, len(v.encItems)-1)
	for i := range len(encItems) {
		if i == idx {
			continue
		}
		encItems[i] = v.encItems[i]
	}
	v.encItems = encItems
	return nil
}

// if there is an item with the given id, returns the unlocked item
//
// WARN: is recommendend to use the `Erase` method when the item wont be
// used anymore
func (v *vault) UnlockItem(id uuid.UUID) (*Item, error) {
	idx, err := v.getItemIdx(id)
	if err != nil {
		return nil, err
	}
	return v.encItems[idx].unlock(v.key)
}

// This method securely erases the key from memory
func (v *vault) erase() {
	subtle.XORBytes(v.key, v.key, v.key)
}

// This method encrypt the vault items with the vault key and encrypt
// the vault key with the gived public key returning an encrypted vault
func (v *vault) SoftLock(pub *rsa.PublicKey) (encryptedVault, error) {
	// marshal encrypted items list
	jsonEncItems, err := json.Marshal(v.encItems)
	if err != nil {
		return encryptedVault{}, err
	}
	// encrypt encrypted items list
	cipherEncItems, err := EncryptAESGCM(jsonEncItems, v.key)
	if err != nil {
		return encryptedVault{}, err
	}
	// generate key encryption label
	label := generateVaultLabel(v.id)
	// encrypt the encryption key with the public key
	cipherKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, v.key, label)
	if err != nil {
		return encryptedVault{}, err
	}
	encVault := encryptedVault{
		ID:        v.id,
		Title:     v.title,
		Key:       cipherKey,
		Content:   cipherEncItems,
		CreatedAt: v.createdAt,
		UpdatedAt: v.updatedAt,
	}
	return encVault, nil
}

// This method encrypt the vault items with the vault key and encrypt
// the vault key with the gived public key returning an encrypted vault
// and erasing secitive data from memory.
//
// NOTE: once the vault is locked, the vault key is erased from
// memory the vault cannot be used anymore
func (v *vault) Lock(pub *rsa.PublicKey) (encryptedVault, error) {
	encVault, err := v.SoftLock(pub)
	if err != nil {
		return encryptedVault{}, err
	}
	// securely erase the key from memory
	v.erase()
	return encVault, nil
}
